//! ExEx unique for OP-Reth. See also [`reth_exex`] for more op-reth execution extensions.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use alloy_consensus::BlockHeader;
use derive_more::Constructor;
use futures_util::TryStreamExt;
use reth_execution_types::Chain;
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_api::{FullNodeComponents, NodePrimitives};
use reth_node_types::NodeTypes;
use reth_optimism_trie::{live::LiveTrieCollector, OpProofsStorage, OpProofsStore};
use reth_primitives_traits::{BlockTy, RecoveredBlock};
use reth_provider::{BlockNumReader, BlockReader, TransactionVariant};
use std::sync::Arc;
use tracing::{debug, error, info};

/// How many blocks to process in a single batch before yielding
const SYNC_BATCH_SIZE: usize = 10;

/// How close to tip before we process blocks in real-time vs batch
const REAL_TIME_THRESHOLD: u64 = 1000;

/// Delay before applying real-time block (allows for mini-reorgs)
const REAL_TIME_DELAY_SECS: u64 = 3;

/// How long to sleep when sync task is caught up
const SYNC_IDLE_SLEEP_SECS: u64 = 5;

/// OP Proofs ExEx - processes blocks and tracks state changes within fault proof window.
///
/// Saves and serves trie nodes to make proofs faster. This handles the process of
/// saving the current state, new blocks as they're added, and serving proof RPCs
/// based on the saved data.
///
/// # Examples
///
/// The following example shows how to install the ExEx with either in-memory or persistent storage.
/// This can be used when launching an OP-Reth node via a binary.
/// We are currently using it in optimism/bin/src/main.rs.
///
/// ```
/// use futures_util::FutureExt;
/// use reth_db::test_utils::create_test_rw_db;
/// use reth_node_api::NodeTypesWithDBAdapter;
/// use reth_node_builder::{NodeBuilder, NodeConfig};
/// use reth_optimism_chainspec::BASE_MAINNET;
/// use reth_optimism_exex::OpProofsExEx;
/// use reth_optimism_node::{args::RollupArgs, OpNode};
/// use reth_optimism_trie::{db::MdbxProofsStorage, InMemoryProofsStorage, OpProofsStorage};
/// use reth_provider::providers::BlockchainProvider;
/// use std::sync::Arc;
///
/// let config = NodeConfig::new(BASE_MAINNET.clone());
/// let db = create_test_rw_db();
/// let args = RollupArgs::default();
/// let op_node = OpNode::new(args);
///
/// // Create in-memory or persistent storage
/// let storage: OpProofsStorage<Arc<InMemoryProofsStorage>> =
///     Arc::new(InMemoryProofsStorage::new()).into();
///
/// // Example for creating persistent storage
/// # let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
/// # let storage_path = temp_dir.path().join("proofs_storage");
///
/// # let storage: OpProofsStorage<Arc<MdbxProofsStorage>> = Arc::new(
/// #    MdbxProofsStorage::new(&storage_path).expect("Failed to create MdbxProofsStorage"),
/// # ).into();
///
/// let storage_exec = storage.clone();
/// let proofs_history_window = 1_296_000u64;
/// // Can also use install_exex_if along with a boolean flag
/// // Set this based on your configuration or CLI args
/// let _builder = NodeBuilder::new(config)
///     .with_database(db)
///     .with_types_and_provider::<OpNode, BlockchainProvider<NodeTypesWithDBAdapter<OpNode, _>>>()
///     .with_components(op_node.components())
///     .install_exex("proofs-history", move |exex_context| async move {
///         Ok(OpProofsExEx::new(exex_context, storage_exec, proofs_history_window).run().boxed())
///     })
///     .on_node_started(|_full_node| Ok(()))
///     .check_launch();
/// ```
#[derive(Debug, Constructor)]
pub struct OpProofsExEx<Node, Storage>
where
    Node: FullNodeComponents,
{
    /// The ExEx context containing the node related utilities e.g. provider, notifications,
    /// events.
    ctx: ExExContext<Node>,
    /// The type of storage DB.
    storage: OpProofsStorage<Storage>,
    /// The window to span blocks for proofs history. Value is the number of blocks, received as
    /// cli arg.
    #[expect(dead_code)]
    proofs_history_window: u64,
}

impl<Node, Storage, Primitives> OpProofsExEx<Node, Storage>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = Primitives>>,
    Primitives: NodePrimitives,
    Storage: OpProofsStore + Clone + 'static,
{
    /// Main execution loop for the ExEx
    pub async fn run(mut self) -> eyre::Result<()> {
        self.ensure_initialized().await?;

        let sync_target_tx = self.spawn_sync_task();

        let storage = self.storage.clone();
        let collector = LiveTrieCollector::new(
            self.ctx.evm_config().clone(),
            self.ctx.provider().clone(),
            &storage,
        );

        debug!(target: "optimism::exex", "Starting ExEx notification processing loop");
        while let Some(notification) = self.ctx.notifications.try_next().await? {
            self.handle_notification(notification, &collector, &sync_target_tx).await?;
        }

        Ok(())
    }

    /// Ensure proofs storage is initialized
    async fn ensure_initialized(&self) -> eyre::Result<()> {
        // Check if proofs storage is initialized
        let earliest_block_number = match self.storage.get_earliest_block_number().await? {
            Some((n, _)) => n,
            None => {
                return Err(eyre::eyre!(
                    "Proofs storage not initialized. Please run 'op-reth initialize-op-proofs --proofs-history.storage-path <PATH>' first."
                ));
            }
        };

        // Need to update the earliest block metric on startup as this is not called frequently and
        // can show outdated info. When metrics are disabled, this is a no-op.
        self.storage.metrics().block_metrics().earliest_number.set(earliest_block_number as f64);
        Ok(())
    }

    /// Spawn the background sync task and return the target sender
    fn spawn_sync_task(&self) -> tokio::sync::watch::Sender<u64> {
        let (sync_target_tx, sync_target_rx) = tokio::sync::watch::channel(0u64);

        let task_storage = self.storage.clone();
        let task_provider = self.ctx.provider().clone();
        let task_evm_config = self.ctx.evm_config().clone();

        self.ctx.task_executor().spawn_critical(
            "optimism::exex::proofs_storage_sync_loop",
            async move {
                let storage = task_storage.clone();
                let task_collector =
                    LiveTrieCollector::new(task_evm_config, task_provider.clone(), &storage);
                Self::sync_loop(sync_target_rx, task_storage, task_provider, &task_collector).await;
            },
        );

        sync_target_tx
    }

    /// Background sync loop that processes blocks up to the target
    async fn sync_loop(
        mut sync_target_rx: tokio::sync::watch::Receiver<u64>,
        storage: OpProofsStorage<Storage>,
        provider: Node::Provider,
        collector: &LiveTrieCollector<'_, Node::Evm, Node::Provider, Storage>,
    ) {
        debug!(target: "optimism::exex", "Starting proofs storage sync loop");

        loop {
            let target = *sync_target_rx.borrow_and_update();

            let latest = match storage.get_latest_block_number().await {
                Ok(Some((n, _))) => n,
                // todo: handle uninitialized storage
                Ok(None) => {
                    error!(target: "optimism::exex", "No blocks stored in proofs storage during sync loop");
                    continue;
                }
                // todo: handle errors more gracefully
                Err(e) => {
                    error!(target: "optimism::exex", error = ?e, "Failed to get latest block");
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            if latest >= target {
                tokio::time::sleep(tokio::time::Duration::from_secs(SYNC_IDLE_SLEEP_SECS)).await;
                continue;
            }

            // Process one batch
            if let Err(e) =
                Self::process_batch(latest, target, &provider, collector, SYNC_BATCH_SIZE).await
            {
                error!(target: "optimism::exex", error = ?e, "Batch processing failed");
            }

            // Yield to allow other tasks to run
            debug!(target: "optimism::exex", latest_stored = latest, target, "Batch processed, yielding");
            tokio::task::yield_now().await;
        }
    }

    /// Process a batch of blocks from start to target (up to `batch_size`)
    async fn process_batch(
        start: u64,
        target: u64,
        provider: &Node::Provider,
        collector: &LiveTrieCollector<'_, Node::Evm, Node::Provider, Storage>,
        batch_size: usize,
    ) -> eyre::Result<()> {
        let end = (start + batch_size as u64).min(target);

        for block_num in (start + 1)..=end {
            let block = provider
                .recovered_block(block_num.into(), TransactionVariant::NoHash)?
                .ok_or_else(|| eyre::eyre!("Missing block {}", block_num))?;

            collector.execute_and_store_block_updates(&block).await?;
        }

        Ok(())
    }

    /// Handle a single notification
    async fn handle_notification(
        &self,
        notification: ExExNotification<Primitives>,
        collector: &LiveTrieCollector<'_, Node::Evm, Node::Provider, Storage>,
        sync_target_tx: &tokio::sync::watch::Sender<u64>,
    ) -> eyre::Result<()> {
        let latest_stored = match self.storage.get_latest_block_number().await? {
            Some((n, _)) => n,
            None => {
                return Err(eyre::eyre!("No blocks stored in proofs storage"));
            }
        };

        match &notification {
            ExExNotification::ChainCommitted { new } => {
                self.handle_chain_committed(new.clone(), latest_stored, collector, sync_target_tx)
                    .await?
            }
            ExExNotification::ChainReorged { old, new } => {
                self.handle_chain_reorged(old.clone(), new.clone(), latest_stored, collector)
                    .await?
            }
            ExExNotification::ChainReverted { old } => {
                self.handle_chain_reverted(old.clone(), latest_stored, collector).await?
            }
        }

        if let Some(committed_chain) = notification.committed_chain() {
            self.ctx.events.send(ExExEvent::FinishedHeight(committed_chain.tip().num_hash()))?;
        }

        Ok(())
    }

    async fn handle_chain_committed(
        &self,
        new: Arc<Chain<Primitives>>,
        latest_stored: u64,
        collector: &LiveTrieCollector<'_, Node::Evm, Node::Provider, Storage>,
        sync_target_tx: &tokio::sync::watch::Sender<u64>,
    ) -> eyre::Result<()> {
        let tip = new.tip();
        debug!(
            target: "optimism::exex",
            block_number = tip.number(),
            block_hash = ?tip.hash(),
            "ChainCommitted"
        );

        // Already processed
        if tip.number() <= latest_stored {
            debug!(
                target: "optimism::exex",
                block_number = tip.number(),
                latest_stored,
                "Already processed, skipping"
            );
            self.ctx.events.send(ExExEvent::FinishedHeight(tip.num_hash()))?;
            return Ok(());
        }

        let best_block = self.ctx.provider().best_block_number()?;
        let is_sequential = tip.number() == latest_stored + 1;
        let is_near_tip = best_block.saturating_sub(tip.number()) < REAL_TIME_THRESHOLD;

        if is_sequential && is_near_tip {
            // Process in real-time
            debug!(
                target: "optimism::exex",
                block_number = tip.number(),
                best_block,
                latest_stored,
                "Processing in real-time"
            );
            collector.execute_and_store_block_updates(tip).await?;
        } else {
            // Delegate to sync task
            debug!(
                target: "optimism::exex",
                block_number = tip.number(),
                best_block,
                latest_stored,
                "Delegating to sync task"
            );
            sync_target_tx.send(tip.number())?;
        }
        Ok(())
    }

    async fn handle_chain_reorged(
        &self,
        old: Arc<Chain<Primitives>>,
        new: Arc<Chain<Primitives>>,
        latest_stored: u64,
        collector: &LiveTrieCollector<'_, Node::Evm, Node::Provider, Storage>,
    ) -> eyre::Result<()> {
        info!(
            target: "optimism::exex",
            old_block = old.tip().number(),
            new_block = new.tip().number(),
            "ChainReorged"
        );

        if old.first().number() > latest_stored {
            info!(target: "optimism::exex", "Reorg beyond stored blocks, skipping");
            return Ok(());
        }

        // Find divergent blocks inline to maintain references
        let mut new_blocks: Vec<&RecoveredBlock<BlockTy<Primitives>>> =
            Vec::with_capacity(new.len());

        for block_num in new.blocks().keys().rev() {
            let new_block = new
                .blocks()
                .get(block_num)
                .ok_or_else(|| eyre::eyre!("Missing block {} in new chain", block_num))?;

            match old.blocks().get(block_num) {
                Some(old_block) => {
                    if new_block.hash() == old_block.hash() {
                        break;
                    }

                    new_blocks.push(new_block);
                    if new_block.parent_hash() == old_block.parent_hash() {
                        break;
                    }
                }
                None => {
                    // Block only in new chain
                    new_blocks.push(new_block);
                }
            }
        }
        collector.unwind_and_store_block_updates(new_blocks).await?;
        Ok(())
    }

    async fn handle_chain_reverted(
        &self,
        old: Arc<Chain<Primitives>>,
        latest_stored: u64,
        collector: &LiveTrieCollector<'_, Node::Evm, Node::Provider, Storage>,
    ) -> eyre::Result<()> {
        info!(target: "optimism::exex", block = old.tip().number(), "ChainReverted");

        if old.first().number() > latest_stored {
            info!(target: "optimism::exex", "Revert beyond stored blocks, skipping");
            return Ok(());
        }

        collector.unwind_history(old.first().block_with_parent()).await?;
        Ok(())
    }
}
