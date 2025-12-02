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
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_api::{FullNodeComponents, NodePrimitives};
use reth_node_types::NodeTypes;
use reth_optimism_trie::{live::LiveTrieCollector, OpProofsStorage, OpProofsStore};
use reth_primitives_traits::{BlockTy, RecoveredBlock};
use reth_provider::{BlockNumReader, BlockReader, TransactionVariant};
use tracing::{debug, error, info};

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
        // Check if proofs storage is initialized
        if self.storage.get_earliest_block_number().await?.is_none() {
            return Err(eyre::eyre!(
                "Proofs storage not initialized. Please run 'op-reth initialize-op-proofs --proofs-history.storage-path <PATH>' first."
            ));
        }

        let (sync_block_number_tx, sync_block_number_rx) = tokio::sync::watch::channel(0);
        let storage_clone = self.storage.clone();
        let provider_clone = self.ctx.provider().clone();
        let evm_config_clone = self.ctx.evm_config().clone();

        let task_storage = storage_clone.clone();
        let task_provider = provider_clone.clone();
        let task_evm_config = evm_config_clone.clone();

        let collector = LiveTrieCollector::new(evm_config_clone, provider_clone, &storage_clone);

        self.ctx.task_executor().spawn_critical(
            "optimism::exex::proofs_storage_sync_loop",
            async move {
            debug!(target: "optimism::exex", "Starting proofs storage sync loop");
            let task_collector =
                LiveTrieCollector::new(task_evm_config, task_provider.clone(), &task_storage);

            loop {
                let target = *sync_block_number_rx.borrow();
                let mut latest_stored_block = match task_storage.get_latest_block_number().await {
                    Err(e) => {
                        error!("Error fetching latest stored block number: {:?}", e);
                        continue;
                    }
                    Ok(Some((n, _))) => n,
                    Ok(None) => {
                        error!("No blocks stored in proofs storage during sync loop",);
                        continue;
                    }
                };

                if latest_stored_block >= target {
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }

                while latest_stored_block < target {

                    // Process up to 10 blocks without yielding
                    for _ in 0..50 {
                        if latest_stored_block >= target {
                            break;
                        }

                        let next_block_number = latest_stored_block.saturating_add(1);
                        match task_provider
                            .recovered_block(next_block_number.into(), TransactionVariant::NoHash)
                        {
                            Err(e) => {
                                error!(next_block_number, "Error fetching block in sync loop: {:?}", e);
                                break;
                            }
                            Ok(Some(block)) => {
                                if let Err(err) =
                                    task_collector.execute_and_store_block_updates(&block).await
                                {
                                    error!(
                                        next_block_number,
                                        "Error executing and storing block updates in sync loop: {:?}",
                                        err
                                    );
                                    break;
                                }
                            }
                            Ok(None) => {
                                error!(
                                    next_block_number,
                                    "Missing block in sync loop, stopping incremental application",
                                );
                                break;
                            }

                        }
                        latest_stored_block = next_block_number;
                    }

                    // Yield after processing a batch of blocks
                    tokio::task::yield_now().await;
                }
            }
        });

        debug!(target: "optimism::exex", "Starting ExEx notification processing loop");
        while let Some(notification) = self.ctx.notifications.try_next().await? {
            // Get latest stored number (ignore stored hash for now)
            let latest_stored_block_number = match self.storage.get_latest_block_number().await? {
                Some((n, _)) => n,
                None => {
                    return Err(eyre::eyre!("No blocks stored in proofs storage"));
                }
            };

            match &notification {
                ExExNotification::ChainCommitted { new } => {
                    debug!(
                        target: "optimism::exex",
                        block_number = new.tip().number(),
                        block_hash = ?new.tip().hash(),
                        "ChainCommitted notification received",
                    );

                    // If tip is not newer than what we have, nothing to do.
                    if new.tip().number() <= latest_stored_block_number {
                        debug!(
                            target: "optimism::exex",
                            block_number = new.tip().number(),
                            latest_stored = latest_stored_block_number,
                            "Tip number is less than or equal to latest stored, skipping"
                        );
                        continue;
                    }

                    let best_block_number = self.ctx.provider().best_block_number()?;
                    if new.tip().number() == latest_stored_block_number.saturating_add(1) &&
                        best_block_number.saturating_sub(new.tip().number()) < 1000
                    {
                        debug!(
                            target: "optimism::exex",
                            block_number = new.tip().number(),
                            best_block_number,
                            latest_stored_block_number,
                            "Applying single block update in near real-time"
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                        collector.execute_and_store_block_updates(new.tip()).await?;
                    } else {
                        debug!(
                            target: "optimism::exex",
                            block_number = new.tip().number(),
                            best_block_number,
                            latest_stored_block_number,
                            "Applying batch block updates to catch up"
                        );
                        sync_block_number_tx.send(new.tip().number())?;
                    }
                }
                ExExNotification::ChainReorged { old, new } => {
                    info!(
                        old_block_number = old.tip().number(),
                        old_block_hash = ?old.tip().hash(),
                        new_block_number = new.tip().number(),
                        new_block_hash = ?new.tip().hash(),
                        "ChainReorged notification received",
                    );

                    let first_block = old.first();
                    if first_block.number() > latest_stored_block_number {
                        info!(
                            target: "optimism::exex",
                            first_block_number = first_block.number(),
                            latest_stored = latest_stored_block_number,
                            "Reorg block number is greater than latest stored, skipping",
                        );
                        continue;
                    }

                    // find the common ancestor
                    let mut new_blocks: Vec<&RecoveredBlock<BlockTy<Primitives>>> =
                        Vec::with_capacity(new.len());
                    for block_number in new.blocks().keys().rev() {
                        let old_block = old.blocks().get(block_number);
                        let new_block = new.blocks().get(block_number);
                        match (new_block, old_block) {
                            (Some(new_block), Some(old_block)) => {
                                if new_block.hash() == old_block.hash() {
                                    break;
                                }

                                new_blocks.push(new_block);
                                if new_block.parent_hash() == old_block.parent_hash() {
                                    break;
                                }
                            }
                            (Some(new_block), None) => {
                                // Block only exists in new chain, collect it
                                new_blocks.push(new_block);
                            }
                            _ => {
                                error!(
                                    block_number,
                                    "Missing block in new chain during reorg detection",
                                );
                                return Err(eyre::eyre!(
                                    "Missing block {} in new chain during reorg detection",
                                    block_number
                                ));
                            }
                        }
                    }

                    // reverse to get the new blocks in the correct order
                    new_blocks.reverse();
                    collector.unwind_and_store_block_updates(new_blocks).await?;
                }
                ExExNotification::ChainReverted { old } => {
                    info!(
                        target: "optimism::exex",
                        old_block_number = old.tip().number(),
                        old_block_hash = ?old.tip().hash(),
                        "ChainReverted notification received",
                    );

                    let first_block = old.first();
                    if first_block.number() > latest_stored_block_number {
                        info!(
                            target: "optimism::exex",
                            first_block_number = first_block.number(),
                            latest_stored = latest_stored_block_number,
                            "Fork block number is greater than latest stored, skipping",
                        );
                        continue;
                    }

                    collector.unwind_history(first_block.block_with_parent()).await?;
                }
            };

            if let Some(committed_chain) = notification.committed_chain() {
                self.ctx
                    .events
                    .send(ExExEvent::FinishedHeight(committed_chain.tip().num_hash()))?;
            }
        }

        Ok(())
    }
}
