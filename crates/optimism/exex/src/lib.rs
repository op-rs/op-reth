//! ExEx unique for OP-Reth. See also [`reth_exex`] for more op-reth execution extensions.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use std::sync::{Arc, Mutex};

use alloy_consensus::BlockHeader;
use alloy_eips::NumHash;
use derive_more::Constructor;
use futures_util::TryStreamExt;
use reth_exex::{ExExContext, ExExEvent, ExExHead, ExExNotification};
use reth_node_api::{FullNodeComponents, NodePrimitives};
use reth_node_types::NodeTypes;
use reth_optimism_trie::{live::LiveTrieCollector, BackfillJob, OpProofsStorage, OpProofsStore};
use reth_provider::{BlockHashReader, BlockNumReader, DBProvider, DatabaseProviderFactory};
use tracing::{debug, error};

/// OP Proofs ExEx - processes blocks and tracks state changes within fault proof window.
///
/// Saves and serves trie nodes to make proofs faster. This handles the process of
/// saving the current state, new blocks as they're added, and serving proof RPCs
/// based on the saved data.
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
        let head = Arc::new(Mutex::new(None));

        let db_provider = self.ctx.provider().database_provider_ro().unwrap();
        let storage_clone = self.storage.clone();

        let head_clone = head.clone();

        self.ctx.task_executor().spawn(async move {
            let db_provider = db_provider.disable_long_read_transaction_safety();
            let head_number = db_provider.best_block_number().unwrap();
            let Some(head_hash) = db_provider.block_hash(head_number).unwrap() else {
                error!("No head hash found for best block number");
                return;
            };
            let db_tx = db_provider.into_tx();
            BackfillJob::new(storage_clone, &db_tx).run(head_number, head_hash).await.unwrap();

            head_clone
                .lock()
                .unwrap()
                .replace(Some(ExExHead::new(NumHash::new(head_number, head_hash))));
        });

        let collector = LiveTrieCollector::new(
            self.ctx.evm_config().clone(),
            self.ctx.provider().clone(),
            &self.storage,
        );

        while let Some(notification) = self.ctx.notifications.try_next().await? {
            // if there is no head, acknowledge the notification and continue
            if head.lock().unwrap().is_none() {
                let tip_number = notification.committed_chain().unwrap().tip().number();
                debug!("No head found, acknowledging block {tip_number} notification and continuing");
            } else {
                match &notification {
                    ExExNotification::ChainCommitted { new } => {
                        debug!(
                            block_number = new.tip().number(),
                            block_hash = ?new.tip().hash(),
                            "ChainCommitted notification received",
                        );

                        // Get latest stored number (ignore stored hash for now)
                        let latest_stored_block_number =
                            match self.storage.get_latest_block_number().await? {
                                Some((n, _)) => n,
                                None => {
                                    return Err(eyre::eyre!("No blocks stored in proofs storage"));
                                }
                            };

                        // If tip is not newer than what we have, nothing to do.
                        if new.tip().number() <= latest_stored_block_number {
                            debug!(
                                block_number = new.tip().number(),
                                latest_stored = latest_stored_block_number,
                                "Tip number is less than or equal to latest stored, skipping"
                            );
                            continue;
                        }

                        // Start from the next block after the latest stored one.
                        let start = latest_stored_block_number.saturating_add(1);
                        debug!(
                            start,
                            end = new.tip().number(),
                            "Applying updates for blocks in committed chain"
                        );
                        for block_number in start..=new.tip().number() {
                            match new.blocks().get(&block_number) {
                                Some(block) => {
                                    collector.execute_and_store_block_updates(&block).await?;
                                }
                                None => {
                                    error!(
                                        block_number,
                                        "Missing block in committed chain, stopping incremental application",
                                    );
                                    return Err(eyre::eyre!(
                                        "Missing block {} in committed chain",
                                        block_number
                                    ));
                                }
                            }
                        }
                    }
                    ExExNotification::ChainReorged { old, new } => {
                        debug!(
                            old_block_number = old.tip().number(),
                            old_block_hash = ?old.tip().hash(),
                            new_block_number = new.tip().number(),
                            new_block_hash = ?new.tip().hash(),
                            "ChainReorged notification received",
                        );
                        unimplemented!("Chain reorg handling not yet implemented in OpProofsExEx");
                    }
                    ExExNotification::ChainReverted { old } => {
                        debug!(
                            old_block_number = old.tip().number(),
                            old_block_hash = ?old.tip().hash(),
                            "ChainReverted notification received",
                        );
                        unimplemented!("Chain revert handling not yet implemented");
                    }
                };
            }

            if let Some(committed_chain) = notification.committed_chain() {
                self.ctx
                    .events
                    .send(ExExEvent::FinishedHeight(committed_chain.tip().num_hash()))?;
            }
        }

        Ok(())
    }
}
