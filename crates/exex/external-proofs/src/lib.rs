//! OP Proofs ExEx - processes blocks and tracks state changes

use crate::{
    backfill::BackfillJob, live::LiveTrieCollector, mdbx::MdbxOpProofsStorage,
    metrics::StorageMetrics, storage::OpProofsStorage,
    storage_with_metrics::OpProofsStorageWithMetrics,
};
use futures_util::TryStreamExt;
use reth_chainspec::ChainInfo;
use reth_db::DatabaseEnv;
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_api::{FullNodeComponents, NodePrimitives};
use reth_node_types::NodeTypes;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{
    BlockNumReader, BlockReader, DBProvider, DatabaseProviderFactory, TransactionVariant,
};
use std::{env, path::PathBuf, sync::Arc};
use tracing::info;

pub mod backfill;
pub mod in_memory;
pub mod live;
pub mod mdbx;
pub mod metrics;
pub mod models;
pub mod proof;
pub mod provider;
pub mod storage;
pub mod storage_with_metrics;

#[cfg(test)]
mod storage_tests;

/// Saves and serves trie nodes to make proofs faster. This handles the process of
/// saving the current state, new blocks as they're added, and serving proof RPCs
/// based on the saved data.
#[derive(Debug)]
pub struct OpProofsExEx<Node>
where
    Node: FullNodeComponents,
{
    ctx: ExExContext<Node>,
    storage: Arc<OpProofsStorageWithMetrics<MdbxOpProofsStorage<DatabaseEnv>>>,
    metrics: Arc<StorageMetrics>,
}

impl<Node, Primitives> OpProofsExEx<Node>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = Primitives>>,
    Primitives: NodePrimitives,
{
    /// Create a new `OpProofsExEx` instance
    pub fn new(ctx: ExExContext<Node>) -> Self {
        let datadir = env::var("OP_PROOFS_DATA_DIR").unwrap();
        let datadir = PathBuf::from(datadir);

        let storage = MdbxOpProofsStorage::new_from_path(datadir).unwrap();
        let metrics = Arc::new(StorageMetrics::new());
        let storage_with_metrics = OpProofsStorageWithMetrics::new(storage, metrics.clone());

        Self { ctx, storage: Arc::new(storage_with_metrics), metrics }
    }

    /// Main execution loop for the ExEx
    pub async fn run(mut self) -> eyre::Result<()> {
        // Run the earliest block job (idempotent)
        let ChainInfo { best_number, best_hash } = self.ctx.provider().chain_info()?;
        BackfillJob::new(&*self.storage, self.ctx.provider()).run(best_number, best_hash).await?;

        let collector = LiveTrieCollector::<
            Node,
            Arc<OpProofsStorageWithMetrics<MdbxOpProofsStorage<DatabaseEnv>>>,
        >::new(
            self.ctx.evm_config().clone(),
            self.ctx.provider().clone(),
            self.storage.clone(),
            self.metrics.clone(),
        );

        // check if we can process up to the latest block
        let Some((latest_stored_block_number, _)) = self.storage.get_latest_block_number().await?
        else {
            return Err(eyre::eyre!("No blocks stored"));
        };
        let ChainInfo { best_number: latest_block_number, .. } =
            self.ctx.provider().chain_info()?;

        if latest_stored_block_number < latest_block_number {
            info!(
                "Backfilling blocks from {} to {}",
                latest_stored_block_number, latest_block_number
            );
            for block_number in (latest_stored_block_number + 1)..=latest_block_number {
                let Some(block) = self
                    .ctx
                    .provider()
                    .recovered_block(block_number.into(), TransactionVariant::NoHash)?
                else {
                    return Err(eyre::eyre!("Block {} not found", block_number));
                };
                collector.execute_and_store_block_updates(&block).await?;
            }
        } else {
            info!(
                "Skipping backfill, latest stored block number is up to date (latest stored: {}, latest: {})",
                latest_stored_block_number, latest_block_number
            );
        }

        while let Some(notification) = self.ctx.notifications.try_next().await? {
            #[allow(clippy::single_match)]
            match &notification {
                ExExNotification::ChainCommitted { new } => {
                    let Some((latest_stored_block_number, _)) =
                        self.storage.get_latest_block_number().await?
                    else {
                        // db deleted?
                        return Err(eyre::eyre!("No blocks stored"));
                    };
                    if new.tip().number() <= latest_stored_block_number {
                        continue;
                    }
                    for block_number in (latest_stored_block_number + 1)..=new.tip().number() {
                        let block = new.blocks().get(&block_number).unwrap();

                        // By this point, we know that the parent block is stored
                        collector.execute_and_store_block_updates(block).await?;
                    }
                }
                _ => {}
            };

            // Send finish event for committed chain
            if let Some(committed_chain) = notification.committed_chain() {
                self.ctx
                    .events
                    .send(ExExEvent::FinishedHeight(committed_chain.tip().num_hash()))?;
            }
        }

        Ok(())
    }
}
