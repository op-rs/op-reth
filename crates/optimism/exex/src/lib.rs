//! ExEx unique for OP-Reth. See also [`reth_exex`] for more op-reth execution extensions.

use derive_more::Constructor;
use futures_util::TryStreamExt;
use reth_chainspec::ChainInfo;
use reth_exex::{ExExContext, ExExEvent};
use reth_node_api::{FullNodeComponents, NodePrimitives};
use reth_node_types::NodeTypes;
use reth_optimism_trie::{BackfillJob, InMemoryProofsStorage};
use reth_provider::{BlockNumReader, DBProvider, DatabaseProviderFactory};
use std::sync::Arc;

/// OP Proofs ExEx - processes blocks and tracks state changes within fault proof window.
///
/// Saves and serves trie nodes to make proofs faster. This handles the process of
/// saving the current state, new blocks as they're added, and serving proof RPCs
/// based on the saved data.
#[derive(Debug, Constructor)]
pub struct OpProofsExEx<Node>
where
    Node: FullNodeComponents,
{
    /// The ExEx context containing the node related utilities e.g. provider, notifications,
    /// events.
    ctx: ExExContext<Node>,
    /// The type of storage DB.
    #[expect(dead_code)]
    db: ProofsStorage,
    /// The path to the storage DB for proofs history.
    #[expect(dead_code)]
    db_path: Option<String>,
    /// The window to span past blocks for proofs history. Value is the number of blocks.
    #[expect(dead_code)]
    proofs_window: u64,
}

impl<Node, Primitives> OpProofsExEx<Node>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = Primitives>>,
    Primitives: NodePrimitives,
{
    /// Main execution loop for the ExEx
    pub async fn run(mut self) -> eyre::Result<()> {
        // TODO: support different storage types
        let storage = Arc::new(InMemoryProofsStorage::new());

        let db_provider =
            self.ctx.provider().database_provider_ro()?.disable_long_read_transaction_safety();
        let db_tx = db_provider.into_tx();
        let ChainInfo { best_number, best_hash } = self.ctx.provider().chain_info()?;
        BackfillJob::new(storage.clone(), &db_tx).run(best_number, best_hash).await?;

        while let Some(notification) = self.ctx.notifications.try_next().await? {
            // match &notification {
            //     _ => {}
            // };

            if let Some(committed_chain) = notification.committed_chain() {
                self.ctx
                    .events
                    .send(ExExEvent::FinishedHeight(committed_chain.tip().num_hash()))?;
            }
        }

        Ok(())
    }
}

/// The type of storage DB for proofs history.
#[derive(Debug, Clone, PartialEq, Eq, clap::ValueEnum)]
pub enum ProofsStorage {
    /// MDBX
    Mdbx,
}

impl std::fmt::Display for ProofsStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mdbx => f.write_str("mdbx"),
        }
    }
}
