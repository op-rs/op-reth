//! OP Proofs ExEx - processes blocks and tracks state changes within fault proof window

use derive_more::Constructor;
use futures_util::TryStreamExt;
use reth_exex::{ExExContext, ExExEvent};
use reth_node_api::{FullNodeComponents, NodePrimitives};
use reth_node_types::NodeTypes;
use reth_provider::StateReader;

/// Saves and serves trie nodes to make proofs faster. This handles the process of
/// saving the current state, new blocks as they're added, and serving proof RPCs
/// based on the saved data.
#[derive(Debug, Constructor)]
pub struct OpProofsExEx<Node>
where
    Node: FullNodeComponents,
    Node::Provider: StateReader,
{
    ctx: ExExContext<Node>,
}

impl<Node, Primitives> OpProofsExEx<Node>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = Primitives>>,
    Primitives: NodePrimitives,
{
    /// Main execution loop for the ExEx
    pub async fn run(mut self) -> eyre::Result<()> {
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
