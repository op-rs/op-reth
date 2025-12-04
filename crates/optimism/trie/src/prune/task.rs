use crate::{prune::OpProofStoragePruner, OpProofsStore};
use reth_provider::BlockHashReader;
use reth_tasks::shutdown::GracefulShutdown;
use tokio::{time, time::Duration};
use tracing::info;

/// Periodic pruner task: constructs the pruner and runs it every interval.
#[derive(Debug)]
pub struct OpProofStoragePrunerTask<P, H> {
    pruner: OpProofStoragePruner<P, H>,
    min_block_interval: u64,
    task_run_interval: Duration,
}

impl<P, H> OpProofStoragePrunerTask<P, H>
where
    P: OpProofsStore,
    H: BlockHashReader,
{
    /// Initialize a new [`OpProofStoragePrunerTask`]
    pub const fn new(
        provider: P,
        hash_reader: H,
        min_block_interval: u64,
        task_run_interval: Duration,
    ) -> Self {
        let pruner = OpProofStoragePruner::new(provider, hash_reader, min_block_interval);
        Self { pruner, min_block_interval, task_run_interval }
    }

    /// Run forever (until `cancel`), executing one prune pass per `task_run_interval`.
    pub async fn run(self, mut shutdown: GracefulShutdown) {
        info!(
            target: "trie::pruner_task",
            min_block_interval = self.min_block_interval,
            interval_secs = self.task_run_interval.as_secs(),
            "Starting pruner task"
        );

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    info!(target: "trie::pruner_task", "Pruner task cancelled; exiting");
                    break;
                }
                _ = self.pruner.run() => {
                    // After a tick completes (success or error), sleep until the next interval or cancel
                    tokio::select! {
                        _ = &mut shutdown => break,
                        _ = time::sleep(self.task_run_interval) => {}
                    }
                }
            }
        }

        info!(target: "trie::pruner_task", "Pruner task stopped");
    }
}
