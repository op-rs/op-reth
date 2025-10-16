//! Live trie collector for external proofs storage.

use crate::{
    metrics::StorageMetrics,
    provider::OpProofsStateProviderRef,
    storage::{BlockStateDiff, OpProofsStorage},
};
use alloy_primitives::B256;
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_node_api::{FullNodeComponents, NodePrimitives, NodeTypes};
use reth_primitives_traits::{AlloyBlockHeader, RecoveredBlock};
use reth_provider::{
    DatabaseProviderFactory, HashedPostStateProvider, StateProviderFactory, StateReader,
    StateRootProvider,
};
use reth_revm::database::StateProviderDatabase;
use reth_storage_api::StateProvider;
use std::{
    collections::VecDeque,
    sync::{Arc, RwLock},
    time::Instant,
};
use tracing::debug;

pub struct LiveTrieWriter<S: OpProofsStorage, P> {
    provider: P,

    storage: S,

    // map of (block_number, block_hash, combined_state_diff)
    // The last element is the most recent block with the smallest state diff
    // Adding a block involves updating all previous blocks to include the new block's state diff
    // When we save a block, we just delete the entry for the block we are saving and it's assumed
    // that storage now contains this block's state diff
    pending_blocks: RwLock<VecDeque<(u64, B256, BlockStateDiff)>>,
}

impl<'a, S: OpProofsStorage + Clone + 'a, P: StateProviderFactory + DatabaseProviderFactory>
    LiveTrieWriter<S, P>
{
    pub fn write_block_updates(
        &self,
        block_number: u64,
        block_hash: B256,
        block_state_diff: BlockStateDiff,
    ) -> eyre::Result<()> {
        let mut pending_blocks = self.pending_blocks.write().unwrap();
        // update all previous blocks to include the new block's state diff
        for i in (0..pending_blocks.len() - 1).rev() {
            pending_blocks[i].2.extend_ref(&block_state_diff);
        }
        pending_blocks.push_back((block_number, block_hash, block_state_diff));
        Ok(())
    }

    pub async fn flush_block(&self) -> eyre::Result<()> {
        //
        let pending_block = self.pending_blocks.read().unwrap().front().cloned();
        if let Some((block_number, block_hash, block_state_diff)) = pending_block {
            self.storage.store_trie_updates(block_number, block_state_diff).await?;

            // remove this block from the pending blocks
            {
                let mut pending_blocks = self.pending_blocks.write().unwrap();
                let remove_idx = pending_blocks
                    .iter()
                    .position(|(b, h, _)| *b == block_number && *h == block_hash)
                    .unwrap();
                pending_blocks.remove(remove_idx);
            }
        }
        Ok(())
    }

    pub fn state_provider(
        &self,
        block_hash: B256,
        block_number: u64,
    ) -> Box<dyn StateProvider + 'a> {
        // check if we have a pending block for this block number
        let pending = self
            .pending_blocks
            .read()
            .unwrap()
            .iter()
            .find(|(_, h, _)| *h == block_hash)
            .map(|(_, _, diff)| diff.clone());

        Box::new(OpProofsStateProviderRef::new(
            self.provider.state_by_block_hash(block_hash).unwrap(),
            self.storage.clone(),
            block_number,
            pending,
        ))
    }
}

/// Live trie collector for external proofs storage.
#[derive(Debug)]
pub struct LiveTrieCollector<Node, PreimageStore>
where
    Node: FullNodeComponents,
    Node::Provider: StateReader + DatabaseProviderFactory + StateProviderFactory,
{
    evm_config: Node::Evm,
    provider: Node::Provider,
    storage: PreimageStore,
    metrics: Arc<StorageMetrics>,
}

impl<Node, Store, Primitives> LiveTrieCollector<Node, Store>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = Primitives>>,
    Primitives: NodePrimitives,
    Store: OpProofsStorage + Clone + 'static,
{
    /// Create a new `LiveTrieCollector` instance
    pub const fn new(
        evm_config: Node::Evm,
        provider: Node::Provider,
        storage: Store,
        metrics: Arc<StorageMetrics>,
    ) -> Self {
        Self { evm_config, provider, storage, metrics }
    }

    /// Execute a block and store the updates in the storage.
    pub async fn execute_and_store_block_updates(
        &self,
        block: &RecoveredBlock<Primitives::Block>,
    ) -> eyre::Result<()> {
        let total_start = Instant::now();

        // Ensure that we have the state of the parent block
        let (Some((earliest, _)), Some((latest, _))) = (
            self.storage.get_earliest_block_number().await?,
            self.storage.get_latest_block_number().await?,
        ) else {
            return Err(eyre::eyre!("No blocks stored"));
        };

        let parent_block_number = block.number() - 1;
        if parent_block_number < earliest {
            return Err(eyre::eyre!(
                "Parent block number is less than earliest stored block number"
            ));
        }

        if parent_block_number > latest {
            return Err(eyre::eyre!(
                "Cannot execute block updates for block {} without parent state {} (latest stored block number: {})",
                block.number(),
                parent_block_number,
                latest
            ));
        }

        let block_number = block.number();

        // TODO: should we check block hash here?

        let state_provider = OpProofsStateProviderRef::new(
            self.provider.state_by_block_hash(block.parent_hash())?,
            self.storage.clone(),
            parent_block_number,
        );

        // Execute block (EVM)
        let execution_start = Instant::now();
        let db = StateProviderDatabase::new(&state_provider);
        let block_executor = self.evm_config.batch_executor(db);
        let execution_result =
            block_executor.execute(&(*block).clone()).map_err(|err| eyre::eyre!(err))?;
        let execution_duration = execution_start.elapsed();

        // Calculate state root
        let state_root_start = Instant::now();
        let hashed_state = state_provider.hashed_post_state(&execution_result.state);
        let (state_root, trie_updates) =
            state_provider.state_root_with_updates(hashed_state.clone())?;
        let state_root_duration = state_root_start.elapsed();

        if state_root != block.state_root() {
            return Err(eyre::eyre!(
                "State root mismatch for block {} (have: {}, expected: {})",
                block.number(),
                state_root,
                block.state_root()
            ));
        }

        // Write trie updates
        let write_start = Instant::now();
        let (
            account_trie_updates_written,
            storage_trie_updates_written,
            hashed_accounts_written,
            hashed_storages_written,
        ) = self
            .storage
            .store_trie_updates(
                block_number,
                BlockStateDiff { trie_updates, post_state: hashed_state },
            )
            .await?;
        let write_duration = write_start.elapsed();

        let total_duration = total_start.elapsed();

        // Record metrics
        let block_metrics = self.metrics.block_metrics();
        block_metrics.execution_duration_seconds.record(execution_duration);
        block_metrics.state_root_duration_seconds.record(state_root_duration);
        block_metrics.write_duration_seconds.record(write_duration);
        block_metrics.total_duration_seconds.record(total_duration);
        block_metrics.account_trie_updates_written_total.increment(account_trie_updates_written);
        block_metrics.storage_trie_updates_written_total.increment(storage_trie_updates_written);
        block_metrics.hashed_accounts_written_total.increment(hashed_accounts_written);
        block_metrics.hashed_storages_written_total.increment(hashed_storages_written);

        // Keep debug logs for backward compatibility
        debug!("execute_and_store_block_updates duration: {:?}", total_duration);
        debug!("- execution_duration: {:?}", execution_duration);
        debug!("- state_root_duration: {:?}", state_root_duration);
        debug!("- write_duration: {:?}", write_duration);
        debug!("- account_trie_updates_written: {:?}", account_trie_updates_written);
        debug!("- storage_trie_updates_written: {:?}", storage_trie_updates_written);
        debug!("- hashed_accounts_written: {:?}", hashed_accounts_written);
        debug!("- hashed_storages_written: {:?}", hashed_storages_written);

        Ok(())
    }
}
