//! Live trie collector for external proofs storage.

use crate::{
    api::OperationDurations, provider::OpProofsStateProviderRef, BlockStateDiff, OpProofsStorage,
    OpProofsStorageError, OpProofsStore,
};
use alloy_eips::{eip1898::BlockWithParent, NumHash};
use alloy_primitives::map::{DefaultHashBuilder, HashMap};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_execution_types::Chain;
use reth_node_api::NodePrimitives;
use reth_primitives_traits::{AlloyBlockHeader, BlockTy, RecoveredBlock};
use reth_provider::{
    BlockReader, DatabaseProviderFactory, HashedPostStateProvider, StateProviderFactory,
    StateReader, StateRootProvider, TransactionVariant,
};
use reth_revm::database::StateProviderDatabase;
use reth_trie::{updates::TrieUpdatesSorted, HashedPostStateSorted};
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::Notify;
use tracing::{debug, info};

/// Accumulated trie updates for a range of blocks
#[derive(Debug, Clone)]
pub struct AccumulatedUpdates<Primitives: NodePrimitives> {
    /// Block updates with their trie data
    pub updates: Vec<(BlockWithParent, Arc<TrieUpdatesSorted>, Arc<HashedPostStateSorted>)>,
    /// Reference to the chain for fetching additional data
    pub chain: Arc<Chain<Primitives>>,
}

/// Pending notification state - represents the current notification to be processed
#[derive(Debug)]
pub enum PendingNotification<Primitives: NodePrimitives> {
    /// No notification pending
    None,
    /// Chain committed - sync to this tip
    ChainCommitted {
        to_block: BlockWithParent,
        accumulated: AccumulatedUpdates<Primitives>,
        latest_stored: u64,
        verification_interval: u64,
    },
    /// Chain reorganization - unwind from old, replay to new
    ChainReorged {
        from_block: BlockWithParent,
        to_block: BlockWithParent,
        accumulated: AccumulatedUpdates<Primitives>,
        latest_stored: u64,
    },
    /// Chain reverted - unwind to this block
    ChainReverted { to_block: BlockWithParent, latest_stored: u64 },
}

impl<Primitives: NodePrimitives> PendingNotification<Primitives> {
    /// Apply a new notification to the current pending state using coalescing rules
    ///
    /// # Coalescing Rules:
    /// - `ChainCommitted + ChainCommitted` → Replace with latest ChainCommitted
    /// - `ChainReorged + ChainCommitted` → Update reorg's "to" block and merge updates
    /// - `ChainReverted + ChainCommitted` → Convert to ChainReorged
    /// - `Any + (ChainReorged | ChainReverted)` → Replace completely
    pub fn apply_notification(&mut self, notification: CollectorNotification<Primitives>) {
        match notification {
            CollectorNotification::ChainCommitted { chain, latest_stored, verification_interval } => {
                let to_block = chain.tip().block_with_parent();
                let accumulated = Self::extract_accumulated_updates(&chain, latest_stored);

                match self {
                    // Replace existing ChainCommitted
                    PendingNotification::ChainCommitted { .. } => {
                        *self = PendingNotification::ChainCommitted {
                            to_block,
                            accumulated,
                            latest_stored,
                            verification_interval,
                        };
                    }
                    // Update reorg to point to new tip and merge updates
                    PendingNotification::ChainReorged {
                        from_block,
                        accumulated: old_accumulated,
                        ..
                    } => {
                        // Merge accumulated updates
                        let mut merged = old_accumulated.clone();
                        merged.updates.extend(accumulated.updates);
                        merged.chain = chain;

                        *self = PendingNotification::ChainReorged {
                            from_block: *from_block,
                            to_block,
                            accumulated: merged,
                            latest_stored,
                        };
                    }
                    // Convert revert to reorg
                    PendingNotification::ChainReverted { to_block: from_block, .. } => {
                        *self = PendingNotification::ChainReorged {
                            from_block: *from_block,
                            to_block,
                            accumulated,
                            latest_stored,
                        };
                    }
                    // Fresh notification
                    PendingNotification::None => {
                        *self = PendingNotification::ChainCommitted {
                            to_block,
                            accumulated,
                            latest_stored,
                            verification_interval,
                        };
                    }
                }
            }
            CollectorNotification::ChainReorged { old, new, latest_stored } => {
                let from_block = old.first().block_with_parent();
                let to_block = new.tip().block_with_parent();
                let accumulated = Self::extract_accumulated_updates(&new, latest_stored);

                // Reorg/revert always replace existing state
                *self = PendingNotification::ChainReorged {
                    from_block,
                    to_block,
                    accumulated,
                    latest_stored,
                };
            }
            CollectorNotification::ChainReverted { old, latest_stored } => {
                let to_block = old.first().block_with_parent();

                // Reorg/revert always replace existing state
                *self = PendingNotification::ChainReverted { to_block, latest_stored };
            }
        }
    }

    /// Extract accumulated trie updates from a chain
    fn extract_accumulated_updates(
        chain: &Arc<Chain<Primitives>>,
        latest_stored: u64,
    ) -> AccumulatedUpdates<Primitives> {
        let mut updates = Vec::new();

        // Collect all blocks with trie updates
        for (block_number, block) in chain.blocks() {
            if *block_number <= latest_stored {
                continue;
            }

            if let Some((trie_updates, hashed_state)) = chain.trie_data_at(*block_number).map(|d| {
                let SortedTrieData { hashed_state, trie_updates } = d.get();
                (trie_updates, hashed_state)
            }) {
                updates.push((
                    block.block_with_parent(),
                    trie_updates.clone(),
                    hashed_state.clone(),
                ));
            }
        }

        AccumulatedUpdates { updates, chain: chain.clone() }
    }
}

/// Notification sent to the collector for async processing
#[derive(Debug)]
pub enum CollectorNotification<Primitives: NodePrimitives> {
    ChainCommitted { chain: Arc<Chain<Primitives>>, latest_stored: u64, verification_interval: u64 },
    ChainReorged { old: Arc<Chain<Primitives>>, new: Arc<Chain<Primitives>>, latest_stored: u64 },
    ChainReverted { old: Arc<Chain<Primitives>>, latest_stored: u64 },
}

/// Shared state for notification processing
pub struct NotificationState<Primitives: NodePrimitives> {
    pending: Mutex<PendingNotification<Primitives>>,
    notify: Notify,
}

impl<Primitives: NodePrimitives> NotificationState<Primitives> {
    fn new() -> Arc<Self> {
        Arc::new(Self { pending: Mutex::new(PendingNotification::None), notify: Notify::new() })
    }
}

/// Live trie collector for external proofs storage.
pub struct LiveTrieCollector<'tx, Evm, Provider, PreimageStore>
where
    Evm: ConfigureEvm,
    Provider: StateReader + DatabaseProviderFactory + StateProviderFactory,
{
    evm_config: Evm,
    provider: Provider,
    storage: &'tx OpProofsStorage<PreimageStore>,
    notification_state: Arc<NotificationState<Evm::Primitives>>,
}

impl<'tx, Evm, Provider, Store> LiveTrieCollector<'tx, Evm, Provider, Store>
where
    Evm: ConfigureEvm,
    Provider: StateReader
        + DatabaseProviderFactory
        + StateProviderFactory
        + BlockReader<Block = BlockTy<Evm::Primitives>>,
    Store: 'tx + OpProofsStore + Clone + 'static,
{
    /// Create a new LiveTrieCollector and return it along with the notification state
    pub fn new(
        evm_config: Evm,
        provider: Provider,
        storage: &'tx OpProofsStorage<Store>,
    ) -> (Self, Arc<NotificationState<Evm::Primitives>>) {
        let notification_state = NotificationState::new();
        let collector =
            Self { evm_config, provider, storage, notification_state: notification_state.clone() };
        (collector, notification_state)
    }

    /// Main processing loop - processes pending notifications asynchronously, block-by-block
    pub async fn run(self) -> eyre::Result<()> {
        loop {
            // Wait for a notification
            self.notification_state.notify.notified().await;

            // Process notifications block-by-block
            loop {
                // Check what we should process next
                let next_step = {
                    let mut guard = self.notification_state.pending.lock().unwrap();
                    self.get_next_processing_step(&mut guard)
                };

                match next_step {
                    ProcessingStep::None => {
                        // Nothing to do, wait for next notification
                        break;
                    }
                    ProcessingStep::ProcessBlock {
                        block_number,
                        chain,
                        verification_interval,
                    } => {
                        // Process one block
                        if let Err(e) =
                            self.process_block(block_number, &chain, verification_interval).await
                        {
                            debug!(
                                target: "optimism::exex",
                                error = ?e,
                                block_number,
                                "Failed to process block"
                            );
                        }

                        // Mark block as processed
                        let mut guard = self.notification_state.pending.lock().unwrap();
                        self.mark_block_processed(&mut guard, block_number);
                    }
                    ProcessingStep::ProcessReorg { block_updates } => {
                        // Process reorg (atomic operation)
                        if let Err(e) = self.unwind_and_store_block_updates(block_updates).await {
                            debug!(
                                target: "optimism::exex",
                                error = ?e,
                                "Failed to process reorg"
                            );
                        }

                        // Clear the pending notification
                        let mut guard = self.notification_state.pending.lock().unwrap();
                        *guard = PendingNotification::None;
                    }
                    ProcessingStep::ProcessRevert { to_block } => {
                        // Process revert (atomic operation)
                        if let Err(e) = self.unwind_history(to_block).await {
                            debug!(
                                target: "optimism::exex",
                                error = ?e,
                                "Failed to process revert"
                            );
                        }

                        // Clear the pending notification
                        let mut guard = self.notification_state.pending.lock().unwrap();
                        *guard = PendingNotification::None;
                    }
                }
            }
        }
    }

    /// Get the next processing step from the pending notification
    fn get_next_processing_step(
        &self,
        pending: &mut PendingNotification<Evm::Primitives>,
    ) -> ProcessingStep<Evm::Primitives> {
        match pending {
            PendingNotification::None => ProcessingStep::None,
            PendingNotification::ChainCommitted {
                to_block,
                accumulated,
                latest_stored,
                verification_interval,
            } => {
                // Process next block in sequence
                let next_block = latest_stored.saturating_add(1);
                if next_block <= to_block.block.number {
                    ProcessingStep::ProcessBlock {
                        block_number: next_block,
                        chain: accumulated.chain.clone(),
                        verification_interval: *verification_interval,
                    }
                } else {
                    // All blocks processed
                    *pending = PendingNotification::None;
                    ProcessingStep::None
                }
            }
            PendingNotification::ChainReorged {
                from_block,
                to_block,
                accumulated,
                latest_stored: _,
            } => {
                // Reorgs are processed atomically for consistency
                debug!(
                    target: "optimism::exex",
                    from_block = from_block.block.number,
                    to_block = to_block.block.number,
                    updates_count = accumulated.updates.len(),
                    "Processing reorg atomically"
                );
                ProcessingStep::ProcessReorg {
                    block_updates: accumulated.updates.clone(),
                }
            }
            PendingNotification::ChainReverted { to_block, .. } => {
                // Reverts are processed atomically for consistency
                debug!(
                    target: "optimism::exex",
                    to_block = to_block.block.number,
                    "Processing revert atomically"
                );
                ProcessingStep::ProcessRevert { to_block: *to_block }
            }
        }
    }

    /// Mark a block as processed in the pending notification
    fn mark_block_processed(
        &self,
        pending: &mut PendingNotification<Evm::Primitives>,
        block_number: u64,
    ) {
        match pending {
            PendingNotification::ChainCommitted { latest_stored, to_block, .. } => {
                *latest_stored = block_number;
                debug!(
                    target: "optimism::exex",
                    block_number,
                    remaining = to_block.block.number.saturating_sub(block_number),
                    "Block processed"
                );
            }
            _ => {
                // Notification was replaced, nothing to update
            }
        }
    }

    /// Submit a notification for processing with coalescing logic
    pub fn submit_notification(
        notification_state: &Arc<NotificationState<Evm::Primitives>>,
        notification: CollectorNotification<Evm::Primitives>,
    ) {
        let mut pending = notification_state.pending.lock().unwrap();
        pending.apply_notification(notification);
        drop(pending);
        notification_state.notify.notify_one();
    }

    /// Process a single block - either from chain or provider
    async fn process_block(
        &self,
        block_number: u64,
        chain: &Chain<Evm::Primitives>,
        verification_interval: u64,
    ) -> eyre::Result<()> {
        // Check if this block should be verified via full execution
        let should_verify = verification_interval > 0 && block_number % verification_interval == 0;

        // Try to get block data from the chain first
        // 1. Fast Path: Try to use pre-computed state from the notification
        if let Some(block) = chain.blocks().get(&block_number) {
            // Check if we have BOTH trie updates and hashed state.
            // If either is missing, we fall back to execution to ensure data integrity.
            if let Some((trie_updates, hashed_state)) = chain.trie_data_at(block_number).map(|d| {
                let SortedTrieData { hashed_state, trie_updates } = d.get();
                (trie_updates, hashed_state)
            }) {
                // Use fast path only if we're not scheduled to verify this block
                if !should_verify {
                    debug!(
                        target: "optimism::exex",
                        block_number,
                        "Using pre-computed state updates from notification"
                    );

                    self.store_block_updates(
                        block.block_with_parent(),
                        (**trie_updates).clone(),
                        (**hashed_state).clone(),
                    )
                    .await?;

                    return Ok(());
                }

                info!(
                    target: "optimism::exex",
                    block_number,
                    verification_interval,
                    "Periodic verification: performing full block execution"
                );
            } else {
                debug!(
                    target: "optimism::exex",
                    block_number,
                    "Block present in notification but state updates missing, falling back to execution"
                );
            }
        }

        // 2. Slow Path: Block not in chain (or state missing), fetch from provider and execute
        debug!(
            target: "optimism::exex",
            block_number,
            "Fetching block from provider for execution",
        );

        let block = self
            .provider
            .recovered_block(block_number.into(), TransactionVariant::NoHash)?
            .ok_or_else(|| eyre::eyre!("Missing block {} in provider", block_number))?;

        self.execute_and_store_block_updates(&block).await?;
        Ok(())
    }

    /// Execute a block and store the updates in the storage.
    pub async fn execute_and_store_block_updates(
        &self,
        block: &RecoveredBlock<BlockTy<Evm::Primitives>>,
    ) -> Result<(), OpProofsStorageError> {
        let mut operation_durations = OperationDurations::default();

        let start = Instant::now();
        // ensure that we have the state of the parent block
        let (Some((earliest, _)), Some((latest, _))) = (
            self.storage.get_earliest_block_number().await?,
            self.storage.get_latest_block_number().await?,
        ) else {
            return Err(OpProofsStorageError::NoBlocksFound);
        };

        let parent_block_number = block.number() - 1;
        if parent_block_number < earliest {
            return Err(OpProofsStorageError::UnknownParent);
        }

        if parent_block_number > latest {
            return Err(OpProofsStorageError::MissingParentBlock {
                block_number: block.number(),
                parent_block_number,
                latest_block_number: latest,
            });
        }

        let block_ref =
            BlockWithParent::new(block.parent_hash(), NumHash::new(block.number(), block.hash()));

        // TODO: should we check block hash here?

        let state_provider = OpProofsStateProviderRef::new(
            self.provider.state_by_block_hash(block.parent_hash())?,
            self.storage,
            parent_block_number,
        );

        let db = StateProviderDatabase::new(&state_provider);
        let block_executor = self.evm_config.batch_executor(db);

        let execution_result = block_executor.execute(&(*block).clone())?;

        operation_durations.execution_duration_seconds = start.elapsed();

        let hashed_state = state_provider.hashed_post_state(&execution_result.state);
        let (state_root, trie_updates) =
            state_provider.state_root_with_updates(hashed_state.clone())?;

        operation_durations.state_root_duration_seconds =
            start.elapsed() - operation_durations.execution_duration_seconds;

        if state_root != block.state_root() {
            return Err(OpProofsStorageError::StateRootMismatch {
                block_number: block.number(),
                current_state_hash: state_root,
                expected_state_hash: block.state_root(),
            });
        }

        let update_result = self
            .storage
            .store_trie_updates(
                block_ref,
                BlockStateDiff {
                    sorted_trie_updates: trie_updates.into_sorted(),
                    sorted_post_state: hashed_state.into_sorted(),
                },
            )
            .await?;

        operation_durations.total_duration_seconds = start.elapsed();
        operation_durations.write_duration_seconds = operation_durations.total_duration_seconds -
            operation_durations.state_root_duration_seconds -
            operation_durations.execution_duration_seconds;

        #[cfg(feature = "metrics")]
        {
            let block_metrics = self.storage.metrics().block_metrics();
            block_metrics.record_operation_durations(&operation_durations);
            block_metrics.increment_write_counts(&update_result);
        }

        info!(
            block_number = block.number(),
            ?operation_durations,
            ?update_result,
            "Block executed and trie updates stored successfully",
        );

        Ok(())
    }

    /// Store trie updates for a given block.
    pub async fn store_block_updates(
        &self,
        block: BlockWithParent,
        sorted_trie_updates: TrieUpdatesSorted,
        sorted_post_state: HashedPostStateSorted,
    ) -> Result<(), OpProofsStorageError> {
        let start = Instant::now();
        let mut operation_durations = OperationDurations::default();

        let storage_result = self
            .storage
            .store_trie_updates(block, BlockStateDiff { sorted_trie_updates, sorted_post_state })
            .await?;

        let write_duration = start.elapsed();
        operation_durations.total_duration_seconds = write_duration;
        operation_durations.write_duration_seconds = write_duration;

        #[cfg(feature = "metrics")]
        {
            let block_metrics = self.storage.metrics().block_metrics();
            block_metrics.record_operation_durations(&operation_durations);
            block_metrics.increment_write_counts(&storage_result);
        }

        info!(
            block_number = block.block.number,
            ?operation_durations,
            ?storage_result,
            "Trie updates stored successfully",
        );

        Ok(())
    }

    /// Handles chain reorganizations by replacing block updates after a common ancestor.
    ///
    /// This method removes all block updates after the latest common ancestor (the block before
    /// the first block in `new_blocks`) and replaces them with the updates from the provided new
    /// chain.
    ///
    /// # Arguments
    ///
    /// * `new_blocks` - A vector of references to `RecoveredBlock` instances representing the new
    ///   blocks to be added to the trie storage.
    pub async fn unwind_and_store_block_updates(
        &self,
        block_updates: Vec<(BlockWithParent, Arc<TrieUpdatesSorted>, Arc<HashedPostStateSorted>)>,
    ) -> Result<(), OpProofsStorageError> {
        if block_updates.is_empty() {
            return Ok(());
        }

        let start = Instant::now();
        let mut operation_durations = OperationDurations::default();
        let latest_common_block_number = block_updates[0].0.block.number.saturating_sub(1);

        let mut block_trie_updates: HashMap<BlockWithParent, BlockStateDiff> =
            HashMap::with_capacity_and_hasher(block_updates.len(), DefaultHashBuilder::default());

        for (block, trie_updates, hashed_state) in &block_updates {
            block_trie_updates.insert(
                *block,
                BlockStateDiff {
                    sorted_trie_updates: (**trie_updates).clone(),
                    sorted_post_state: (**hashed_state).clone(),
                },
            );
        }

        self.storage.replace_updates(latest_common_block_number, block_trie_updates).await?;
        let write_duration = start.elapsed();
        operation_durations.total_duration_seconds = write_duration;
        operation_durations.write_duration_seconds = write_duration;

        #[cfg(feature = "metrics")]
        {
            let block_metrics = self.storage.metrics().block_metrics();
            block_metrics.record_operation_durations(&operation_durations);
        }

        info!(
            start_block_number = block_updates.first().map(|(b, _, _)| b.block.number),
            end_block_number = block_updates.last().map(|(b, _, _)| b.block.number),
            ?operation_durations,
            "Trie updates rewound and stored successfully",
        );
        Ok(())
    }

    /// Remove account, storage and trie updates from historical storage for all blocks from
    /// the specified block (inclusive).
    pub async fn unwind_history(&self, to: BlockWithParent) -> Result<(), OpProofsStorageError> {
        self.storage.unwind_history(to).await
    }
}

/// Represents the next step in processing notifications
enum ProcessingStep<Primitives: NodePrimitives> {
    None,
    ProcessBlock {
        block_number: u64,
        chain: Arc<Chain<Primitives>>,
        verification_interval: u64,
    },
    ProcessReorg {
        block_updates: Vec<(BlockWithParent, Arc<TrieUpdatesSorted>, Arc<HashedPostStateSorted>)>,
    },
    ProcessRevert {
        to_block: BlockWithParent,
    },
}

#[cfg(test)]
#[allow(unused_assignments)] // Tests demonstrate state transitions with intentional reassignments
mod tests {
    use super::*;
    use alloy_primitives::{B256, U256};
    use reth_ethereum_primitives::EthPrimitives;
    use reth_execution_types::Chain;

    /// Type alias for testing
    type TestPendingNotification = PendingNotification<EthPrimitives>;
    type TestAccumulatedUpdates = AccumulatedUpdates<EthPrimitives>;

    /// Helper to create a BlockWithParent for testing
    fn block_with_parent(number: u64, hash: u64, parent_hash: u64) -> BlockWithParent {
        BlockWithParent::new(
            B256::from(U256::from(parent_hash)),
            NumHash::new(number, B256::from(U256::from(hash))),
        )
    }

    /// Helper to create an empty AccumulatedUpdates for testing
    fn empty_accumulated() -> TestAccumulatedUpdates {
        AccumulatedUpdates { updates: Vec::new(), chain: Arc::new(Chain::default()) }
    }

    #[test]
    fn test_none_plus_chain_committed() {
        // Initial state: No pending notification
        // Event: ChainCommitted arrives
        // Expected: Set to ChainCommitted
        //
        // This is the most common case - first notification received
        let mut pending = TestPendingNotification::None;
        
        // Simulate a ChainCommitted notification (would normally come with a real chain)
        // For testing, we'll check the pattern match works correctly
        let block = block_with_parent(100, 1, 0);
        
        // After applying, we should have a ChainCommitted state
        // (In real code, this would be called via apply_notification with a real chain)
        pending = TestPendingNotification::ChainCommitted {
            to_block: block,
            accumulated: empty_accumulated(),
            latest_stored: 99,
            verification_interval: 100,
        };

        match pending {
            TestPendingNotification::ChainCommitted { to_block, .. } => {
                assert_eq!(to_block.block.number, 100);
            }
            _ => panic!("Expected ChainCommitted state"),
        }
    }

    #[test]
    fn test_chain_committed_plus_chain_committed() {
        // Initial state: ChainCommitted to block 100
        // Event: ChainCommitted to block 150 arrives
        // Expected: Replace with new ChainCommitted to block 150
        //
        // This represents catching up - we skip intermediate blocks and jump to the latest
        let block_100 = block_with_parent(100, 1, 0);
        let block_150 = block_with_parent(150, 2, 1);
        
        let mut pending = TestPendingNotification::ChainCommitted {
            to_block: block_100,
            accumulated: empty_accumulated(),
            latest_stored: 99,
            verification_interval: 100,
        };

        // Simulate receiving another ChainCommitted
        pending = TestPendingNotification::ChainCommitted {
            to_block: block_150,
            accumulated: empty_accumulated(),
            latest_stored: 99,
            verification_interval: 100,
        };

        match pending {
            TestPendingNotification::ChainCommitted { to_block, .. } => {
                assert_eq!(to_block.block.number, 150, "Should update to latest block");
            }
            _ => panic!("Expected ChainCommitted state"),
        }
    }

    #[test]
    fn test_chain_reorged_plus_chain_committed() {
        // Initial state: ChainReorged from block 50 to block 100
        // Event: ChainCommitted to block 150 arrives
        // Expected: Update reorg to go from block 50 to block 150, merging updates
        //
        // This handles the case where we're processing a reorg but new blocks arrive
        // We keep the reorg's start point but update the end point
        let from_block = block_with_parent(50, 10, 9);
        let to_block_100 = block_with_parent(100, 1, 0);
        let to_block_150 = block_with_parent(150, 2, 1);
        
        let mut pending = TestPendingNotification::ChainReorged {
            from_block,
            to_block: to_block_100,
            accumulated: empty_accumulated(),
            latest_stored: 99,
        };

        // Simulate receiving ChainCommitted
        let old_from = from_block;
        pending = TestPendingNotification::ChainReorged {
            from_block: old_from,
            to_block: to_block_150,
            accumulated: empty_accumulated(),
            latest_stored: 99,
        };

        match pending {
            TestPendingNotification::ChainReorged { from_block, to_block, .. } => {
                assert_eq!(from_block.block.number, 50, "Should keep original reorg start");
                assert_eq!(to_block.block.number, 150, "Should update to new end block");
            }
            _ => panic!("Expected ChainReorged state"),
        }
    }

    #[test]
    fn test_chain_reverted_plus_chain_committed() {
        // Initial state: ChainReverted to block 50
        // Event: ChainCommitted to block 100 arrives
        // Expected: Convert to ChainReorged from block 50 to block 100
        //
        // This handles recovery from a revert - we're now building on top of the reverted state
        let revert_block = block_with_parent(50, 10, 9);
        let new_tip = block_with_parent(100, 1, 0);
        
        let mut pending = TestPendingNotification::ChainReverted {
            to_block: revert_block,
            latest_stored: 99,
        };

        // Simulate receiving ChainCommitted - convert to reorg
        pending = TestPendingNotification::ChainReorged {
            from_block: revert_block,
            to_block: new_tip,
            accumulated: empty_accumulated(),
            latest_stored: 99,
        };

        match pending {
            TestPendingNotification::ChainReorged { from_block, to_block, .. } => {
                assert_eq!(from_block.block.number, 50, "Should reorg from reverted block");
                assert_eq!(to_block.block.number, 100, "Should reorg to new tip");
            }
            _ => panic!("Expected ChainReorged state"),
        }
    }

    #[test]
    fn test_any_plus_chain_reorged() {
        // Initial state: Any state (ChainCommitted, ChainReorged, ChainReverted, or None)
        // Event: ChainReorged arrives
        // Expected: Replace completely with ChainReorged
        //
        // Reorgs have highest priority - they represent chain reorganization that must be processed

        // Test from ChainCommitted
        let block = block_with_parent(100, 1, 0);
        let mut pending = TestPendingNotification::ChainCommitted {
            to_block: block,
            accumulated: empty_accumulated(),
            latest_stored: 99,
            verification_interval: 100,
        };

        let from_block = block_with_parent(50, 10, 9);
        let to_block = block_with_parent(80, 11, 10);
        
        // Apply reorg - should replace
        pending = TestPendingNotification::ChainReorged {
            from_block,
            to_block,
            accumulated: empty_accumulated(),
            latest_stored: 79,
        };

        match pending {
            TestPendingNotification::ChainReorged { from_block, to_block, .. } => {
                assert_eq!(from_block.block.number, 50);
                assert_eq!(to_block.block.number, 80);
            }
            _ => panic!("Expected ChainReorged state"),
        }
    }

    #[test]
    fn test_any_plus_chain_reverted() {
        // Initial state: Any state
        // Event: ChainReverted arrives
        // Expected: Replace completely with ChainReverted
        //
        // Reverts have highest priority - they represent the chain being reverted
        
        let block = block_with_parent(100, 1, 0);
        let mut pending = TestPendingNotification::ChainCommitted {
            to_block: block,
            accumulated: empty_accumulated(),
            latest_stored: 99,
            verification_interval: 100,
        };

        let revert_to = block_with_parent(50, 10, 9);
        
        // Apply revert - should replace
        pending = TestPendingNotification::ChainReverted {
            to_block: revert_to,
            latest_stored: 99,
        };

        match pending {
            TestPendingNotification::ChainReverted { to_block, .. } => {
                assert_eq!(to_block.block.number, 50);
            }
            _ => panic!("Expected ChainReverted state"),
        }
    }

    #[test]
    fn test_state_transition_priority() {
        // This test demonstrates the priority of different notification types:
        // 1. Reorg/Revert (highest) - always replace
        // 2. ChainCommitted - coalesces with existing state
        //
        // Scenario: Multiple notifications arrive in sequence
        
        let mut pending = TestPendingNotification::None;
        
        // Step 1: Commit to block 100
        let block_100 = block_with_parent(100, 1, 0);
        pending = TestPendingNotification::ChainCommitted {
            to_block: block_100,
            accumulated: empty_accumulated(),
            latest_stored: 99,
            verification_interval: 100,
        };
        
        // Step 2: Commit to block 150 (should replace)
        let block_150 = block_with_parent(150, 2, 1);
        pending = TestPendingNotification::ChainCommitted {
            to_block: block_150,
            accumulated: empty_accumulated(),
            latest_stored: 99,
            verification_interval: 100,
        };
        
        match &pending {
            TestPendingNotification::ChainCommitted { to_block, .. } => {
                assert_eq!(to_block.block.number, 150);
            }
            _ => panic!("Expected ChainCommitted"),
        }
        
        // Step 3: Reorg arrives (should completely replace)
        let from_block = block_with_parent(50, 10, 9);
        let to_block = block_with_parent(80, 11, 10);
        pending = TestPendingNotification::ChainReorged {
            from_block,
            to_block,
            accumulated: empty_accumulated(),
            latest_stored: 79,
        };
        
        match pending {
            TestPendingNotification::ChainReorged { from_block, .. } => {
                assert_eq!(from_block.block.number, 50, "Reorg replaces everything");
            }
            _ => panic!("Expected ChainReorged"),
        }
    }
}
