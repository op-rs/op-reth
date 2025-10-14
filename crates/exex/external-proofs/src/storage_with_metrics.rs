//! Storage wrapper that records metrics for all operations.

use crate::{
    metrics::{OperationContext, StorageMetrics, StorageOperation},
    storage::{
        BlockStateDiff, OpProofsHashedCursor, OpProofsStorage, OpProofsStorageResult,
        OpProofsTrieCursor,
    },
};
use alloy_primitives::{map::HashMap, B256, U256};
use async_trait::async_trait;
use reth_primitives_traits::Account;
use reth_trie::{BranchNodeCompact, Nibbles};
use std::{fmt::Debug, sync::Arc};

/// Wrapper around OpProofsStorage that records metrics for all operations.
#[derive(Debug, Clone)]
pub struct OpProofsStorageWithMetrics<S> {
    storage: S,
    metrics: Arc<StorageMetrics>,
}

impl<S> OpProofsStorageWithMetrics<S> {
    /// Create a new storage wrapper with metrics.
    pub fn new(storage: S, metrics: Arc<StorageMetrics>) -> Self {
        Self { storage, metrics }
    }

    /// Get the underlying storage.
    pub const fn inner(&self) -> &S {
        &self.storage
    }

    /// Get the metrics.
    pub const fn metrics(&self) -> &Arc<StorageMetrics> {
        &self.metrics
    }
}

/// Wrapper for OpProofsTrieCursor that records metrics.
#[derive(Debug)]
pub struct TrieCursorWithMetrics<C> {
    cursor: C,
    metrics: Arc<StorageMetrics>,
    context: OperationContext,
}

impl<C> TrieCursorWithMetrics<C> {
    /// Create a new cursor wrapper with metrics.
    pub const fn new(cursor: C, metrics: Arc<StorageMetrics>, context: OperationContext) -> Self {
        Self { cursor, metrics, context }
    }
}

impl<C: OpProofsTrieCursor> OpProofsTrieCursor for TrieCursorWithMetrics<C> {
    fn seek_exact(
        &mut self,
        path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        self.metrics.record_operation(StorageOperation::TrieCursorSeekExact, self.context, || {
            self.cursor.seek_exact(path)
        })
    }

    fn seek(
        &mut self,
        path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        self.metrics.record_operation(StorageOperation::TrieCursorSeek, self.context, || {
            self.cursor.seek(path)
        })
    }

    fn next(&mut self) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        self.metrics
            .record_operation(StorageOperation::TrieCursorNext, self.context, || self.cursor.next())
    }

    fn current(&mut self) -> OpProofsStorageResult<Option<Nibbles>> {
        self.metrics.record_operation(StorageOperation::TrieCursorCurrent, self.context, || {
            self.cursor.current()
        })
    }
}

/// Wrapper for OpProofsHashedCursor that records metrics.
#[derive(Debug)]
pub struct HashedCursorWithMetrics<C> {
    cursor: C,
    metrics: Arc<StorageMetrics>,
    context: OperationContext,
}

impl<C> HashedCursorWithMetrics<C> {
    /// Create a new cursor wrapper with metrics.
    pub const fn new(cursor: C, metrics: Arc<StorageMetrics>, context: OperationContext) -> Self {
        Self { cursor, metrics, context }
    }
}

impl<C: OpProofsHashedCursor> OpProofsHashedCursor for HashedCursorWithMetrics<C> {
    type Value = C::Value;

    fn seek(&mut self, key: B256) -> OpProofsStorageResult<Option<(B256, Self::Value)>> {
        self.metrics.record_operation(StorageOperation::HashedCursorSeek, self.context, || {
            self.cursor.seek(key)
        })
    }

    fn next(&mut self) -> OpProofsStorageResult<Option<(B256, Self::Value)>> {
        self.metrics.record_operation(StorageOperation::HashedCursorNext, self.context, || {
            self.cursor.next()
        })
    }

    fn is_storage_empty(&mut self) -> OpProofsStorageResult<bool> {
        self.metrics.record_operation(
            StorageOperation::HashedCursorIsStorageEmpty,
            self.context,
            || self.cursor.is_storage_empty(),
        )
    }
}

#[async_trait]
impl<S> OpProofsStorage for OpProofsStorageWithMetrics<S>
where
    S: OpProofsStorage,
{
    type StorageTrieCursor = TrieCursorWithMetrics<S::StorageTrieCursor>;
    type AccountTrieCursor = TrieCursorWithMetrics<S::AccountTrieCursor>;
    type StorageCursor = HashedCursorWithMetrics<S::StorageCursor>;
    type AccountHashedCursor = HashedCursorWithMetrics<S::AccountHashedCursor>;

    async fn store_account_branches(
        &self,
        block_number: u64,
        updates: Vec<(Nibbles, Option<BranchNodeCompact>)>,
    ) -> OpProofsStorageResult<()> {
        let count = updates.len();
        let start = std::time::Instant::now();
        let result = self.storage.store_account_branches(block_number, updates).await;
        let duration = start.elapsed();

        // Record per-item duration
        if count > 0 {
            self.metrics.record_duration(
                StorageOperation::StoreAccountBranches,
                OperationContext::Write,
                duration / count as u32,
            );
        }

        result
    }

    async fn store_storage_branches(
        &self,
        block_number: u64,
        hashed_address: B256,
        items: Vec<(Nibbles, Option<BranchNodeCompact>)>,
    ) -> OpProofsStorageResult<()> {
        let count = items.len();
        let start = std::time::Instant::now();
        let result = self.storage.store_storage_branches(block_number, hashed_address, items).await;
        let duration = start.elapsed();

        // Record per-item duration
        if count > 0 {
            self.metrics.record_duration(
                StorageOperation::StoreStorageBranches,
                OperationContext::Write,
                duration / count as u32,
            );
        }

        result
    }

    async fn store_hashed_accounts(
        &self,
        accounts: Vec<(B256, Option<Account>)>,
        block_number: u64,
    ) -> OpProofsStorageResult<()> {
        let count = accounts.len();
        let start = std::time::Instant::now();
        let result = self.storage.store_hashed_accounts(accounts, block_number).await;
        let duration = start.elapsed();

        // Record per-item duration
        if count > 0 {
            self.metrics.record_duration(
                StorageOperation::StoreHashedAccounts,
                OperationContext::Write,
                duration / count as u32,
            );
        }

        result
    }

    async fn store_hashed_storages(
        &self,
        hashed_address: B256,
        storages: Vec<(B256, U256)>,
        block_number: u64,
    ) -> OpProofsStorageResult<()> {
        let count = storages.len();
        let start = std::time::Instant::now();
        let result =
            self.storage.store_hashed_storages(hashed_address, storages, block_number).await;
        let duration = start.elapsed();

        // Record per-item duration
        if count > 0 {
            self.metrics.record_duration(
                StorageOperation::StoreHashedStorages,
                OperationContext::Write,
                duration / count as u32,
            );
        }

        result
    }

    async fn get_earliest_block_number(&self) -> OpProofsStorageResult<Option<(u64, B256)>> {
        self.metrics
            .record_operation_async(
                StorageOperation::GetEarliestBlockNumber,
                OperationContext::Metadata,
                self.storage.get_earliest_block_number(),
            )
            .await
    }

    async fn get_latest_block_number(&self) -> OpProofsStorageResult<Option<(u64, B256)>> {
        self.metrics
            .record_operation_async(
                StorageOperation::GetLatestBlockNumber,
                OperationContext::Metadata,
                self.storage.get_latest_block_number(),
            )
            .await
    }

    fn storage_trie_cursor(
        &self,
        hashed_address: B256,
        max_block_number: u64,
    ) -> OpProofsStorageResult<Self::StorageTrieCursor> {
        let cursor = self.metrics.record_operation(
            StorageOperation::StorageTrieCursor,
            OperationContext::None,
            || self.storage.storage_trie_cursor(hashed_address, max_block_number),
        )?;
        Ok(TrieCursorWithMetrics::new(cursor, self.metrics.clone(), OperationContext::None))
    }

    fn account_trie_cursor(
        &self,
        max_block_number: u64,
    ) -> OpProofsStorageResult<Self::AccountTrieCursor> {
        let cursor = self.metrics.record_operation(
            StorageOperation::AccountTrieCursor,
            OperationContext::None,
            || self.storage.account_trie_cursor(max_block_number),
        )?;
        Ok(TrieCursorWithMetrics::new(cursor, self.metrics.clone(), OperationContext::None))
    }

    fn storage_hashed_cursor(
        &self,
        hashed_address: B256,
        max_block_number: u64,
    ) -> OpProofsStorageResult<Self::StorageCursor> {
        let cursor = self.metrics.record_operation(
            StorageOperation::StorageHashedCursor,
            OperationContext::None,
            || self.storage.storage_hashed_cursor(hashed_address, max_block_number),
        )?;
        Ok(HashedCursorWithMetrics::new(cursor, self.metrics.clone(), OperationContext::None))
    }

    fn account_hashed_cursor(
        &self,
        max_block_number: u64,
    ) -> OpProofsStorageResult<Self::AccountHashedCursor> {
        let cursor = self.metrics.record_operation(
            StorageOperation::AccountHashedCursor,
            OperationContext::None,
            || self.storage.account_hashed_cursor(max_block_number),
        )?;
        Ok(HashedCursorWithMetrics::new(cursor, self.metrics.clone(), OperationContext::None))
    }

    async fn store_trie_updates(
        &self,
        block_number: u64,
        block_state_diff: BlockStateDiff,
    ) -> OpProofsStorageResult<(u64, u64, u64, u64)> {
        self.metrics
            .record_operation_async(
                StorageOperation::StoreTrieUpdates,
                OperationContext::Write,
                self.storage.store_trie_updates(block_number, block_state_diff),
            )
            .await
    }

    async fn fetch_trie_updates(&self, block_number: u64) -> OpProofsStorageResult<BlockStateDiff> {
        self.metrics
            .record_operation_async(
                StorageOperation::FetchTrieUpdates,
                OperationContext::Metadata,
                self.storage.fetch_trie_updates(block_number),
            )
            .await
    }

    async fn prune_earliest_state(
        &self,
        new_earliest_block_number: u64,
        diff: BlockStateDiff,
    ) -> OpProofsStorageResult<()> {
        self.metrics
            .record_operation_async(
                StorageOperation::PruneEarliestState,
                OperationContext::Write,
                self.storage.prune_earliest_state(new_earliest_block_number, diff),
            )
            .await
    }

    async fn replace_updates(
        &self,
        latest_common_block_number: u64,
        blocks_to_add: HashMap<u64, BlockStateDiff>,
    ) -> OpProofsStorageResult<()> {
        self.metrics
            .record_operation_async(
                StorageOperation::ReplaceUpdates,
                OperationContext::Write,
                self.storage.replace_updates(latest_common_block_number, blocks_to_add),
            )
            .await
    }

    async fn set_earliest_block_number(
        &self,
        block_number: u64,
        hash: B256,
    ) -> OpProofsStorageResult<()> {
        self.metrics
            .record_operation_async(
                StorageOperation::SetEarliestBlockNumber,
                OperationContext::Metadata,
                self.storage.set_earliest_block_number(block_number, hash),
            )
            .await
    }

    // no metrics for these
    async fn get_last_stored_account_branch(&self) -> OpProofsStorageResult<Option<Nibbles>> {
        self.storage.get_last_stored_account_branch().await
    }

    async fn get_last_stored_storage_branch(
        &self,
    ) -> OpProofsStorageResult<Option<(B256, Nibbles)>> {
        self.storage.get_last_stored_storage_branch().await
    }

    async fn get_last_stored_hashed_account(&self) -> OpProofsStorageResult<Option<B256>> {
        self.storage.get_last_stored_hashed_account().await
    }

    async fn get_last_stored_hashed_storage(&self) -> OpProofsStorageResult<Option<(B256, B256)>> {
        self.storage.get_last_stored_hashed_storage().await
    }
}
