//! Metrics for external proofs storage operations.

use alloy_primitives::map::HashMap;
use metrics::{Counter, Histogram};
use reth_metrics::Metrics;
use std::time::{Duration, Instant};
use strum::{EnumCount, EnumIter, IntoEnumIterator};

/// Context in which a storage operation is performed.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, EnumCount, EnumIter)]
pub enum OperationContext {
    /// Storage operations during block execution (EVM state access)
    Execution,
    /// Storage operations during state root calculation (trie traversal)
    StateRoot,
    /// Storage operations during writing updates (storing trie updates)
    Write,
    /// Storage operations for metadata (block number queries, etc.)
    Metadata,
}

impl OperationContext {
    /// Returns the context as a string for metrics labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::StateRoot => "state_root",
            Self::Write => "write",
            Self::Metadata => "metadata",
        }
    }
}

/// Types of storage operations that can be tracked.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, EnumCount, EnumIter)]
pub enum StorageOperation {
    /// Store account trie branch
    StoreAccountBranch,
    /// Store storage trie branch
    StoreStorageBranch,
    /// Store hashed account
    StoreHashedAccount,
    /// Store hashed storage
    StoreHashedStorage,
    /// Trie cursor seek exact operation
    TrieCursorSeekExact,
    /// Trie cursor seek
    TrieCursorSeek,
    /// Trie cursor next
    TrieCursorNext,
    /// Trie cursor current
    TrieCursorCurrent,
    /// Hashed cursor seek
    HashedCursorSeek,
    /// Hashed cursor next
    HashedCursorNext,
    /// Hashed cursor is_storage_empty
    HashedCursorIsStorageEmpty,
}

impl StorageOperation {
    /// Returns the operation as a string for metrics labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::StoreAccountBranch => "store_account_branch",
            Self::StoreStorageBranch => "store_storage_branch",
            Self::StoreHashedAccount => "store_hashed_account",
            Self::StoreHashedStorage => "store_hashed_storage",
            Self::TrieCursorSeekExact => "trie_cursor_seek_exact",
            Self::TrieCursorSeek => "trie_cursor_seek",
            Self::TrieCursorNext => "trie_cursor_next",
            Self::TrieCursorCurrent => "trie_cursor_current",
            Self::HashedCursorSeek => "hashed_cursor_seek",
            Self::HashedCursorNext => "hashed_cursor_next",
            Self::HashedCursorIsStorageEmpty => "hashed_cursor_is_storage_empty",
        }
    }
}

/// Labels used in metrics.
enum Labels {
    /// Operation type label
    Operation,
    /// Context label
    Context,
}

impl Labels {
    /// Returns the label key as a string.
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::Context => "context",
        }
    }
}

/// Metrics for storage operations.
#[derive(Debug)]
pub struct StorageMetrics {
    /// Cache of operation metrics handles, keyed by (operation, context)
    operations: HashMap<StorageOperation, OperationMetrics>,
    /// Block-level metrics
    block_metrics: BlockMetrics,
}

impl StorageMetrics {
    /// Create a new metrics instance with pre-allocated handles.
    pub fn new() -> Self {
        Self {
            operations: Self::generate_operation_handles(),
            block_metrics: BlockMetrics::new_with_labels(&[] as &[(&str, &str)]),
        }
    }

    /// Generate metric handles for all operation and context combinations.
    fn generate_operation_handles() -> HashMap<StorageOperation, OperationMetrics> {
        let mut operations =
            HashMap::with_capacity_and_hasher(StorageOperation::COUNT, Default::default());
        for operation in StorageOperation::iter() {
            operations.insert(
                operation,
                OperationMetrics::new_with_labels(&[(
                    Labels::Operation.as_str(),
                    operation.as_str(),
                )]),
            );
        }
        operations
    }

    /// Record a storage operation with timing.
    pub fn record_operation<R>(&self, operation: StorageOperation, f: impl FnOnce() -> R) -> R {
        if let Some(metrics) = self.operations.get(&operation) {
            metrics.record(f)
        } else {
            f()
        }
    }

    /// Record a storage operation with timing (async version).
    pub async fn record_operation_async<F, R>(&self, operation: StorageOperation, f: F) -> R
    where
        F: std::future::Future<Output = R>,
    {
        let start = Instant::now();
        let result = f.await;
        let duration = start.elapsed();

        if let Some(metrics) = self.operations.get(&operation) {
            metrics.record_duration(duration);
        }

        result
    }

    /// Get block metrics for recording high-level timing.
    pub const fn block_metrics(&self) -> &BlockMetrics {
        &self.block_metrics
    }

    /// Record a pre-measured duration for an operation.
    pub fn record_duration(
        &self,
        operation: StorageOperation,
        context: OperationContext,
        duration: Duration,
    ) {
        if let Some(metrics) = self.operations.get(&operation) {
            metrics.record_duration(duration);
        }
    }

    pub fn record_duration_per_item(
        &self,
        operation: StorageOperation,
        context: OperationContext,
        duration: Duration,
        count: usize,
    ) {
        if let Some(metrics) = self.operations.get(&operation) {
            metrics.record_duration_per_item(duration, count);
        }
    }
}

impl Default for StorageMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics for individual storage operations.
#[derive(Metrics, Clone)]
#[metrics(scope = "external_proofs.storage.operation")]
struct OperationMetrics {
    /// Duration of storage operations in seconds
    duration_seconds: Histogram,
}

impl OperationMetrics {
    /// Record an operation with timing.
    fn record<R>(&self, f: impl FnOnce() -> R) -> R {
        let start = Instant::now();
        let result = f();
        self.duration_seconds.record(start.elapsed());
        result
    }

    /// Record a pre-measured duration.
    fn record_duration(&self, duration: Duration) {
        self.duration_seconds.record(duration);
    }

    fn record_duration_per_item(&self, duration: Duration, count_usize: usize) {
        if count_usize > 0
            && let Some(count) = u32::try_from(count_usize).ok()
        {
            self.duration_seconds.record_many(duration / count, count as usize);
        }
    }
}

/// High-level block processing metrics.
#[derive(Metrics, Clone)]
#[metrics(scope = "external_proofs.block")]
pub struct BlockMetrics {
    /// Total time to process a block (end-to-end) in seconds
    pub total_duration_seconds: Histogram,
    /// Time spent executing the block (EVM) in seconds
    pub execution_duration_seconds: Histogram,
    /// Time spent calculating state root in seconds
    pub state_root_duration_seconds: Histogram,
    /// Time spent writing trie updates to storage in seconds
    pub write_duration_seconds: Histogram,
    /// Number of trie updates written
    pub account_trie_updates_written_total: Counter,
    /// Number of storage trie updates written
    pub storage_trie_updates_written_total: Counter,
    /// Number of hashed accounts written
    pub hashed_accounts_written_total: Counter,
    /// Number of hashed storages written
    pub hashed_storages_written_total: Counter,
}
