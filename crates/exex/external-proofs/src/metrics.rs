//! Metrics for external proofs storage operations.

use metrics::{describe_histogram, Counter, Histogram};
use reth_metrics::Metrics;
use rustc_hash::FxHashMap;
use std::time::{Duration, Instant};
use strum::{EnumCount, EnumIter, IntoEnumIterator};

/// Describe external proofs metrics for Prometheus
pub fn describe_external_proofs_metrics() {
    describe_histogram!(
        "external_proofs.storage.operation.duration_seconds",
        metrics::Unit::Seconds,
        "Duration of storage operations"
    );
    describe_histogram!(
        "external_proofs.block.total_duration_seconds",
        metrics::Unit::Seconds,
        "Total time to process a block"
    );
    describe_histogram!(
        "external_proofs.block.execution_duration_seconds",
        metrics::Unit::Seconds,
        "Time spent executing block in EVM"
    );
    describe_histogram!(
        "external_proofs.block.state_root_duration_seconds",
        metrics::Unit::Seconds,
        "Time spent calculating state root"
    );
    describe_histogram!(
        "external_proofs.block.write_duration_seconds",
        metrics::Unit::Seconds,
        "Time spent writing trie updates"
    );
}

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
    /// Storage operations without specific context
    None,
}

impl OperationContext {
    /// Returns the context as a string for metrics labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::StateRoot => "state_root",
            Self::Write => "write",
            Self::Metadata => "metadata",
            Self::None => "none",
        }
    }
}

/// Types of storage operations that can be tracked.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, EnumCount, EnumIter)]
pub enum StorageOperation {
    /// Store account trie branches
    StoreAccountBranches,
    /// Store storage trie branches
    StoreStorageBranches,
    /// Store hashed accounts
    StoreHashedAccounts,
    /// Store hashed storages
    StoreHashedStorages,
    /// Get earliest block number
    GetEarliestBlockNumber,
    /// Get latest block number
    GetLatestBlockNumber,
    /// Get storage trie cursor
    StorageTrieCursor,
    /// Get account trie cursor
    AccountTrieCursor,
    /// Get storage hashed cursor
    StorageHashedCursor,
    /// Get account hashed cursor
    AccountHashedCursor,
    /// Store trie updates
    StoreTrieUpdates,
    /// Fetch trie updates
    FetchTrieUpdates,
    /// Prune earliest state
    PruneEarliestState,
    /// Replace updates
    ReplaceUpdates,
    /// Set earliest block number
    SetEarliestBlockNumber,
    /// Trie cursor seek exact operation
    TrieCursorSeekExact,
    /// Trie cursor seek operation
    TrieCursorSeek,
    /// Trie cursor next operation
    TrieCursorNext,
    /// Trie cursor current operation
    TrieCursorCurrent,
    /// Hashed cursor seek operation
    HashedCursorSeek,
    /// Hashed cursor next operation
    HashedCursorNext,
    /// Hashed cursor is_storage_empty operation
    HashedCursorIsStorageEmpty,
}

impl StorageOperation {
    /// Returns the operation as a string for metrics labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::StoreAccountBranches => "store_account_branches",
            Self::StoreStorageBranches => "store_storage_branches",
            Self::StoreHashedAccounts => "store_hashed_accounts",
            Self::StoreHashedStorages => "store_hashed_storages",
            Self::GetEarliestBlockNumber => "get_earliest_block_number",
            Self::GetLatestBlockNumber => "get_latest_block_number",
            Self::StorageTrieCursor => "storage_trie_cursor",
            Self::AccountTrieCursor => "account_trie_cursor",
            Self::StorageHashedCursor => "storage_hashed_cursor",
            Self::AccountHashedCursor => "account_hashed_cursor",
            Self::StoreTrieUpdates => "store_trie_updates",
            Self::FetchTrieUpdates => "fetch_trie_updates",
            Self::PruneEarliestState => "prune_earliest_state",
            Self::ReplaceUpdates => "replace_updates",
            Self::SetEarliestBlockNumber => "set_earliest_block_number",
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
    operations: FxHashMap<(StorageOperation, OperationContext), OperationMetrics>,
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
    fn generate_operation_handles(
    ) -> FxHashMap<(StorageOperation, OperationContext), OperationMetrics> {
        let mut operations = FxHashMap::with_capacity_and_hasher(
            StorageOperation::COUNT * OperationContext::COUNT,
            Default::default(),
        );
        for operation in StorageOperation::iter() {
            for context in OperationContext::iter() {
                operations.insert(
                    (operation, context),
                    OperationMetrics::new_with_labels(&[
                        (Labels::Operation.as_str(), operation.as_str()),
                        (Labels::Context.as_str(), context.as_str()),
                    ]),
                );
            }
        }
        operations
    }

    /// Record a storage operation with timing.
    pub fn record_operation<R>(
        &self,
        operation: StorageOperation,
        context: OperationContext,
        f: impl FnOnce() -> R,
    ) -> R {
        if let Some(metrics) = self.operations.get(&(operation, context)) {
            metrics.record(f)
        } else {
            f()
        }
    }

    /// Record a storage operation with timing (async version).
    pub async fn record_operation_async<F, R>(
        &self,
        operation: StorageOperation,
        context: OperationContext,
        f: F,
    ) -> R
    where
        F: std::future::Future<Output = R>,
    {
        let start = Instant::now();
        let result = f.await;
        let duration = start.elapsed();

        if let Some(metrics) = self.operations.get(&(operation, context)) {
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
        if let Some(metrics) = self.operations.get(&(operation, context)) {
            metrics.record_duration(duration);
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
