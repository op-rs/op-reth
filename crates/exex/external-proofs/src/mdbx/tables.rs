//! Table definitions for MDBX external storage
//!
//! This module defines all database tables used to store external proofs data.
//! Each table is completely independent from Reth's main database tables.

use super::{
    codec::BlockNumberHash,
    models::{
        HashedAccountEntry, HashedStorageEntry, HashedStorageSubKey, MetadataKey,
        StorageBranchEntry, StorageBranchSubKey, StoredNibblesWithBranch,
    },
};
use crate::models::IntegerList;
use alloy_primitives::B256;
use reth_db_api::table::{DupSort, Table};
use reth_trie_common::StoredNibbles;

// ============================================================================
// Changeset Tables (DupSort, sorted by block_number for fast appends)
// ============================================================================

/// Account trie branches changeset (DupSort by block_number)
///
/// Key: block_number (u64)
/// SubKey: path (StoredNibbles) - for DupSort ordering within block
/// Value: (StoredNibbles, MaybeDeleted<BranchNodeCompact>) - path + branch data
///
/// This structure allows fast appends since all inserts are sorted by block_number.
#[derive(Debug, Clone)]
pub struct ExternalAccountBranchesChangeset;

impl Table for ExternalAccountBranchesChangeset {
    const NAME: &'static str = "ExternalAccountBranchesChangeset";
    const DUPSORT: bool = true;

    type Key = u64; // block_number
    type Value = StoredNibblesWithBranch;
}

impl DupSort for ExternalAccountBranchesChangeset {
    type SubKey = StoredNibbles; // path
}

/// Storage trie branches changeset (DupSort by block_number)
///
/// Key: block_number (u64)
/// SubKey: (hashed_address, path) - for DupSort ordering within block
/// Value: (StorageBranchSubKey, MaybeDeleted<BranchNodeCompact>) - (address, path) + branch
///
/// This structure allows fast appends since all inserts are sorted by block_number.
#[derive(Debug, Clone)]
pub struct ExternalStorageBranchesChangeset;

impl Table for ExternalStorageBranchesChangeset {
    const NAME: &'static str = "ExternalStorageBranchesChangeset";
    const DUPSORT: bool = true;

    type Key = u64; // block_number
    type Value = StorageBranchEntry;
}

impl DupSort for ExternalStorageBranchesChangeset {
    type SubKey = StorageBranchSubKey; // (hashed_address, path)
}

/// Hashed accounts changeset (DupSort by block_number)
///
/// Key: block_number (u64)
/// SubKey: hashed_address (B256) - for DupSort ordering within block
/// Value: (B256, MaybeDeleted<Account>) - address + account data
///
/// This structure allows fast appends since all inserts are sorted by block_number.
#[derive(Debug, Clone)]
pub struct ExternalHashedAccountsChangeset;

impl Table for ExternalHashedAccountsChangeset {
    const NAME: &'static str = "ExternalHashedAccountsChangeset";
    const DUPSORT: bool = true;

    type Key = u64; // block_number
    type Value = HashedAccountEntry;
}

impl DupSort for ExternalHashedAccountsChangeset {
    type SubKey = B256; // hashed_address
}

/// Hashed storage values changeset (DupSort by block_number)
///
/// Key: block_number (u64)
/// SubKey: (hashed_address, hashed_storage_key) - for DupSort ordering within block
/// Value: (HashedStorageSubKey, MaybeDeleted<B256>) - (address, storage_key) + storage_value
///
/// This structure allows fast appends since all inserts are sorted by block_number.
/// Zero values are represented as MaybeDeleted::None (deleted).
#[derive(Debug, Clone)]
pub struct ExternalHashedStoragesChangeset;

impl Table for ExternalHashedStoragesChangeset {
    const NAME: &'static str = "ExternalHashedStoragesChangeset";
    const DUPSORT: bool = true;

    type Key = u64; // block_number
    type Value = HashedStorageEntry;
}

impl DupSort for ExternalHashedStoragesChangeset {
    type SubKey = HashedStorageSubKey; // (hashed_address, hashed_storage_key)
}

// ============================================================================
// History Tables (track which blocks modified each key)
// ============================================================================

/// Account trie branches history: path → list of block numbers
///
/// Tracks which block numbers modified each account trie path.
/// Allows efficient lookups to find the latest value for a path at a given block.
///
/// Key: path (StoredNibbles)
/// Value: IntegerList (compressed list of block numbers)
#[derive(Debug, Clone)]
pub struct ExternalAccountBranchesHistory;

impl Table for ExternalAccountBranchesHistory {
    const NAME: &'static str = "ExternalAccountBranchesHistory";
    const DUPSORT: bool = false;

    type Key = StoredNibbles;
    type Value = IntegerList;
}

/// Storage trie branches history: (address, path) → list of block numbers
///
/// Tracks which block numbers modified each storage trie branch.
///
/// Key: (hashed_address, path) - StorageBranchSubKey
/// Value: IntegerList
#[derive(Debug, Clone)]
pub struct ExternalStorageBranchesHistory;

impl Table for ExternalStorageBranchesHistory {
    const NAME: &'static str = "ExternalStorageBranchesHistory";
    const DUPSORT: bool = false;

    type Key = StorageBranchSubKey;
    type Value = IntegerList;
}

/// Hashed accounts history: address → list of block numbers
///
/// Tracks which block numbers modified each account.
///
/// Key: hashed_address (B256)
/// Value: IntegerList
#[derive(Debug, Clone)]
pub struct ExternalHashedAccountsHistory;

impl Table for ExternalHashedAccountsHistory {
    const NAME: &'static str = "ExternalHashedAccountsHistory";
    const DUPSORT: bool = false;

    type Key = B256;
    type Value = IntegerList;
}

/// Hashed storage history: (address, storage_key) → list of block numbers
///
/// Tracks which block numbers modified each storage slot.
///
/// Key: (hashed_address, hashed_storage_key) - HashedStorageSubKey
/// Value: IntegerList
#[derive(Debug, Clone)]
pub struct ExternalHashedStoragesHistory;

impl Table for ExternalHashedStoragesHistory {
    const NAME: &'static str = "ExternalHashedStoragesHistory";
    const DUPSORT: bool = false;

    type Key = HashedStorageSubKey;
    type Value = IntegerList;
}

// ============================================================================
// Metadata Table
// ============================================================================

/// Metadata (earliest/latest block tracking)
///
/// Key: MetadataKey (EarliestBlock or LatestBlock)
/// Value: BlockNumberHash (block_number + block_hash)
#[derive(Debug, Clone)]
pub struct ExternalBlockMetadata;

impl Table for ExternalBlockMetadata {
    const NAME: &'static str = "ExternalBlockMetadata";
    const DUPSORT: bool = false;

    type Key = MetadataKey;
    type Value = BlockNumberHash;
}

// ============================================================================
// Table Set for Database Initialization
// ============================================================================

/// All external storage tables as an enum
///
/// This is used to initialize the database with all required tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tables {
    /// Account trie branches changeset
    ExternalAccountBranchesChangeset,
    /// Storage trie branches changeset
    ExternalStorageBranchesChangeset,
    /// Hashed accounts changeset
    ExternalHashedAccountsChangeset,
    /// Hashed storage values changeset
    ExternalHashedStoragesChangeset,
    /// Account branches history
    ExternalAccountBranchesHistory,
    /// Storage branches history
    ExternalStorageBranchesHistory,
    /// Hashed accounts history
    ExternalHashedAccountsHistory,
    /// Hashed storages history
    ExternalHashedStoragesHistory,
    /// Block metadata
    ExternalBlockMetadata,
}

impl Tables {
    /// All external tables
    pub const ALL: &'static [Self] = &[
        Self::ExternalAccountBranchesChangeset,
        Self::ExternalStorageBranchesChangeset,
        Self::ExternalHashedAccountsChangeset,
        Self::ExternalHashedStoragesChangeset,
        Self::ExternalAccountBranchesHistory,
        Self::ExternalStorageBranchesHistory,
        Self::ExternalHashedAccountsHistory,
        Self::ExternalHashedStoragesHistory,
        Self::ExternalBlockMetadata,
    ];

    /// Get the table name
    pub const fn name(&self) -> &'static str {
        match self {
            Self::ExternalAccountBranchesChangeset => ExternalAccountBranchesChangeset::NAME,
            Self::ExternalStorageBranchesChangeset => ExternalStorageBranchesChangeset::NAME,
            Self::ExternalHashedAccountsChangeset => ExternalHashedAccountsChangeset::NAME,
            Self::ExternalHashedStoragesChangeset => ExternalHashedStoragesChangeset::NAME,
            Self::ExternalAccountBranchesHistory => ExternalAccountBranchesHistory::NAME,
            Self::ExternalStorageBranchesHistory => ExternalStorageBranchesHistory::NAME,
            Self::ExternalHashedAccountsHistory => ExternalHashedAccountsHistory::NAME,
            Self::ExternalHashedStoragesHistory => ExternalHashedStoragesHistory::NAME,
            Self::ExternalBlockMetadata => ExternalBlockMetadata::NAME,
        }
    }

    /// Check if the table is a DUPSORT table
    pub const fn is_dupsort(&self) -> bool {
        match self {
            Self::ExternalAccountBranchesChangeset |
            Self::ExternalStorageBranchesChangeset |
            Self::ExternalHashedAccountsChangeset |
            Self::ExternalHashedStoragesChangeset => true,
            _ => false,
        }
    }
}

impl reth_db_api::table::TableInfo for Tables {
    fn name(&self) -> &'static str {
        self.name()
    }

    fn is_dupsort(&self) -> bool {
        self.is_dupsort()
    }
}

impl reth_db_api::TableSet for Tables {
    fn tables() -> Box<dyn Iterator<Item = Box<dyn reth_db_api::table::TableInfo>>> {
        Box::new(
            Self::ALL
                .iter()
                .map(|table| Box::new(*table) as Box<dyn reth_db_api::table::TableInfo>),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_names_unique() {
        use std::collections::HashSet;
        let names: HashSet<_> = Tables::ALL.iter().collect();
        assert_eq!(names.len(), Tables::ALL.len(), "Table names must be unique");
    }
}
