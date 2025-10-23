//! MDBX cursor implementations for external storage
//!
//! This module provides efficient cursors that work with the changeset + history table pattern.
//! Cursors use history indices to find the latest value for keys at a specific block number
//! without collecting all data into memory.

use alloy_primitives::{B256, U256};
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO},
    models::IntegerList,
    table::{DupSort, Table},
    transaction::DbTx,
};
use reth_primitives_traits::Account;
use reth_trie::{BranchNodeCompact, Nibbles, StoredNibbles};
use tracing::info;

use super::{models::*, tables};
use crate::storage::{OpProofsHashedCursor, OpProofsStorageResult, OpProofsTrieCursor};

// ============================================================================
// Account Trie Cursor
// ============================================================================

/// Account trie cursor that works with history + changeset tables
///
/// Uses the ExternalAccountBranchesHistory table to efficiently find which block
/// last modified a path, then looks up the value in ExternalAccountBranchesChangeset.
#[derive(Debug)]
pub struct AccountTrieCursor<TX> {
    tx: TX,
    max_block_number: u64,
    current_path: Option<Nibbles>,
}

impl<TX: DbTx> AccountTrieCursor<TX> {
    /// Create a new account trie cursor with the given max block number
    pub fn new(tx: TX, max_block_number: u64) -> Self {
        Self { tx, max_block_number, current_path: None }
    }

    /// Find the latest value for a specific path by using history index
    fn find_path_value(
        &self,
        target_path: &Nibbles,
    ) -> OpProofsStorageResult<Option<BranchNodeCompact>> {
        let mut history_cursor = self.tx.cursor_read::<tables::ExternalAccountBranchesHistory>()?;

        let stored_path = StoredNibbles(target_path.clone());

        // Look up the history index for this path
        let Some((_key, list)) = history_cursor.seek_exact(stored_path.clone())? else {
            // Path never modified
            return Ok(None);
        };

        // Find the last block <= max_block_number where this path was modified
        let block_number = find_last_block_in_list(&list, self.max_block_number)?;

        let Some(block_number) = block_number else {
            // No modifications at or before max_block_number
            return Ok(None);
        };

        // Look up the value in the changeset table at that block
        let mut changeset_cursor =
            self.tx.cursor_dup_read::<tables::ExternalAccountBranchesChangeset>()?;

        let Some(StoredNibblesWithBranch(_, value)) =
            changeset_cursor.seek_by_key_subkey(block_number, stored_path)?
        else {
            return Ok(None);
        };

        Ok(value.0.clone())
    }

    /// Find the first path >= target_path with a non-deleted value
    fn find_next_path(
        &self,
        target_path: &Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        let mut history_cursor = self.tx.cursor_read::<tables::ExternalAccountBranchesHistory>()?;

        let stored_target = StoredNibbles(target_path.clone());

        // Seek to the first path >= target_path in the history table
        let Some((key, _list)) = history_cursor.seek(stored_target)? else {
            return Ok(None);
        };

        let mut current_key = key;

        // Iterate through paths until we find one with a non-deleted value
        loop {
            let path = current_key.0.clone();

            // Try to get the value for this path
            if let Some(branch) = self.find_path_value(&path)? {
                return Ok(Some((path, branch)));
            }

            // Move to next path
            let Some((next_key, _list)) = history_cursor.next()? else {
                return Ok(None);
            };

            current_key = next_key;
        }
    }
}

impl<TX: DbTx> OpProofsTrieCursor for AccountTrieCursor<TX> {
    fn seek_exact(
        &mut self,
        target_path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        let result =
            self.find_path_value(&target_path)?.map(|branch| (target_path.clone(), branch));
        if result.is_some() {
            self.current_path = Some(target_path);
        }
        Ok(result)
    }

    fn seek(
        &mut self,
        target_path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        let result = self.find_next_path(&target_path)?;
        if let Some((ref path, _)) = result {
            self.current_path = Some(path.clone());
        }
        Ok(result)
    }

    fn next(&mut self) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        let next_path = if let Some(current) = &self.current_path {
            // Find next path after current
            let mut next = current.clone();
            next.push(0);
            next
        } else {
            Nibbles::default()
        };

        self.seek(next_path)
    }

    fn current(&mut self) -> OpProofsStorageResult<Option<Nibbles>> {
        Ok(self.current_path.clone())
    }
}

// ============================================================================
// Storage Trie Cursor
// ============================================================================

/// Storage trie cursor that works with history + changeset tables
#[derive(Debug)]
pub struct MdbxOpProofsStorageTrieCursor<T: Table + DupSort, TX> {
    hashed_address: B256,
    tx: TX,
    max_block_number: u64,
    current_path: Option<Nibbles>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Table<Key = u64> + DupSort, TX: DbTx> MdbxOpProofsStorageTrieCursor<T, TX> {
    pub(crate) fn new(tx: TX, hashed_address: B256, max_block_number: u64) -> Self {
        Self {
            hashed_address,
            tx,
            max_block_number,
            current_path: None,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<TX: DbTx> MdbxOpProofsStorageTrieCursor<tables::ExternalStorageBranchesChangeset, TX> {
    /// Find the latest value for a specific path using history index
    fn find_path_value(
        &self,
        target_path: &Nibbles,
    ) -> OpProofsStorageResult<Option<BranchNodeCompact>> {
        let mut history_cursor = self.tx.cursor_read::<tables::ExternalStorageBranchesHistory>()?;

        let history_key =
            StorageBranchSubKey::new(self.hashed_address, StoredNibbles(target_path.clone()));

        // Look up the history index for this (address, path)
        let Some((_key, list)) = history_cursor.seek_exact(history_key.clone())? else {
            return Ok(None);
        };

        // Find the last block <= max_block_number
        let block_number = find_last_block_in_list(&list, self.max_block_number)?;

        let Some(block_number) = block_number else {
            return Ok(None);
        };

        // Look up the value in the changeset table
        let mut changeset_cursor =
            self.tx.cursor_dup_read::<tables::ExternalStorageBranchesChangeset>()?;

        let Some(StorageBranchEntry(_, value)) =
            changeset_cursor.seek_by_key_subkey(block_number, history_key)?
        else {
            return Ok(None);
        };

        Ok(value.0.clone())
    }

    /// Find the first path >= target_path for this address with a non-deleted value
    fn find_next_path(
        &self,
        target_path: &Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        let mut history_cursor = self.tx.cursor_read::<tables::ExternalStorageBranchesHistory>()?;

        let start_key =
            StorageBranchSubKey::new(self.hashed_address, StoredNibbles(target_path.clone()));

        // Seek to first entry >= (address, path)
        let Some((key, _list)) = history_cursor.seek(start_key)? else {
            return Ok(None);
        };

        let mut current_key = key;

        // Iterate through paths for this address
        loop {
            // Check if still the same address
            if current_key.hashed_address != self.hashed_address {
                return Ok(None);
            }

            let path = current_key.path.0.clone();

            // Try to get the value for this path
            if let Some(branch) = self.find_path_value(&path)? {
                return Ok(Some((path, branch)));
            }

            // Move to next path
            let Some((next_key, _list)) = history_cursor.next()? else {
                return Ok(None);
            };

            current_key = next_key;
        }
    }
}

impl<TX: DbTx> OpProofsTrieCursor
    for MdbxOpProofsStorageTrieCursor<tables::ExternalStorageBranchesChangeset, TX>
{
    fn seek_exact(
        &mut self,
        target_path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        let result =
            self.find_path_value(&target_path)?.map(|branch| (target_path.clone(), branch));
        if result.is_some() {
            self.current_path = Some(target_path);
        }
        Ok(result)
    }

    fn seek(
        &mut self,
        target_path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        let result = self.find_next_path(&target_path)?;
        if let Some((ref path, _)) = result {
            self.current_path = Some(path.clone());
        }
        Ok(result)
    }

    fn next(&mut self) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        let next_path = if let Some(current) = &self.current_path {
            let mut next = current.clone();
            next.push(0);
            next
        } else {
            Nibbles::default()
        };

        self.seek(next_path)
    }

    fn current(&mut self) -> OpProofsStorageResult<Option<Nibbles>> {
        Ok(self.current_path.clone())
    }
}

// ============================================================================
// Hashed Account Cursor
// ============================================================================

/// Account hashed cursor that works with history + changeset tables
#[derive(Debug)]
pub struct MdbxAccountCursor<TX> {
    tx: TX,
    max_block_number: u64,
    current_address: Option<B256>,
}

impl<TX: DbTx> MdbxAccountCursor<TX> {
    pub(crate) fn new(tx: TX, max_block_number: u64) -> Self {
        Self { tx, max_block_number, current_address: None }
    }

    /// Find the latest account value using history index
    fn find_account(&self, address: B256) -> OpProofsStorageResult<Option<Account>> {
        let mut history_cursor = self.tx.cursor_read::<tables::ExternalHashedAccountsHistory>()?;

        // Look up the history index for this address
        let Some((_key, list)) = history_cursor.seek_exact(address)? else {
            return Ok(None);
        };

        // Find the last block <= max_block_number
        let block_number = find_last_block_in_list(&list, self.max_block_number)?;

        let Some(block_number) = block_number else {
            return Ok(None);
        };

        // Look up the value in the changeset table
        let mut changeset_cursor =
            self.tx.cursor_dup_read::<tables::ExternalHashedAccountsChangeset>()?;

        let Some(HashedAccountEntry(_, value)) =
            changeset_cursor.seek_by_key_subkey(block_number, address)?
        else {
            return Ok(None);
        };

        Ok(value.0.clone())
    }

    /// Find the first address >= target with a non-deleted value
    fn find_next_address(&self, target: B256) -> OpProofsStorageResult<Option<(B256, Account)>> {
        let mut history_cursor = self.tx.cursor_read::<tables::ExternalHashedAccountsHistory>()?;

        info!("seeking to first address >= target");
        // Seek to first address >= target
        let Some((address, _list)) = history_cursor.seek(target)? else {
            return Ok(None);
        };
        info!("found address: {:?}", address);

        let mut current_address = address;

        // Iterate through addresses
        loop {
            // Try to get the account for this address
            info!("finding account for address: {:?}", current_address);
            if let Some(account) = self.find_account(current_address)? {
                info!("found account: {:?}", account);
                return Ok(Some((current_address, account)));
            }

            // Move to next address
            let Some((next_address, _list)) = history_cursor.next()? else {
                return Ok(None);
            };

            info!("moving to next address: {:?}", next_address);

            current_address = next_address;
        }
    }
}

impl<TX: DbTx> OpProofsHashedCursor for MdbxAccountCursor<TX> {
    type Value = Account;

    fn seek(&mut self, target_address: B256) -> OpProofsStorageResult<Option<(B256, Account)>> {
        let result = self.find_next_address(target_address)?;
        if let Some((addr, _)) = result {
            self.current_address = Some(addr);
        }
        Ok(result)
    }

    fn next(&mut self) -> OpProofsStorageResult<Option<(B256, Account)>> {
        let next_addr = if let Some(current) = self.current_address {
            // Increment address by 1
            increment_b256(current)
        } else {
            B256::ZERO
        };

        self.seek(next_addr)
    }
}

// ============================================================================
// Hashed Storage Cursor
// ============================================================================

/// Storage hashed cursor that works with history + changeset tables
#[derive(Debug)]
pub struct MdbxStorageCursor<TX> {
    tx: TX,
    max_block_number: u64,
    hashed_address: B256,
    current_storage_key: Option<B256>,
}

impl<TX: DbTx> MdbxStorageCursor<TX> {
    pub(crate) fn new(tx: TX, max_block_number: u64, hashed_address: B256) -> Self {
        Self { tx, max_block_number, hashed_address, current_storage_key: None }
    }

    /// Find the latest storage value using history index
    fn find_storage(&self, storage_key: B256) -> OpProofsStorageResult<Option<U256>> {
        let mut history_cursor = self.tx.cursor_read::<tables::ExternalHashedStoragesHistory>()?;

        let history_key = HashedStorageSubKey::new(self.hashed_address, storage_key);

        // Look up the history index
        let Some((_key, list)) = history_cursor.seek_exact(history_key.clone())? else {
            return Ok(None);
        };

        // Find the last block <= max_block_number
        let block_number = find_last_block_in_list(&list, self.max_block_number)?;

        let Some(block_number) = block_number else {
            return Ok(None);
        };

        // Look up the value in the changeset table
        let mut changeset_cursor =
            self.tx.cursor_dup_read::<tables::ExternalHashedStoragesChangeset>()?;

        let Some(HashedStorageEntry(_, value)) =
            changeset_cursor.seek_by_key_subkey(block_number, history_key)?
        else {
            return Ok(None);
        };

        Ok(value.0.map(|v| U256::from_be_slice(v.as_slice())))
    }

    /// Find the first storage key >= target for this address with a non-deleted value
    fn find_next_storage(&self, target: B256) -> OpProofsStorageResult<Option<(B256, U256)>> {
        let mut history_cursor = self.tx.cursor_read::<tables::ExternalHashedStoragesHistory>()?;

        let start_key = HashedStorageSubKey::new(self.hashed_address, target);

        // Seek to first entry >= (address, storage_key)
        let Some((key, _list)) = history_cursor.seek(start_key)? else {
            return Ok(None);
        };

        let mut current_key = key;

        // Iterate through storage keys for this address
        loop {
            // Check if still the same address
            if current_key.hashed_address != self.hashed_address {
                return Ok(None);
            }

            let storage_key = current_key.hashed_storage_key;

            // Try to get the value for this storage key
            if let Some(value) = self.find_storage(storage_key)? {
                return Ok(Some((storage_key, value)));
            }

            // Move to next storage key
            let Some((next_key, _list)) = history_cursor.next()? else {
                return Ok(None);
            };

            current_key = next_key;
        }
    }
}

impl<TX: DbTx> OpProofsHashedCursor for MdbxStorageCursor<TX> {
    type Value = U256;

    fn seek(&mut self, target_storage_key: B256) -> OpProofsStorageResult<Option<(B256, U256)>> {
        let result = self.find_next_storage(target_storage_key)?;
        if let Some((key, _)) = result {
            self.current_storage_key = Some(key);
        }
        Ok(result)
    }

    fn next(&mut self) -> OpProofsStorageResult<Option<(B256, U256)>> {
        let next_key = if let Some(current) = self.current_storage_key {
            increment_b256(current)
        } else {
            B256::ZERO
        };

        self.seek(next_key)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Find the last block number in an IntegerList that is <= max_block
///
/// Uses the rank/select API from RoaringTreemap to efficiently find the value
/// without iterating through all entries.
fn find_last_block_in_list(
    list: &IntegerList,
    max_block: u64,
) -> OpProofsStorageResult<Option<u64>> {
    let inner = &list.0;

    // If the list is empty, return None
    if inner.is_empty() {
        return Ok(None);
    }

    // Get the rank (number of elements <= max_block)
    let rank = inner.rank(max_block);

    // If rank is 0, no elements <= max_block
    if rank == 0 {
        return Ok(None);
    }

    // Select the element at rank-1 (0-indexed)
    Ok(inner.select(rank - 1))
}

/// Increment a B256 by 1 (for iterating to next key)
fn increment_b256(mut value: B256) -> B256 {
    for i in (0..32).rev() {
        if value.0[i] == 255 {
            value.0[i] = 0;
        } else {
            value.0[i] += 1;
            break;
        }
    }
    value
}
