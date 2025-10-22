//! MDBX cursor implementations for external storage
//!
//! This module provides efficient cursors that work with the changeset + history table pattern.
//! Cursors scan through changesets by block_number and track the latest values for each key.

use alloy_primitives::{B256, U256};
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO},
    table::{DupSort, Table},
};
use reth_primitives_traits::Account;
use reth_trie::{BranchNodeCompact, Nibbles};
use std::collections::BTreeMap;

use super::tables;
use crate::storage::{
    OpProofsHashedCursor, OpProofsStorageError, OpProofsStorageResult, OpProofsTrieCursor,
};

/// Account trie cursor that works with changeset table
#[derive(Debug)]
pub struct AccountTrieCursor<Cursor> {
    cursor: Cursor,
    max_block_number: u64,
    cached_paths: Option<BTreeMap<Nibbles, BranchNodeCompact>>,
    current_path: Option<Nibbles>,
}

impl<
        Cursor: DbCursorRO<tables::ExternalAccountBranchesChangeset>
            + DbDupCursorRO<tables::ExternalAccountBranchesChangeset>
            + Send
            + Sync,
    > AccountTrieCursor<Cursor>
{
    /// Create a new account trie cursor with the given max block number
    pub fn new(cursor: Cursor, max_block_number: u64) -> Self {
        Self { cursor, max_block_number, cached_paths: None, current_path: None }
    }

    /// Collect all paths with their latest values
    fn collect_all_paths(&mut self) -> OpProofsStorageResult<BTreeMap<Nibbles, BranchNodeCompact>> {
        let mut path_values: BTreeMap<Nibbles, (u64, Option<BranchNodeCompact>)> = BTreeMap::new();

        // Scan through all blocks <= max_block_number
        if let Some((_block, _)) =
            self.cursor.first().map_err(|e| OpProofsStorageError::Other(e.into()))?
        {
            loop {
                let Some((block, value)) =
                    self.cursor.current().map_err(|e| OpProofsStorageError::Other(e.into()))?
                else {
                    break;
                };

                if block > self.max_block_number {
                    break;
                }

                let path = value.0 .0.clone();
                let branch_opt = value.1 .0.clone();

                // Keep the latest (highest block number) value for each path
                path_values
                    .entry(path)
                    .and_modify(|(latest_block, latest_branch)| {
                        if block > *latest_block {
                            *latest_block = block;
                            *latest_branch = branch_opt.clone();
                        }
                    })
                    .or_insert((block, branch_opt));

                if self.cursor.next().map_err(|e| OpProofsStorageError::Other(e.into()))?.is_none()
                {
                    break;
                }
            }
        }

        // Filter out deleted entries (None) and return only the branches
        Ok(path_values
            .into_iter()
            .filter_map(|(path, (_block, branch_opt))| branch_opt.map(|branch| (path, branch)))
            .collect())
    }

    /// Get or initialize cached paths
    fn get_cached_paths(&mut self) -> OpProofsStorageResult<&BTreeMap<Nibbles, BranchNodeCompact>> {
        if self.cached_paths.is_none() {
            self.cached_paths = Some(self.collect_all_paths()?);
        }
        Ok(self.cached_paths.as_ref().unwrap())
    }
}

impl<
        Cursor: DbCursorRO<tables::ExternalAccountBranchesChangeset>
            + DbDupCursorRO<tables::ExternalAccountBranchesChangeset>
            + Send
            + Sync,
    > OpProofsTrieCursor for AccountTrieCursor<Cursor>
{
    fn seek_exact(
        &mut self,
        target_path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        let paths = self.get_cached_paths()?;
        let result = paths.get(&target_path).map(|branch| (target_path.clone(), branch.clone()));
        if result.is_some() {
            self.current_path = Some(target_path);
        }
        Ok(result)
    }

    fn seek(
        &mut self,
        target_path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        let paths = self.get_cached_paths()?;
        // Find first path >= target_path
        let result = paths
            .range(target_path..)
            .next()
            .map(|(path, branch)| (path.clone(), branch.clone()));
        if let Some((ref path, _)) = result {
            self.current_path = Some(path.clone());
        }
        Ok(result)
    }

    fn next(&mut self) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        let next_path = if let Some(current) = &self.current_path {
            // Find next path after current
            let mut next = current.clone();
            // Simple increment: append a nibble or increase last nibble
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

/// Storage trie cursor that works with changeset table
#[derive(Debug)]
pub struct MdbxOpProofsStorageTrieCursor<T: Table + DupSort, Cursor> {
    hashed_address: B256,
    cursor: Cursor,
    max_block_number: u64,
    cached_paths: Option<BTreeMap<Nibbles, BranchNodeCompact>>,
    current_path: Option<Nibbles>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Table<Key = u64> + DupSort, Cursor: DbCursorRO<T> + DbDupCursorRO<T>>
    MdbxOpProofsStorageTrieCursor<T, Cursor>
{
    pub(crate) fn new(cursor: Cursor, hashed_address: B256, max_block_number: u64) -> Self {
        Self {
            hashed_address,
            cursor,
            max_block_number,
            cached_paths: None,
            current_path: None,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<
        Cursor: DbCursorRO<tables::ExternalStorageBranchesChangeset>
            + DbDupCursorRO<tables::ExternalStorageBranchesChangeset>
            + Send
            + Sync,
    > MdbxOpProofsStorageTrieCursor<tables::ExternalStorageBranchesChangeset, Cursor>
{
    /// Collect all paths for this address with their latest values
    fn collect_paths(&mut self) -> OpProofsStorageResult<BTreeMap<Nibbles, BranchNodeCompact>> {
        let mut path_values: BTreeMap<Nibbles, (u64, Option<BranchNodeCompact>)> = BTreeMap::new();

        if let Some((_block, _)) =
            self.cursor.first().map_err(|e| OpProofsStorageError::Other(e.into()))?
        {
            loop {
                let Some((block, value)) =
                    self.cursor.current().map_err(|e| OpProofsStorageError::Other(e.into()))?
                else {
                    break;
                };

                if block > self.max_block_number {
                    break;
                }

                // Only collect entries for our address
                if value.0.hashed_address == self.hashed_address {
                    let path = value.0.path.0.clone();
                    let branch_opt = value.1 .0.clone();

                    // Keep the latest (highest block number) value for each path
                    path_values
                        .entry(path)
                        .and_modify(|(latest_block, latest_branch)| {
                            if block > *latest_block {
                                *latest_block = block;
                                *latest_branch = branch_opt.clone();
                            }
                        })
                        .or_insert((block, branch_opt));
                }

                if self.cursor.next().map_err(|e| OpProofsStorageError::Other(e.into()))?.is_none()
                {
                    break;
                }
            }
        }

        // Filter out deleted entries and return
        Ok(path_values
            .into_iter()
            .filter_map(|(path, (_block, branch_opt))| branch_opt.map(|branch| (path, branch)))
            .collect())
    }

    /// Get or initialize cached paths
    fn get_cached_paths(&mut self) -> OpProofsStorageResult<&BTreeMap<Nibbles, BranchNodeCompact>> {
        if self.cached_paths.is_none() {
            self.cached_paths = Some(self.collect_paths()?);
        }
        Ok(self.cached_paths.as_ref().unwrap())
    }
}

impl<
        Cursor: DbCursorRO<tables::ExternalStorageBranchesChangeset>
            + DbDupCursorRO<tables::ExternalStorageBranchesChangeset>
            + Send
            + Sync,
    > OpProofsTrieCursor
    for MdbxOpProofsStorageTrieCursor<tables::ExternalStorageBranchesChangeset, Cursor>
{
    fn seek_exact(
        &mut self,
        target_path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        let paths = self.get_cached_paths()?;
        let result = paths.get(&target_path).map(|branch| (target_path.clone(), branch.clone()));
        if result.is_some() {
            self.current_path = Some(target_path);
        }
        Ok(result)
    }

    fn seek(
        &mut self,
        target_path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        let paths = self.get_cached_paths()?;
        // Find first path >= target_path
        let result = paths
            .range(target_path..)
            .next()
            .map(|(path, branch)| (path.clone(), branch.clone()));
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

/// Account hashed cursor that works with changeset table
#[derive(Debug)]
pub struct MdbxAccountCursor<Cursor> {
    cursor: Cursor,
    max_block_number: u64,
    cached_addresses: Option<BTreeMap<B256, Account>>,
    current_address: Option<B256>,
}

impl<
        Cursor: DbCursorRO<tables::ExternalHashedAccountsChangeset>
            + DbDupCursorRO<tables::ExternalHashedAccountsChangeset>
            + Send
            + Sync,
    > MdbxAccountCursor<Cursor>
{
    pub(crate) fn new(cursor: Cursor, max_block_number: u64) -> Self {
        Self { cursor, max_block_number, cached_addresses: None, current_address: None }
    }

    /// Collect all addresses with their latest values
    fn collect_all_addresses(&mut self) -> OpProofsStorageResult<BTreeMap<B256, Account>> {
        let mut address_values: BTreeMap<B256, (u64, Option<Account>)> = BTreeMap::new();

        if let Some((_block, _)) =
            self.cursor.first().map_err(|e| OpProofsStorageError::Other(e.into()))?
        {
            loop {
                let Some((block, value)) =
                    self.cursor.current().map_err(|e| OpProofsStorageError::Other(e.into()))?
                else {
                    break;
                };

                if block > self.max_block_number {
                    break;
                }

                let address = value.0;
                let account_opt = value.1 .0.clone();

                // Keep the latest (highest block number) value for each address
                address_values
                    .entry(address)
                    .and_modify(|(latest_block, latest_account)| {
                        if block > *latest_block {
                            *latest_block = block;
                            *latest_account = account_opt.clone();
                        }
                    })
                    .or_insert((block, account_opt));

                if self.cursor.next().map_err(|e| OpProofsStorageError::Other(e.into()))?.is_none()
                {
                    break;
                }
            }
        }

        // Filter out deleted entries and return
        Ok(address_values
            .into_iter()
            .filter_map(|(addr, (_block, account_opt))| account_opt.map(|account| (addr, account)))
            .collect())
    }

    /// Get or initialize cached addresses
    fn get_cached_addresses(&mut self) -> OpProofsStorageResult<&BTreeMap<B256, Account>> {
        if self.cached_addresses.is_none() {
            self.cached_addresses = Some(self.collect_all_addresses()?);
        }
        Ok(self.cached_addresses.as_ref().unwrap())
    }
}

impl<
        Cursor: DbCursorRO<tables::ExternalHashedAccountsChangeset>
            + DbDupCursorRO<tables::ExternalHashedAccountsChangeset>
            + Send
            + Sync,
    > OpProofsHashedCursor for MdbxAccountCursor<Cursor>
{
    type Value = Account;

    fn seek(&mut self, target_address: B256) -> OpProofsStorageResult<Option<(B256, Account)>> {
        let addresses = self.get_cached_addresses()?;
        // Find first address >= target_address
        let result = addresses
            .range(target_address..)
            .next()
            .map(|(addr, account)| (*addr, *account));
        if let Some((addr, _)) = result {
            self.current_address = Some(addr);
        }
        Ok(result)
    }

    fn next(&mut self) -> OpProofsStorageResult<Option<(B256, Account)>> {
        let next_addr = if let Some(current) = self.current_address {
            // Find next address after current
            let mut next_bytes = current.0;
            // Increment by 1
            for i in (0..32).rev() {
                if next_bytes[i] == 255 {
                    next_bytes[i] = 0;
                } else {
                    next_bytes[i] += 1;
                    break;
                }
            }
            B256::from(next_bytes)
        } else {
            B256::ZERO
        };

        self.seek(next_addr)
    }
}

/// Storage hashed cursor that works with changeset table
#[derive(Debug)]
pub struct MdbxStorageCursor<Cursor> {
    cursor: Cursor,
    max_block_number: u64,
    hashed_address: B256,
    cached_storage: Option<BTreeMap<B256, U256>>,
    current_storage_key: Option<B256>,
}

impl<
        Cursor: DbCursorRO<tables::ExternalHashedStoragesChangeset>
            + DbDupCursorRO<tables::ExternalHashedStoragesChangeset>
            + Send
            + Sync,
    > MdbxStorageCursor<Cursor>
{
    pub(crate) fn new(cursor: Cursor, max_block_number: u64, hashed_address: B256) -> Self {
        Self { cursor, max_block_number, hashed_address, cached_storage: None, current_storage_key: None }
    }

    /// Collect all storage keys for this address with their latest values
    fn collect_storage(&mut self) -> OpProofsStorageResult<BTreeMap<B256, U256>> {
        let mut storage_values: BTreeMap<B256, (u64, Option<B256>)> = BTreeMap::new();

        if let Some((_block, _)) =
            self.cursor.first().map_err(|e| OpProofsStorageError::Other(e.into()))?
        {
            loop {
                let Some((block, value)) =
                    self.cursor.current().map_err(|e| OpProofsStorageError::Other(e.into()))?
                else {
                    break;
                };

                if block > self.max_block_number {
                    break;
                }

                // Only collect entries for our address
                if value.0.hashed_address == self.hashed_address {
                    let storage_key = value.0.hashed_storage_key;
                    let value_opt = value.1 .0.clone();

                    // Keep the latest (highest block number) value for each storage key
                    storage_values
                        .entry(storage_key)
                        .and_modify(|(latest_block, latest_value)| {
                            if block > *latest_block {
                                *latest_block = block;
                                *latest_value = value_opt.clone();
                            }
                        })
                        .or_insert((block, value_opt));
                }

                if self.cursor.next().map_err(|e| OpProofsStorageError::Other(e.into()))?.is_none()
                {
                    break;
                }
            }
        }

        // Filter out deleted entries and convert to U256
        Ok(storage_values
            .into_iter()
            .filter_map(|(key, (_block, value_opt))| {
                value_opt.map(|v| (key, U256::from_be_slice(v.as_slice())))
            })
            .collect())
    }

    /// Get or initialize cached storage
    fn get_cached_storage(&mut self) -> OpProofsStorageResult<&BTreeMap<B256, U256>> {
        if self.cached_storage.is_none() {
            self.cached_storage = Some(self.collect_storage()?);
        }
        Ok(self.cached_storage.as_ref().unwrap())
    }
}

impl<
        Cursor: DbCursorRO<tables::ExternalHashedStoragesChangeset>
            + DbDupCursorRO<tables::ExternalHashedStoragesChangeset>
            + Send
            + Sync,
    > OpProofsHashedCursor for MdbxStorageCursor<Cursor>
{
    type Value = U256;

    fn seek(&mut self, target_storage_key: B256) -> OpProofsStorageResult<Option<(B256, U256)>> {
        let storage = self.get_cached_storage()?;
        // Find first storage key >= target_storage_key
        let result = storage
            .range(target_storage_key..)
            .next()
            .map(|(key, value)| (*key, *value));
        if let Some((key, _)) = result {
            self.current_storage_key = Some(key);
        }
        Ok(result)
    }

    fn next(&mut self) -> OpProofsStorageResult<Option<(B256, U256)>> {
        let next_key = if let Some(current) = self.current_storage_key {
            // Find next key after current
            let mut next_bytes = current.0;
            // Increment by 1
            for i in (0..32).rev() {
                if next_bytes[i] == 255 {
                    next_bytes[i] = 0;
                } else {
                    next_bytes[i] += 1;
                    break;
                }
            }
            B256::from(next_bytes)
        } else {
            B256::ZERO
        };

        self.seek(next_key)
    }
}
