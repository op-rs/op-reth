//! MDBX-backed implementation of ExternalStorage
//!
//! This module provides a persistent storage backend using MDBX (libmdbx) for the external proofs
//! ExEx. The database is completely separate from Reth's main database and is stored by default
//! at `<datadir>/external-proofs/`.

pub mod codec;
pub mod cursor;
pub mod models;
pub mod tables;

use crate::storage::{
    BlockStateDiff, OpProofsStorage, OpProofsStorageError, OpProofsStorageResult,
};
use alloy_primitives::{map::HashMap, B256, U256};
use reth_db::{
    mdbx::{init_db_for, DatabaseArguments, MaxReadTransactionDuration},
    ClientVersion, DatabaseEnv, DatabaseError,
};
use reth_db_api::{
    cursor::{DbCursorRO, DbCursorRW},
    database::Database,
    transaction::{DbTx, DbTxMut},
};
use reth_primitives_traits::Account;
use reth_trie::{BranchNodeCompact, Nibbles, StoredNibbles};
use std::path::Path;

pub use codec::{BlockNumberHash, MaybeDeleted};
pub use cursor::MdbxOpProofsStorageTrieCursor;
pub use models::{
    HashedAccountEntry, HashedStorageEntry, HashedStorageSubKey, MetadataKey, StorageBranchEntry,
    StorageBranchSubKey, StoredNibblesWithBranch,
};
pub use tables::Tables as ExternalTables;

impl From<DatabaseError> for OpProofsStorageError {
    fn from(error: DatabaseError) -> Self {
        Self::Other(error.into())
    }
}

/// MDBX-backed implementation of ExternalStorage
///
/// **IMPORTANT**: This uses a COMPLETELY SEPARATE database from Reth's main DB.
/// By default, it creates a database in `<datadir>/external-proofs/`.
#[derive(Debug, Clone)]
pub struct MdbxOpProofsStorage<DB> {
    /// Database environment (separate from main Reth DB)
    db: DB,
}

impl MdbxOpProofsStorage<DatabaseEnv> {
    /// Open or create external storage database at the specified path
    ///
    /// # Arguments
    /// * `path` - Path to the external storage database directory (e.g.,
    ///   `/path/to/datadir/external-proofs/`)
    pub fn new(db: DatabaseEnv) -> OpProofsStorageResult<Self> {
        Ok(Self { db })
    }

    /// Get database for testing (creates in temp directory)
    #[cfg(test)]
    pub fn new_test() -> OpProofsStorageResult<Self> {
        let temp_dir = tempfile::tempdir().map_err(|e| {
            OpProofsStorageError::Other(eyre::eyre!("Failed to create temp dir: {}", e))
        })?;
        Self::new_from_path(temp_dir.path())
    }

    /// Create a new storage instance from a given path
    ///
    /// # Arguments
    /// * `path` - Path to the external storage database directory
    pub fn new_from_path(path: impl AsRef<Path>) -> OpProofsStorageResult<Self> {
        let path = path.as_ref().to_path_buf();

        // Create a NEW database with our external tables
        // This is SEPARATE from Reth's main database
        // init_db_for will create the directory and all tables automatically
        let mut args = DatabaseArguments::new(ClientVersion::default());
        args.max_read_transaction_duration(Some(MaxReadTransactionDuration::Unbounded));
        let db = init_db_for::<_, tables::Tables>(&path, args).map_err(|e| {
            OpProofsStorageError::Other(eyre::eyre!(
                "Failed to initialize external storage database at {}: {}",
                path.display(),
                e
            ))
        })?;
        tracing::info!(
            path = %path.display(),
            tables = tables::Tables::ALL.len(),
            "Initialized external storage MDBX database"
        );

        Self::new(db)
    }
}

impl<TX: DbTxMut + DbTx, DB: Database<TXMut = TX>> MdbxOpProofsStorage<DB> {
    async fn store_account_branches_inner(
        &self,
        tx: &TX,
        block_number: u64,
        updates: Vec<(Nibbles, Option<BranchNodeCompact>)>,
        append: bool,
    ) -> OpProofsStorageResult<()> {
        // 1. Append to changeset table (DupSort with block_number as Key)
        {
            let mut cursor = tx.cursor_dup_write::<tables::ExternalAccountBranchesChangeset>()?;

            for (path, branch) in &updates {
                let stored_nibbles: StoredNibbles = path.clone().into();
                let maybe_deleted = MaybeDeleted::from(branch.clone());
                let value = StoredNibblesWithBranch(stored_nibbles.clone(), maybe_deleted);

                if append {
                    // Use append since block_number always increases
                    cursor.append(block_number, &value)?;
                } else {
                    cursor.upsert(block_number, &value)?;
                }
            }
        }

        // 2. Update history table (upsert IntegerList) - skip for block 0 during initial backfill
        let mut cursor = tx.cursor_write::<tables::ExternalAccountBranchesHistory>()?;

        for (path, _) in updates {
            let key: StoredNibbles = path.into();

            // Get existing list or create new
            let mut list =
                cursor.seek_exact(key.clone())?.map(|(_, list)| list).unwrap_or_default();

            // Add block number to list (using inner RoaringTreemap)
            list.0.insert(block_number);

            // Update the history table
            cursor.upsert(key, &list)?;
        }

        Ok(())
    }

    async fn store_storage_branches_inner(
        &self,
        tx: &TX,
        block_number: u64,
        hashed_address: B256,
        items: Vec<(Nibbles, Option<BranchNodeCompact>)>,
        append: bool,
    ) -> OpProofsStorageResult<()> {
        // 1. Append to changeset table (DupSort with block_number as Key)
        {
            let mut cursor = tx.cursor_dup_write::<tables::ExternalStorageBranchesChangeset>()?;

            for (path, branch) in &items {
                let subkey = StorageBranchSubKey::new(hashed_address, StoredNibbles(path.clone()));
                let maybe_deleted = MaybeDeleted::from(branch.clone());
                let value = StorageBranchEntry(subkey.clone(), maybe_deleted);

                if append {
                    // Use append since block_number always increases
                    cursor.append(block_number, &value)?;
                } else {
                    cursor.upsert(block_number, &value)?;
                }
            }
        }

        // 2. Update history table (upsert IntegerList) - skip for block 0 during initial backfill
        let mut cursor = tx.cursor_write::<tables::ExternalStorageBranchesHistory>()?;

        for (path, _) in items {
            let key = StorageBranchSubKey::new(hashed_address, StoredNibbles(path));

            // Get existing list or create new
            let mut list =
                cursor.seek_exact(key.clone())?.map(|(_, list)| list).unwrap_or_default();

            // Add block number to list (using inner RoaringTreemap)
            list.0.insert(block_number);

            // Update the history table
            cursor.upsert(key, &list)?;
        }

        Ok(())
    }

    async fn store_hashed_accounts_inner(
        &self,
        tx: &TX,
        accounts: Vec<(B256, Option<Account>)>,
        block_number: u64,
        append: bool,
    ) -> OpProofsStorageResult<()> {
        // 1. Append to changeset table (DupSort with block_number as Key)
        {
            let mut cursor = tx.cursor_dup_write::<tables::ExternalHashedAccountsChangeset>()?;

            for (address, account) in &accounts {
                let maybe_deleted = MaybeDeleted::from(account.clone());
                let value = HashedAccountEntry(*address, maybe_deleted);

                if append {
                    // Use append since block_number always increases
                    cursor.append(block_number, &value)?;
                } else {
                    cursor.upsert(block_number, &value)?;
                }
            }
        }

        // 2. Update history table (upsert IntegerList) - skip for block 0 during initial backfill
        let mut cursor = tx.cursor_write::<tables::ExternalHashedAccountsHistory>()?;

        for (address, _) in accounts {
            // Get existing list or create new
            let mut list = cursor.seek_exact(address)?.map(|(_, list)| list).unwrap_or_default();

            // Add block number to list (using inner RoaringTreemap)
            list.0.insert(block_number);

            // Update the history table
            cursor.upsert(address, &list)?;
        }

        Ok(())
    }

    async fn store_hashed_storages_inner(
        &self,
        tx: &TX,
        hashed_address: B256,
        storages: Vec<(B256, U256)>,
        block_number: u64,
        append: bool,
    ) -> OpProofsStorageResult<()> {
        // 1. Append to changeset table (DupSort with block_number as Key)
        {
            let mut cursor = tx.cursor_dup_write::<tables::ExternalHashedStoragesChangeset>()?;

            for (storage_key, value) in &storages {
                let subkey = HashedStorageSubKey::new(hashed_address, *storage_key);

                // Convert U256 to B256 for storage
                // Zero values are treated as deletions in Ethereum
                let maybe_deleted = if value.is_zero() {
                    MaybeDeleted::from(None)
                } else {
                    let value_b256 = B256::from(value.to_be_bytes());
                    MaybeDeleted::from(Some(value_b256))
                };
                let value = HashedStorageEntry(subkey.clone(), maybe_deleted);

                if append {
                    // Use append since block_number always increases
                    cursor.append(block_number, &value)?;
                } else {
                    cursor.upsert(block_number, &value)?;
                }
            }
        }

        // 2. Update history table (upsert IntegerList) - skip for block 0 during initial backfill
        let mut cursor = tx.cursor_write::<tables::ExternalHashedStoragesHistory>()?;

        for (storage_key, _) in storages {
            let key = HashedStorageSubKey::new(hashed_address, storage_key);

            // Get existing list or create new
            let mut list =
                cursor.seek_exact(key.clone())?.map(|(_, list)| list).unwrap_or_default();

            // Add block number to list (using inner RoaringTreemap)
            list.0.insert(block_number);

            // Update the history table
            cursor.upsert(key, &list)?;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl<TX: DbTx, TXMut: DbTxMut + DbTx, DB: Database<TX = TX, TXMut = TXMut>> OpProofsStorage
    for MdbxOpProofsStorage<DB>
{
    type AccountTrieCursor = cursor::AccountTrieCursor<TX>;
    type StorageTrieCursor =
        MdbxOpProofsStorageTrieCursor<tables::ExternalStorageBranchesChangeset, TX>;
    type AccountHashedCursor = cursor::MdbxAccountCursor<TX>;
    type StorageCursor = cursor::MdbxStorageCursor<TX>;

    async fn store_account_branches(
        &self,
        block_number: u64,
        mut updates: Vec<(Nibbles, Option<BranchNodeCompact>)>,
    ) -> OpProofsStorageResult<()> {
        // Sort updates by path for MDBX append operation
        updates.sort_by(|(a, _), (b, _)| a.cmp(b));

        let tx = self.db.tx_mut()?;

        self.store_account_branches_inner(&tx, block_number, updates, true).await?;

        tx.commit()?;

        Ok(())
    }

    async fn store_storage_branches(
        &self,
        block_number: u64,
        hashed_address: B256,
        mut items: Vec<(Nibbles, Option<BranchNodeCompact>)>,
    ) -> OpProofsStorageResult<()> {
        // Sort items by path for MDBX append operation
        items.sort_by(|(a, _), (b, _)| a.cmp(b));

        let tx = self.db.tx_mut()?;

        self.store_storage_branches_inner(&tx, block_number, hashed_address, items, true).await?;

        tx.commit()?;

        Ok(())
    }

    async fn store_hashed_accounts(
        &self,
        mut accounts: Vec<(B256, Option<Account>)>,
        block_number: u64,
    ) -> OpProofsStorageResult<()> {
        // Sort accounts by address for MDBX append operation
        accounts.sort_by(|(a, _), (b, _)| a.cmp(b));

        let tx = self.db.tx_mut()?;

        self.store_hashed_accounts_inner(&tx, accounts, block_number, true).await?;

        tx.commit()?;

        Ok(())
    }

    async fn store_hashed_storages(
        &self,
        hashed_address: B256,
        mut storages: Vec<(B256, U256)>,
        block_number: u64,
    ) -> OpProofsStorageResult<()> {
        // Sort storages by storage key for MDBX append operation
        storages.sort_by(|(a, _), (b, _)| a.cmp(b));

        let tx = self.db.tx_mut()?;

        self.store_hashed_storages_inner(&tx, hashed_address, storages, block_number, true).await?;

        tx.commit()?;

        Ok(())
    }

    async fn store_trie_updates(
        &self,
        block_number: u64,
        block_state_diff: BlockStateDiff,
    ) -> OpProofsStorageResult<(u64, u64, u64, u64)> {
        // Extract trie updates and post state
        let BlockStateDiff { trie_updates, post_state } = block_state_diff;

        // For now, we don't have the block hash in BlockStateDiff, so use ZERO
        // This matches the in-memory implementation
        let block_hash = B256::ZERO;

        let mut account_trie_updates_written = 0;
        let mut storage_trie_updates_written = 0;
        let mut hashed_accounts_written = 0;
        let mut hashed_storages_written = 0;

        let tx = self.db.tx_mut()?;

        // Store account trie branches
        // Build HashMap: first add removals as None, then apply updates (which take precedence)
        if !trie_updates.removed_nodes_ref().is_empty() || !trie_updates.account_nodes.is_empty() {
            let mut account_updates_map: HashMap<Nibbles, Option<BranchNodeCompact>> =
                HashMap::default();

            // First, add all removed nodes as deletions
            for removed_path in trie_updates.removed_nodes_ref() {
                account_updates_map.insert(*removed_path, None);
            }

            // Then, apply updates (these take precedence over removals)
            for (path, node) in trie_updates.account_nodes_ref() {
                account_updates_map.insert(*path, Some(node.clone()));
            }

            // Convert to sorted vec
            let mut account_updates: Vec<_> = account_updates_map.into_iter().collect();
            account_updates.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            account_trie_updates_written += account_updates.len();
            self.store_account_branches_inner(&tx, block_number, account_updates, true).await?;
        }

        // Store storage trie branches
        for (address, storage_trie) in trie_updates.storage_tries {
            // Build HashMap: first add removals as None, then apply updates (which take precedence)
            if !storage_trie.removed_nodes_ref().is_empty() ||
                !storage_trie.storage_nodes.is_empty()
            {
                let mut storage_updates_map: HashMap<Nibbles, Option<BranchNodeCompact>> =
                    HashMap::default();

                // First, add all removed nodes as deletions
                for removed_path in storage_trie.removed_nodes_ref() {
                    storage_updates_map.insert(*removed_path, None);
                }

                // Then, apply updates (these take precedence over removals)
                for (path, node) in storage_trie.storage_nodes_ref() {
                    storage_updates_map.insert(*path, Some(node.clone()));
                }

                // Convert to sorted vec
                let mut storage_updates: Vec<_> = storage_updates_map.into_iter().collect();
                storage_updates.sort_unstable_by(|a, b| a.0.cmp(&b.0));

                storage_trie_updates_written += storage_updates.len();
                self.store_storage_branches_inner(
                    &tx,
                    block_number,
                    address,
                    storage_updates,
                    true,
                )
                .await?;
            }
        }

        // Store hashed accounts
        if !post_state.accounts.is_empty() {
            let accounts: Vec<_> = post_state.accounts.into_iter().collect();
            hashed_accounts_written += accounts.len();
            self.store_hashed_accounts_inner(&tx, accounts, block_number, true).await?;
        }

        // Store hashed storage
        for (address, storage) in post_state.storages {
            if !storage.storage.is_empty() {
                let storages: Vec<_> = storage.storage.into_iter().collect();
                hashed_storages_written += storages.len();
                self.store_hashed_storages_inner(&tx, address, storages, block_number, true)
                    .await?;
            }
        }

        let mut cursor = tx.cursor_write::<tables::ExternalBlockMetadata>()?;

        // Update latest block
        let latest_value = codec::BlockNumberHash(block_number, block_hash);
        cursor.upsert(models::MetadataKey::LatestBlock, &latest_value)?;

        // Set earliest block if not set
        if cursor.seek_exact(models::MetadataKey::EarliestBlock)?.is_none() {
            let earliest_value = codec::BlockNumberHash(block_number, block_hash);
            cursor.insert(models::MetadataKey::EarliestBlock, &earliest_value)?;
        }

        tx.commit()?;

        Ok((
            account_trie_updates_written as u64,
            storage_trie_updates_written as u64,
            hashed_accounts_written as u64,
            hashed_storages_written as u64,
        ))
    }

    fn storage_trie_cursor(
        &self,
        hashed_address: B256,
        max_block_number: u64,
    ) -> OpProofsStorageResult<Self::StorageTrieCursor> {
        let txn = self.db.tx()?;
        Ok(MdbxOpProofsStorageTrieCursor::new(txn, hashed_address, max_block_number))
    }

    fn account_trie_cursor(
        &self,
        max_block_number: u64,
    ) -> OpProofsStorageResult<Self::AccountTrieCursor> {
        let txn = self.db.tx()?;
        Ok(cursor::AccountTrieCursor::new(txn, max_block_number))
    }

    fn account_hashed_cursor(
        &self,
        max_block_number: u64,
    ) -> OpProofsStorageResult<Self::AccountHashedCursor> {
        let txn = self.db.tx()?;
        Ok(cursor::MdbxAccountCursor::new(txn, max_block_number))
    }

    fn storage_hashed_cursor(
        &self,
        hashed_address: B256,
        max_block_number: u64,
    ) -> OpProofsStorageResult<Self::StorageCursor> {
        let txn = self.db.tx()?;
        Ok(cursor::MdbxStorageCursor::new(txn, max_block_number, hashed_address))
    }

    async fn get_earliest_block_number(&self) -> OpProofsStorageResult<Option<(u64, B256)>> {
        let tx = self.db.tx()?;

        let mut cursor = tx.cursor_read::<tables::ExternalBlockMetadata>()?;

        let result = cursor
            .seek_exact(models::MetadataKey::EarliestBlock)?
            .map(|(_, hash)| hash.into_components());

        if let Some(result) = result {
            return Ok(Some(result));
        }

        let latest_result = cursor
            .seek_exact(models::MetadataKey::LatestBlock)?
            .map(|(_, hash)| hash.into_components());

        Ok(latest_result)
    }

    async fn get_latest_block_number(&self) -> OpProofsStorageResult<Option<(u64, B256)>> {
        let tx = self.db.tx()?;

        let mut cursor = tx.cursor_read::<tables::ExternalBlockMetadata>()?;

        let latest_result = cursor
            .seek_exact(models::MetadataKey::LatestBlock)?
            .map(|(_, hash)| hash.into_components());

        if let Some(latest_result) = latest_result {
            return Ok(Some(latest_result));
        }

        let earliest_result = cursor
            .seek_exact(models::MetadataKey::EarliestBlock)?
            .map(|(_, hash)| hash.into_components());

        Ok(earliest_result)
    }

    async fn fetch_trie_updates(
        &self,
        _block_number: u64,
    ) -> OpProofsStorageResult<BlockStateDiff> {
        // For now, return empty updates
        // A full implementation would need to reconstruct the exact changes
        // made in a specific block, which requires more complex logic
        // This is sufficient for basic operations
        Ok(BlockStateDiff { trie_updates: Default::default(), post_state: Default::default() })
    }

    async fn prune_earliest_state(
        &self,
        new_earliest_block_number: u64,
        _diff: BlockStateDiff,
    ) -> OpProofsStorageResult<()> {
        // Prune all data before new_earliest_block_number
        // This removes old historical data to save space

        let tx = self.db.tx_mut()?;

        // Delete entries with block_number < new_earliest_block_number from all tables
        // Note: We keep block 0 as the new base state, which we'll update with the diff

        // TODO: Implement actual pruning by iterating through tables and deleting old entries
        // For MVP, we'll just update the metadata
        // A full implementation would:
        // 1. Iterate through each table (AccountBranches, StorageBranches, etc.)
        // 2. Delete entries where block_number > 0 AND block_number < new_earliest_block_number
        // 3. Update block 0 with the consolidated diff
        // 4. Update index tables accordingly

        // Update metadata
        let mut cursor = tx.cursor_write::<tables::ExternalBlockMetadata>()?;

        // Note: We need the block hash, but diff doesn't have it
        // For now, use zero hash - this should be fixed in the trait design
        let hash = B256::ZERO;

        let value = codec::BlockNumberHash::new(new_earliest_block_number, hash);
        cursor.upsert(models::MetadataKey::EarliestBlock, &value)?;

        tx.commit()?;
        Ok(())
    }

    async fn replace_updates(
        &self,
        _latest_common_block_number: u64,
        _blocks_to_add: HashMap<u64, BlockStateDiff>,
    ) -> OpProofsStorageResult<()> {
        // Handle chain reorganization:
        // 1. Delete all blocks > latest_common_block_number (the reorg'd blocks)
        // 2. Add the new blocks from blocks_to_add
        // 3. Update LatestBlock metadata

        let tx = self.db.tx_mut()?;

        // TODO: Implement actual reorg handling
        // For MVP, we'll just update the metadata
        // A full implementation would:
        // 1. Delete all entries where block_number > latest_common_block_number
        // 2. For each block in blocks_to_add, call store_trie_updates
        // 3. Update LatestBlock metadata to the highest block in blocks_to_add
        // 4. Update index tables accordingly

        // For now, just commit empty transaction
        tx.commit()?;
        Ok(())
    }

    async fn set_earliest_block_number(
        &self,
        block_number: u64,
        hash: B256,
    ) -> OpProofsStorageResult<()> {
        let tx = self.db.tx_mut()?;

        let mut cursor = tx.cursor_write::<tables::ExternalBlockMetadata>()?;

        let value = codec::BlockNumberHash::new(block_number, hash);
        cursor.upsert(models::MetadataKey::EarliestBlock, &value)?;

        tx.commit()?;
        Ok(())
    }

    async fn get_last_stored_account_branch(&self) -> OpProofsStorageResult<Option<Nibbles>> {
        let tx = self.db.tx()?;
        let mut cursor = tx.cursor_read::<tables::ExternalAccountBranchesChangeset>()?;
        cursor.last()?;

        loop {
            let Some((_block, value)) = cursor.current()? else {
                return Ok(None);
            };
            let Some(_branch) = value.1 .0 else {
                cursor.prev()?;
                continue;
            };

            return Ok(Some(value.0 .0));
        }
    }

    async fn get_last_stored_storage_branch(
        &self,
    ) -> OpProofsStorageResult<Option<(B256, Nibbles)>> {
        let tx = self.db.tx()?;
        let mut cursor = tx.cursor_read::<tables::ExternalStorageBranchesChangeset>()?;
        cursor.last()?;

        loop {
            let Some((_block, value)) = cursor.current()? else {
                return Ok(None);
            };

            let Some(_branch) = value.1 .0 else {
                cursor.prev()?;
                continue;
            };

            return Ok(Some((value.0.hashed_address, value.0.path.0)));
        }
    }

    async fn get_last_stored_hashed_account(&self) -> OpProofsStorageResult<Option<B256>> {
        let tx = self.db.tx()?;
        let mut cursor = tx.cursor_read::<tables::ExternalHashedAccountsChangeset>()?;
        cursor.last()?;

        loop {
            let Some((_block, value)) = cursor.current()? else {
                return Ok(None);
            };

            let Some(_account) = value.1 .0 else {
                cursor.prev()?;
                continue;
            };

            return Ok(Some(value.0));
        }
    }

    async fn get_last_stored_hashed_storage(&self) -> OpProofsStorageResult<Option<(B256, B256)>> {
        let tx = self.db.tx()?;
        let mut cursor = tx.cursor_read::<tables::ExternalHashedStoragesChangeset>()?;
        cursor.last()?;

        loop {
            let Some((_block, value)) = cursor.current()? else {
                return Ok(None);
            };

            let Some(_storage) = value.1 .0 else {
                cursor.prev()?;
                continue;
            };

            return Ok(Some((value.0.hashed_address, value.0.hashed_storage_key)));
        }
    }
}
