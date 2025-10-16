use crate::{
    db::{MdbxAccountCursor, MdbxStorageCursor, MdbxTrieCursor},
    BlockStateDiff, OpProofsStorage, OpProofsStorageError, OpProofsStorageResult,
};
use alloy_primitives::{map::HashMap, B256, U256};
use reth_db::{
    cursor::{DbCursorRO, DbCursorRW},
    mdbx::{init_db_for, DatabaseArguments},
    transaction::DbTx,
    Database, DatabaseEnv,
};
use reth_primitives_traits::Account;
use reth_trie::{BranchNodeCompact, Nibbles};
use std::path::Path;

use super::{BlockNumberHash, ProofWindow, ProofWindowKey};

/// MDBX implementation of `OpProofsStorage`.
#[derive(Debug)]
pub struct MdbxProofsStorage {
    env: DatabaseEnv,
}

impl MdbxProofsStorage {
    /// Creates a new `MdbxProofsStorage` instance with the given path.
    pub fn new(path: &Path) -> Result<Self, OpProofsStorageError> {
        let env = init_db_for::<_, super::models::Tables>(path, DatabaseArguments::default())
            .map_err(OpProofsStorageError::Other)?;
        Ok(Self { env })
    }

    async fn get_block_number_hash(
        &self,
        key: ProofWindowKey,
    ) -> OpProofsStorageResult<Option<(u64, B256)>> {
        let result = self.env.view(|tx| {
            let mut cursor = tx.cursor_read::<ProofWindow>().ok()?;
            let value = cursor.seek_exact(key).ok()?;
            value.map(|(_, val)| (val.0, val.1))
        });
        Ok(result?)
    }

    async fn set_earliest_block_number_hash(
        &self,
        block_number: u64,
        hash: B256,
    ) -> OpProofsStorageResult<()> {
        self.env.update(|tx| {
            let mut cursor = tx
                .new_cursor::<ProofWindow>()
                .map_err(|err| OpProofsStorageError::DatabaseError(err))?;

            cursor
                .append(ProofWindowKey::EarliestBlock, &BlockNumberHash(block_number, hash))
                .map_err(OpProofsStorageError::DatabaseError)?;
            Ok(())
        })?
    }
}

impl OpProofsStorage for MdbxProofsStorage {
    type StorageTrieCursor = MdbxTrieCursor;
    type AccountTrieCursor = MdbxTrieCursor;
    type StorageCursor = MdbxStorageCursor;
    type AccountHashedCursor = MdbxAccountCursor;

    async fn store_account_branches(
        &self,
        _block_number: u64,
        _updates: Vec<(Nibbles, Option<BranchNodeCompact>)>,
    ) -> OpProofsStorageResult<()> {
        unimplemented!()
    }

    async fn store_storage_branches(
        &self,
        _block_number: u64,
        _hashed_address: B256,
        _items: Vec<(Nibbles, Option<BranchNodeCompact>)>,
    ) -> OpProofsStorageResult<()> {
        unimplemented!()
    }

    async fn store_hashed_accounts(
        &self,
        _accounts: Vec<(B256, Option<Account>)>,
        _block_number: u64,
    ) -> OpProofsStorageResult<()> {
        unimplemented!()
    }

    async fn store_hashed_storages(
        &self,
        _hashed_address: B256,
        _storages: Vec<(B256, U256)>,
        _block_number: u64,
    ) -> OpProofsStorageResult<()> {
        unimplemented!()
    }

    async fn get_earliest_block_number(&self) -> OpProofsStorageResult<Option<(u64, B256)>> {
        self.get_block_number_hash(ProofWindowKey::EarliestBlock).await
    }

    async fn get_latest_block_number(&self) -> OpProofsStorageResult<Option<(u64, B256)>> {
        self.get_block_number_hash(ProofWindowKey::LatestBlock).await
    }

    fn storage_trie_cursor(
        &self,
        _hashed_address: B256,
        _max_block_number: u64,
    ) -> OpProofsStorageResult<Self::StorageTrieCursor> {
        unimplemented!()
    }

    fn account_trie_cursor(
        &self,
        _max_block_number: u64,
    ) -> OpProofsStorageResult<Self::AccountTrieCursor> {
        unimplemented!()
    }

    fn storage_hashed_cursor(
        &self,
        _hashed_address: B256,
        _max_block_number: u64,
    ) -> OpProofsStorageResult<Self::StorageCursor> {
        unimplemented!()
    }

    fn account_hashed_cursor(
        &self,
        _max_block_number: u64,
    ) -> OpProofsStorageResult<Self::AccountHashedCursor> {
        unimplemented!()
    }

    async fn store_trie_updates(
        &self,
        _block_number: u64,
        _block_state_diff: BlockStateDiff,
    ) -> OpProofsStorageResult<()> {
        unimplemented!()
    }

    async fn fetch_trie_updates(
        &self,
        _block_number: u64,
    ) -> OpProofsStorageResult<BlockStateDiff> {
        unimplemented!()
    }

    async fn prune_earliest_state(
        &self,
        _new_earliest_block_number: u64,
        _diff: BlockStateDiff,
    ) -> OpProofsStorageResult<()> {
        unimplemented!()
    }

    async fn replace_updates(
        &self,
        _latest_common_block_number: u64,
        _blocks_to_add: HashMap<u64, BlockStateDiff>,
    ) -> OpProofsStorageResult<()> {
        unimplemented!()
    }

    async fn set_earliest_block_number(
        &self,
        block_number: u64,
        hash: B256,
    ) -> OpProofsStorageResult<()> {
        self.set_earliest_block_number_hash(block_number, hash).await
    }
}
