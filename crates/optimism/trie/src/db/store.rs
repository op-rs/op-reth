use crate::{
    db::{
        models::{HashedAccountHistory, HashedStorageHistory, HashedStorageKey, MaybeDeleted, VersionedValue, StorageValue},
        MdbxAccountCursor, MdbxStorageCursor, MdbxTrieCursor,
    },
    BlockStateDiff, OpProofsStorage, OpProofsStorageError, OpProofsStorageResult,
};
use alloy_primitives::{map::HashMap, B256, U256};
use reth_db::{
    cursor::DbDupCursorRW,
    mdbx::{init_db_for, DatabaseArguments},
    Database, DatabaseEnv,
};
use reth_primitives_traits::Account;
use reth_trie::{BranchNodeCompact, Nibbles};
use std::path::Path;

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
}

impl OpProofsStorage for MdbxProofsStorage {
    type TrieCursor = MdbxTrieCursor;
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
        accounts: Vec<(B256, Option<Account>)>,
        block_number: u64,
    ) -> OpProofsStorageResult<()> {
        let mut accounts = accounts;
        if accounts.is_empty() {
            return Ok(());
        }

        // sort the accounts by key to ensure insertion is efficient
        accounts.sort_by_key(|(key, _)| *key);

        self.env
            .update(|tx| {
                let mut cursor = tx
                    .new_cursor::<HashedAccountHistory>()
                    .map_err(|err| OpProofsStorageError::Other(err.into()))?;
                for (key, account) in accounts {
                    let vv = VersionedValue { block_number, value: MaybeDeleted(account) };
                    cursor.append_dup(key, vv)
                        .map_err(|err| OpProofsStorageError::Other(err.into()))?;
                }
                Ok(())
            })
            .map_err(|err| OpProofsStorageError::Other(err.into()))?
    }

    async fn store_hashed_storages(
        &self,
        hashed_address: B256,
        storages: Vec<(B256, U256)>,
        block_number: u64,
    ) -> OpProofsStorageResult<()> {
        let mut storages = storages;
        if storages.is_empty() {
            return Ok(());
        }

        // sort the storages by key to ensure insertion is efficient
        storages.sort_by_key(|(key, _)| *key);

        self.env
            .update(|tx| {
                let mut cursor = tx
                    .new_cursor::<HashedStorageHistory>()
                    .map_err(|err| OpProofsStorageError::Other(err.into()))?;
                for (key, value) in storages {
                    let vv = VersionedValue { block_number, value: MaybeDeleted(Some(StorageValue(value))) };
                    let storage_key = HashedStorageKey::new(hashed_address, key);
                    cursor.append_dup(storage_key, vv)
                        .map_err(|err| OpProofsStorageError::Other(err.into()))?;
                }
                Ok(())
            })
            .map_err(|err| OpProofsStorageError::Other(err.into()))?
    }

    async fn get_earliest_block_number(&self) -> OpProofsStorageResult<Option<(u64, B256)>> {
        unimplemented!()
    }

    async fn get_latest_block_number(&self) -> OpProofsStorageResult<Option<(u64, B256)>> {
        unimplemented!()
    }

    fn trie_cursor(
        &self,
        _hashed_address: Option<B256>,
        _max_block_number: u64,
    ) -> OpProofsStorageResult<Self::TrieCursor> {
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
        _block_number: u64,
        _hash: B256,
    ) -> OpProofsStorageResult<()> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_db::cursor::DbDupCursorRO;
    use tempfile::TempDir;

    #[tokio::test]
    async fn store_hashed_accounts_writes_versioned_values() {
        let dir = TempDir::new().unwrap();
        let store = MdbxProofsStorage::new(dir.path()).expect("env");

        let block_number = 0;
        let addr = B256::from([0xAA; 32]);
        let account = Account::default();
        store
            .store_hashed_accounts(vec![(addr, Some(account))], block_number)
            .await
            .expect("write accounts");

        let tx = store.env.tx().expect("ro tx");
        let mut cur = tx.new_cursor::<HashedAccountHistory>().expect("cursor");
        let vv = cur.seek_by_key_subkey(addr, block_number).expect("seek");
        let vv = vv.expect("entry exists");

        assert_eq!(vv.block_number, block_number);
        assert_eq!(vv.value.0, Some(account));
    }

    #[tokio::test]
    async fn store_hashed_storages_writes_versioned_values() {
        let dir = TempDir::new().unwrap();
        let store = MdbxProofsStorage::new(dir.path()).expect("env");

        let block_number = 0;
        let addr = B256::from([0x11; 32]);
        let slot = B256::from([0x22; 32]);
        let val = U256::from(0x1234u64);

        store
            .store_hashed_storages(addr, vec![(slot, val)], block_number)
            .await
            .expect("write storage");

        let tx = store.env.tx().expect("ro tx");
        let mut cur = tx.new_cursor::<HashedStorageHistory>().expect("cursor");
        let key = HashedStorageKey::new(addr, slot);
        let vv = cur.seek_by_key_subkey(key, block_number).expect("seek");
        let vv = vv.expect("entry exists");

        assert_eq!(vv.block_number, block_number);
        let inner = vv.value.0.as_ref().expect("Some(StorageValue)");
        assert_eq!(inner.0, val);
    }
}
