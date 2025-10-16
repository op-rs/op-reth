use crate::{
    db::{
        models::{AccountTrieHistory, MaybeDeleted, VersionedValue},
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
use reth_trie::{BranchNodeCompact, Nibbles, StoredNibbles};
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
    type StorageTrieCursor = MdbxTrieCursor;
    type AccountTrieCursor = MdbxTrieCursor;
    type StorageCursor = MdbxStorageCursor;
    type AccountHashedCursor = MdbxAccountCursor;

    async fn store_account_branches(
        &self,
        block_number: u64,
        updates: Vec<(Nibbles, Option<BranchNodeCompact>)>,
    ) -> OpProofsStorageResult<()> {
        if updates.is_empty() {
            return Ok(());
        }

        self.env.update(|tx| {
            let mut cursor = tx.new_cursor::<AccountTrieHistory>()?;
            for (nibble, branch_node) in updates {
                let vv = VersionedValue { block_number, value: MaybeDeleted(branch_node) };
                cursor.append_dup(StoredNibbles::from(nibble), vv)?;
            }
            Ok(())
        })?
    }

    async fn store_storage_branches(
        &self,
        block_number: u64,
        hashed_address: B256,
        items: Vec<(Nibbles, Option<BranchNodeCompact>)>,
    ) -> OpProofsStorageResult<()> {
        if items.is_empty() {
            return Ok(());
        }

        self.env.update(|tx| {
            let mut cursor = tx.new_cursor::<super::models::StorageTrieHistory>()?;
            for (nibble, branch_node) in items {
                let key = super::models::StorageTrieSubKey::new(
                    hashed_address,
                    StoredNibbles::from(nibble),
                );
                let vv = VersionedValue { block_number, value: MaybeDeleted(branch_node) };
                cursor.append_dup(key, vv)?;
            }
            Ok(())
        })?
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
        unimplemented!()
    }

    async fn get_latest_block_number(&self) -> OpProofsStorageResult<Option<(u64, B256)>> {
        unimplemented!()
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
        _block_number: u64,
        _hash: B256,
    ) -> OpProofsStorageResult<()> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        models::{AccountTrieHistory, StorageTrieHistory},
        StorageTrieSubKey,
    };
    use alloy_primitives::B256;
    use reth_db::{cursor::DbDupCursorRO, transaction::DbTx};
    use reth_trie::{BranchNodeCompact, Nibbles, StoredNibbles};
    use tempfile::TempDir;

    const B0: u64 = 0;

    #[tokio::test]
    async fn test_store_account_branches_writes_versioned_values() {
        let dir = TempDir::new().unwrap();
        let store = MdbxProofsStorage::new(dir.path()).expect("env");

        let nibble = Nibbles::from_nibbles_unchecked([0x12, 0x34]);
        let branch_node = BranchNodeCompact::new(0b1, 0, 0, vec![], Some(B256::random()));
        let updates = vec![(nibble, Some(branch_node.clone()))];

        store.store_account_branches(B0, updates).await.expect("write");

        let tx = store.env.tx().expect("ro tx");
        let mut cur = tx.cursor_dup_read::<AccountTrieHistory>().expect("cursor");

        let vv = cur
            .seek_by_key_subkey(StoredNibbles::from(nibble), B0)
            .expect("seek")
            .expect("entry exists");

        assert_eq!(vv.block_number, B0);
        assert_eq!(vv.value.0, Some(branch_node));
    }

    #[tokio::test]
    async fn test_store_account_branches_multiple_items_unsorted() {
        let dir = TempDir::new().unwrap();
        let store = MdbxProofsStorage::new(dir.path()).expect("env");

        let n1 = Nibbles::from_nibbles_unchecked([0x01]);
        let b1 = BranchNodeCompact::new(0b1, 0, 0, vec![], Some(B256::random()));
        let n2 = Nibbles::from_nibbles_unchecked([0x02]);
        let n3 = Nibbles::from_nibbles_unchecked([0x03]);
        let b3 = BranchNodeCompact::new(0b1, 0, 0, vec![], Some(B256::random()));

        let updates = vec![(n2, None), (n1, Some(b1.clone())), (n3, Some(b3.clone()))];
        store.store_account_branches(B0, updates.clone()).await.expect("write");

        let tx = store.env.tx().expect("ro tx");
        let mut cur = tx.cursor_dup_read::<AccountTrieHistory>().expect("cursor");

        for (nibble, branch) in updates {
            let v = cur
                .seek_by_key_subkey(StoredNibbles::from(nibble), B0)
                .expect("seek")
                .expect("exists");
            assert_eq!(v.block_number, B0);
            assert_eq!(v.value.0, branch);
        }
    }

    #[tokio::test]
    async fn store_account_branches_multiple_calls() {
        let dir = TempDir::new().unwrap();
        let store = MdbxProofsStorage::new(dir.path()).expect("env");

        let n1 = Nibbles::from_nibbles_unchecked([0x01]);
        let b1 = BranchNodeCompact::new(0b1, 0, 0, vec![], Some(B256::random()));
        let n2 = Nibbles::from_nibbles_unchecked([0x02]);
        let n3 = Nibbles::from_nibbles_unchecked([0x03]);
        let b3 = BranchNodeCompact::new(0b1, 0, 0, vec![], Some(B256::random()));
        let n4 = Nibbles::from_nibbles_unchecked([0x04]);
        let b4 = BranchNodeCompact::new(0b1, 0, 0, vec![], Some(B256::random()));
        let n5 = Nibbles::from_nibbles_unchecked([0x05]);
        let b5 = BranchNodeCompact::new(0b1, 0, 0, vec![], Some(B256::random()));

        {
            let updates1 = vec![(n2, None), (n1, Some(b1.clone())), (n4, Some(b4.clone()))];
            store.store_account_branches(B0, updates1.clone()).await.expect("write");

            let tx = store.env.tx().expect("ro tx");
            let mut cur = tx.cursor_dup_read::<AccountTrieHistory>().expect("cursor");

            for (nibble, branch) in updates1 {
                let v = cur
                    .seek_by_key_subkey(StoredNibbles::from(nibble), B0)
                    .expect("seek")
                    .expect("exists");
                assert_eq!(v.block_number, B0);
                assert_eq!(v.value.0, branch);
            }
        }

        {
            // Second call
            let updates2 = vec![(n5, Some(b5.clone())), (n3, Some(b3.clone()))];
            store.store_account_branches(B0, updates2.clone()).await.expect("write");

            let tx = store.env.tx().expect("ro tx");
            let mut cur = tx.cursor_dup_read::<AccountTrieHistory>().expect("cursor");

            for (nibble, branch) in updates2 {
                let v = cur
                    .seek_by_key_subkey(StoredNibbles::from(nibble), B0)
                    .expect("seek")
                    .expect("exists");
                assert_eq!(v.block_number, B0);
                assert_eq!(v.value.0, branch);
            }
        }
    }

    #[tokio::test]
    async fn test_store_storage_branches_writes_versioned_values() {
        let dir = TempDir::new().unwrap();
        let store = MdbxProofsStorage::new(dir.path()).expect("env");

        let hashed_address = B256::random();
        let nibble = Nibbles::from_nibbles_unchecked([0x12, 0x34]);
        let branch_node = BranchNodeCompact::new(0b1, 0, 0, vec![], Some(B256::random()));
        let items = vec![(nibble, Some(branch_node.clone()))];

        store.store_storage_branches(B0, hashed_address, items).await.expect("write");

        let tx = store.env.tx().expect("ro tx");
        let mut cur = tx.cursor_dup_read::<StorageTrieHistory>().expect("cursor");

        let key = StorageTrieSubKey::new(hashed_address, StoredNibbles::from(nibble));
        let vv = cur.seek_by_key_subkey(key, B0).expect("seek").expect("entry exists");

        assert_eq!(vv.block_number, B0);
        assert_eq!(vv.value.0, Some(branch_node));
    }

    #[tokio::test]
    async fn store_storage_branches_multiple_items_unsorted() {
        let dir = TempDir::new().unwrap();
        let store = MdbxProofsStorage::new(dir.path()).expect("env");

        let hashed_address = B256::random();
        let n1 = Nibbles::from_nibbles_unchecked([0x01]);
        let b1 = BranchNodeCompact::new(0b1, 0, 0, vec![], Some(B256::random()));
        let n2 = Nibbles::from_nibbles_unchecked([0x02]);
        let n3 = Nibbles::from_nibbles_unchecked([0x03]);
        let b3 = BranchNodeCompact::new(0b1, 0, 0, vec![], Some(B256::random()));

        let items = vec![(n2, None), (n1, Some(b1.clone())), (n3, Some(b3.clone()))];
        store.store_storage_branches(B0, hashed_address, items.clone()).await.expect("write");

        let tx = store.env.tx().expect("ro tx");
        let mut cur = tx.cursor_dup_read::<StorageTrieHistory>().expect("cursor");

        for (nibble, branch) in items {
            let key = StorageTrieSubKey::new(hashed_address, StoredNibbles::from(nibble));
            let v = cur.seek_by_key_subkey(key, B0).expect("seek").expect("exists");
            assert_eq!(v.block_number, B0);
            assert_eq!(v.value.0, branch);
        }
    }

    #[tokio::test]
    async fn store_storage_branches_multiple_calls() {
        let dir = TempDir::new().unwrap();
        let store = MdbxProofsStorage::new(dir.path()).expect("env");

        let hashed_address = B256::random();
        let n1 = Nibbles::from_nibbles_unchecked([0x01]);
        let b1 = BranchNodeCompact::new(0b1, 0, 0, vec![], Some(B256::random()));
        let n2 = Nibbles::from_nibbles_unchecked([0x02]);
        let n3 = Nibbles::from_nibbles_unchecked([0x03]);
        let b3 = BranchNodeCompact::new(0b1, 0, 0, vec![], Some(B256::random()));
        let n4 = Nibbles::from_nibbles_unchecked([0x04]);
        let b4 = BranchNodeCompact::new(0b1, 0, 0, vec![], Some(B256::random()));
        let n5 = Nibbles::from_nibbles_unchecked([0x05]);
        let b5 = BranchNodeCompact::new(0b1, 0, 0, vec![], Some(B256::random()));

        {
            let items1 = vec![(n2, None), (n1, Some(b1.clone())), (n5, Some(b5.clone()))];
            store.store_storage_branches(B0, hashed_address, items1.clone()).await.expect("write");

            let tx = store.env.tx().expect("ro tx");
            let mut cur = tx.cursor_dup_read::<StorageTrieHistory>().expect("cursor");

            for (nibble, branch) in items1 {
                let key = StorageTrieSubKey::new(hashed_address, StoredNibbles::from(nibble));
                let v = cur.seek_by_key_subkey(key, B0).expect("seek").expect("exists");
                assert_eq!(v.block_number, B0);
                assert_eq!(v.value.0, branch);
            }
        }

        {
            // Second call
            let items2 = vec![(n4, Some(b4.clone())), (n3, Some(b3.clone()))];
            store.store_storage_branches(B0, hashed_address, items2.clone()).await.expect("write");

            let tx = store.env.tx().expect("ro tx");
            let mut cur = tx.cursor_dup_read::<StorageTrieHistory>().expect("cursor");

            for (nibble, branch) in items2 {
                let key = StorageTrieSubKey::new(hashed_address, StoredNibbles::from(nibble));
                let v = cur.seek_by_key_subkey(key, B0).expect("seek").expect("exists");
                assert_eq!(v.block_number, B0);
                assert_eq!(v.value.0, branch);
            }
        }
    }
}
