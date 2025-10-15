use std::marker::PhantomData;

use crate::{
    db::{
        AccountTrieHistory, MaybeDeleted, StorageTrieHistory, StorageTrieSubKey,
        VersionedValue,
    },
    OpProofsHashedCursor, OpProofsStorageError, OpProofsStorageResult, OpProofsTrieCursor,
};
use alloy_primitives::{B256, U256};
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO},
    table::{DupSort, Table},
};
use reth_primitives_traits::Account;
use reth_trie::{BranchNodeCompact, Nibbles, StoredNibbles};

/// Iterates versioned dup-sorted rows and returns the latest value (<= max_block_number),
/// skipping tombstones.
#[derive(Debug, Clone)]
pub struct BlockNumberVersionedCursor<T: Table + DupSort, Cursor> {
    _table: PhantomData<T>,
    cursor: Cursor,
    max_block_number: u64,
}

impl<V, T, Cursor> BlockNumberVersionedCursor<T, Cursor>
where
    T: Table<Value = VersionedValue<V>> + DupSort<SubKey = u64>,
    Cursor: DbCursorRO<T> + DbDupCursorRO<T>,
{
    const fn new(cursor: Cursor, max_block_number: u64) -> Self {
        Self { _table: PhantomData, cursor, max_block_number }
    }

    /// Resolve the latest version for `key` with block_number <= max_block_number.
    /// Strategy:
    /// - seek_by_key_subkey(key, max) gives first dup >= max.
    ///   - if exactly == max → it's our latest
    ///   - if > max → prev_dup() is latest < max (or None)
    /// - if no dup >= max:
    ///   - if key exists → last_dup() is latest < max
    ///   - else → None
    fn latest_version_for_key(
        &mut self,
        key: T::Key,
    ) -> OpProofsStorageResult<Option<(T::Key, T::Value)>> {
        // First dup with subkey >= max_block_number
        let seek_res = self
            .cursor
            .seek_by_key_subkey(key.clone(), self.max_block_number)
            .map_err(|e| OpProofsStorageError::Other(e.into()))?;

        if let Some(vv) = seek_res {
            if vv.block_number > self.max_block_number {
                // step back to the last dup < max
                return self.cursor.prev_dup().map_err(|e| OpProofsStorageError::Other(e.into()));
            }
            // already at the dup = max
            return Ok(Some((key, vv)))
        }

        // No dup >= max ⇒ either key absent or all dups < max. Check if key exists:
        if self
            .cursor
            .seek_exact(key.clone())
            .map_err(|e| OpProofsStorageError::Other(e.into()))?
            .is_none()
        {
            return Ok(None);
        }

        // Key exists ⇒ take last dup (< max).
        if let Some(vv) =
            self.cursor.last_dup().map_err(|e| OpProofsStorageError::Other(e.into()))?
        {
            return Ok(Some((key, vv)))
        }
        Ok(None)
    }

    /// Returns a non-deleted latest version for exactly `key`, if any.
    fn seek_exact(&mut self, key: T::Key) -> OpProofsStorageResult<Option<(T::Key, V)>> {
        if let Some((latest_key, latest_value)) = self.latest_version_for_key(key)? &&
            let MaybeDeleted(Some(v)) = latest_value.value
        {
            return Ok(Some((latest_key, v)));
        }
        Ok(None)
    }

    /// Seek to the first non-deleted latest version at or after `start_key`.
    /// Logic:
    /// - Try exact key first (above). If alive, return it.
    /// - Otherwise hop to next distinct key and repeat until we find a live version or hit EOF.
    fn seek(&mut self, start_key: T::Key) -> OpProofsStorageResult<Option<(T::Key, V)>> {
        if let Some(pair) = self.seek_exact(start_key)? {
            return Ok(Some(pair));
        }
        self.next()
    }

    /// Advance to the next distinct key from the current MDBX position
    /// and return its non-deleted latest version, if any.
    fn next(&mut self) -> OpProofsStorageResult<Option<(T::Key, V)>> {
        loop {
            let Some((next_key, _)) =
                self.cursor.next_no_dup().map_err(|e| OpProofsStorageError::Other(e.into()))?
            else {
                // No more keys
                return Ok(None);
            };
            // Now get the latest value for this key that's <= max_block_number
            if let Some(result) = self.seek_exact(next_key)? {
                return Ok(Some(result));
            }
        }
    }
}

/// MDBX implementation of `OpProofsTrieCursor`.
#[derive(Debug)]
pub struct MdbxTrieCursor<T: Table + DupSort, Cursor> {
    inner: BlockNumberVersionedCursor<T, Cursor>,
    hashed_address: Option<B256>,
}

impl<
        V,
        T: Table<Value = VersionedValue<V>> + DupSort<SubKey = u64>,
        Cursor: DbCursorRO<T> + DbDupCursorRO<T>,
    > MdbxTrieCursor<T, Cursor>
{
    pub(crate) fn new(cursor: Cursor, max_block_number: u64, hashed_address: Option<B256>) -> Self {
        Self { inner: BlockNumberVersionedCursor::new(cursor, max_block_number), hashed_address }
    }
}

impl<Cursor> OpProofsTrieCursor for MdbxTrieCursor<AccountTrieHistory, Cursor>
where
    Cursor: DbCursorRO<AccountTrieHistory> + DbDupCursorRO<AccountTrieHistory> + Send + Sync,
{
    fn seek_exact(
        &mut self,
        path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        self.inner
            .seek_exact(StoredNibbles(path))
            .map(|opt| opt.map(|(StoredNibbles(n), node)| (n, node)))
    }

    fn seek(
        &mut self,
        path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        self.inner
            .seek(StoredNibbles(path))
            .map(|opt| opt.map(|(StoredNibbles(n), node)| (n, node)))
    }

    fn next(&mut self) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        self.inner.next().map(|opt| opt.map(|(StoredNibbles(n), node)| (n, node)))
    }

    fn current(&mut self) -> OpProofsStorageResult<Option<Nibbles>> {
        self.inner
            .cursor
            .current()
            .map_err(|e| OpProofsStorageError::Other(e.into()))
            .map(|opt| opt.map(|(StoredNibbles(n), _)| n))
    }
}

impl<Cursor> OpProofsTrieCursor for MdbxTrieCursor<StorageTrieHistory, Cursor>
where
    Cursor: DbCursorRO<StorageTrieHistory> + DbDupCursorRO<StorageTrieHistory> + Send + Sync,
{
    fn seek_exact(
        &mut self,
        path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        if let Some(address) = self.hashed_address {
            let key = StorageTrieSubKey::new(address, StoredNibbles(path));
            return self.inner.seek_exact(key).map(|opt| {
                opt.and_then(|(k, node)| (k.hashed_address == address).then(|| (k.path.0, node)))
            })
        }
        Ok(None)
    }

    fn seek(
        &mut self,
        path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        if let Some(address) = self.hashed_address {
            let key = StorageTrieSubKey::new(address, StoredNibbles(path));
            return self.inner.seek(key).map(|opt| opt.map(|(k, node)| (k.path.0, node)))
        }
        Ok(None)
    }

    fn next(&mut self) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        if let Some(address) = self.hashed_address {
            return self.inner.next().map(|opt| {
                opt.and_then(|(k, node)| (k.hashed_address == address).then(|| (k.path.0, node)))
            })
        }
        Ok(None)
    }

    fn current(&mut self) -> OpProofsStorageResult<Option<Nibbles>> {
        self.inner
            .cursor
            .current()
            .map_err(|e| OpProofsStorageError::Other(e.into()))
            .map(|opt| opt.map(|(k, _)| k.path.0))
    }
}

/// MDBX implementation of `OpProofsHashedCursor` for storage state.
#[derive(Debug)]
pub struct MdbxStorageCursor {}

impl OpProofsHashedCursor for MdbxStorageCursor {
    type Value = U256;

    fn seek(&mut self, _key: B256) -> OpProofsStorageResult<Option<(B256, Self::Value)>> {
        unimplemented!()
    }

    fn next(&mut self) -> OpProofsStorageResult<Option<(B256, Self::Value)>> {
        unimplemented!()
    }
}

/// MDBX implementation of `OpProofsHashedCursor` for account state.
#[derive(Debug)]
pub struct MdbxAccountCursor {}

impl OpProofsHashedCursor for MdbxAccountCursor {
    type Value = Account;

    fn seek(&mut self, _key: B256) -> OpProofsStorageResult<Option<(B256, Self::Value)>> {
        unimplemented!()
    }

    fn next(&mut self) -> OpProofsStorageResult<Option<(B256, Self::Value)>> {
        unimplemented!()
    }
}
