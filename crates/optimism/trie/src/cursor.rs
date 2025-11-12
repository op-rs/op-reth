//! Implementation of [`HashedCursor`] and [`TrieCursor`] for
//! [`OpProofsStorage`](crate::OpProofsStorage).

use crate::{OpProofsHashedCursorRO, OpProofsTrieCursorRO};
use alloy_primitives::{B256, U256};
use derive_more::{Constructor, From};
use reth_db::{
    common::{PairResult, ValueOnlyResult},
    cursor::DbDupCursorRO,
    mock::CursorMock,
    table::DupSort,
    DatabaseError,
};
use reth_primitives_traits::Account;
use reth_trie::{
    hashed_cursor::{HashedCursor, HashedStorageCursor},
    trie_cursor::TrieCursor,
    BranchNodeCompact, Nibbles,
};

/// Manages reading storage or account trie nodes from [`OpProofsTrieCursorRO`].
#[derive(Debug, Clone, Constructor, From)]
pub struct OpProofsTrieCursor<C: OpProofsTrieCursorRO>(pub C);

impl<C> TrieCursor for OpProofsTrieCursor<C>
where
    C: OpProofsTrieCursorRO,
{
    #[inline]
    fn seek_exact(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        Ok(self.0.seek_exact(key)?)
    }

    #[inline]
    fn seek(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        Ok(self.0.seek(key)?)
    }

    #[inline]
    fn next(&mut self) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        Ok(self.0.next()?)
    }

    #[inline]
    fn current(&mut self) -> Result<Option<Nibbles>, DatabaseError> {
        Ok(self.0.current()?)
    }
}

/// Manages reading hashed account nodes from external storage.
#[derive(Debug, Clone, Constructor)]
pub struct OpProofsHashedAccountCursor<C>(pub C);

impl<C> HashedCursor for OpProofsHashedAccountCursor<C>
where
    C: OpProofsHashedCursorRO<Value = Account> + Send + Sync,
{
    type Value = Account;

    #[inline]
    fn seek(&mut self, key: B256) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        Ok(self.0.seek(key)?)
    }

    #[inline]
    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        Ok(self.0.next()?)
    }
}

/// Manages reading hashed storage nodes from external storage.
#[derive(Debug, Clone, Constructor)]
pub struct OpProofsHashedStorageCursor<C>(pub C);

impl<C> HashedCursor for OpProofsHashedStorageCursor<C>
where
    C: OpProofsHashedCursorRO<Value = U256> + Send + Sync,
{
    type Value = U256;

    #[inline]
    fn seek(&mut self, key: B256) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        Ok(self.0.seek(key)?)
    }

    #[inline]
    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        Ok(self.0.next()?)
    }
}

impl<C> HashedStorageCursor for OpProofsHashedStorageCursor<C>
where
    C: OpProofsHashedCursorRO<Value = U256> + Send + Sync,
{
    #[inline]
    fn is_storage_empty(&mut self) -> Result<bool, DatabaseError> {
        Ok(self.0.is_storage_empty()?)
    }
}

/// Extension of [`DbDupCursorRO`] trait.
pub trait DbDupCursorROExt<T: DupSort>: DbDupCursorRO<T> {
    /// Positions the cursor at the prev KV pair of the table, returning it.
    fn prev_dup(&mut self) -> PairResult<T>;

    /// Positions the cursor at the last duplicate value of the current key.
    fn last_dup(&mut self) -> ValueOnlyResult<T>;
}

impl<T: DupSort> DbDupCursorROExt<T> for CursorMock {
    fn prev_dup(&mut self) -> PairResult<T> {
        Ok(None)
    }

    fn last_dup(&mut self) -> ValueOnlyResult<T> {
        Ok(None)
    }
}
