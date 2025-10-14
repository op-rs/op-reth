use reth_trie::{Nibbles, BranchNodeCompact};
use reth_primitives_traits::Account;
use alloy_primitives::{B256, U256};
use crate::storage::{OpProofsHashedCursor, OpProofsStorageResult, OpProofsTrieCursor};

/// MDBX implementation of `OpProofsTrieCursor`.
#[derive(Debug)]
pub struct MdbxTrieCursor {}

impl OpProofsTrieCursor for MdbxTrieCursor {
    fn seek_exact(
        &mut self,
        _path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        unimplemented!()
    }

    fn seek(
        &mut self,
        _path: Nibbles,
    ) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        unimplemented!()
    }

    fn next(&mut self) -> OpProofsStorageResult<Option<(Nibbles, BranchNodeCompact)>> {
        unimplemented!()
    }

    fn current(&mut self) -> OpProofsStorageResult<Option<Nibbles>> {
        unimplemented!()
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