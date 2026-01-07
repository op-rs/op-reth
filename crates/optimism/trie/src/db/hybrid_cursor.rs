use crate::db::models::AddressLookup;
use alloy_primitives::{Address, B256, U256};
use derive_more::Constructor;
use reth_db::{
    cursor::{DbCursorRO, DbDupCursorRO},
    models::{storage_sharded_key::StorageShardedKey, BlockNumberAddress, ShardedKey},
    DatabaseError,
};
use reth_primitives_traits::Account;
use reth_trie::hashed_cursor::HashedCursor;

pub trait RethHistoryProvider {
    type Key;
    type Value;

    /// Latest value for `key` at or before `block`.
    fn latest_value_at(
        &mut self,
        key: Self::Key,
        block: u64,
    ) -> Result<Option<(Self::Key, Self::Value)>, DatabaseError> {
        Ok(None)
    }

    /// Next latest value at or before `block`.
    fn next_latest_value_at(
        &mut self,
        block: u64,
    ) -> Result<Option<(Self::Key, Self::Value)>, DatabaseError> {
        Ok(None)
    }
}

#[derive(Debug, Constructor)]
pub struct RethAccountProvider<H, C> {
    history: H,
    changes: C,
}

impl<H, C> RethHistoryProvider for RethAccountProvider<H, C>
where
    H: DbCursorRO<reth_db::AccountsHistory> + Send + Sync,
    C: DbCursorRO<reth_db::AccountChangeSets>
        + DbDupCursorRO<reth_db::AccountChangeSets>
        + Send
        + Sync,
{
    type Key = Address;
    type Value = Account;

    fn latest_value_at(
        &mut self,
        address: Address,
        block: u64,
    ) -> Result<Option<(Address, Account)>, DatabaseError> {
        let sk = ShardedKey::new(address, block);
        if let Some(history) = self.history.seek(sk)? {
            // Check we didn't land on different address
            if history.0.key != address {
                return Ok(None);
            }
            if let Some(target_block) = history.1.iter().take_while(|&v| v < block).last() {
                if let Some(res) = self.changes.seek_by_key_subkey(target_block, address)? {
                    if res.address != address {
                        return Ok(None);
                    }
                    if res.info.is_some() {
                        return Ok(Some((address, res.info.unwrap())));
                    }
                }
            }
        }
        Ok(None)
    }
}

#[derive(Debug, Constructor)]
pub struct RethStorageProvider<H, C> {
    history: H,
    changes: C,
}

impl<H, C> RethHistoryProvider for RethStorageProvider<H, C>
where
    H: DbCursorRO<reth_db::StoragesHistory> + Send + Sync,
    C: DbCursorRO<reth_db::StorageChangeSets>
        + DbDupCursorRO<reth_db::StorageChangeSets>
        + Send
        + Sync,
{
    type Key = (Address, B256);
    type Value = U256;

    fn latest_value_at(
        &mut self,
        key: Self::Key,
        block: u64,
    ) -> Result<Option<(Self::Key, Self::Value)>, DatabaseError> {
        let sk = StorageShardedKey::new(key.0, key.1, block);
        if let Some(history) = self.history.seek(sk)? {
            // Check we didn't land on different address
            if history.0.address != key.0 || history.0.sharded_key.key != key.1 {
                return Ok(None);
            }
            if let Some(target_block) = history.1.iter().take_while(|&v| v < block).last() {
                let pkey = BlockNumberAddress::from((target_block, history.0.address));
                if let Some(res) =
                    self.changes.seek_by_key_subkey(pkey, history.0.sharded_key.key)?
                {
                    if res.key != key.1 {
                        return Ok(None);
                    }
                    return Ok(Some((key, res.value)));
                }
            }
        }
        Ok(None)
    }

    fn next_latest_value_at(
        &mut self,
        block: u64,
    ) -> Result<Option<(Self::Key, Self::Value)>, DatabaseError> {
        while let Some(history) = self.history.next()? {
            if let Some(target_block) = history.1.iter().take_while(|&v| v < block).last() {
                let pkey = BlockNumberAddress::from((target_block, history.0.address));
                // Todo: Check whether we are getting pre state or post state value of the
                // target_block
                if let Some(res) =
                    self.changes.seek_by_key_subkey(pkey, history.0.sharded_key.key)?
                {
                    // Todo: Check whether we need to enforce the check for exact match
                    return Ok(Some(((history.0.address, history.0.sharded_key.key), res.value)));
                }
            }
        }
        Ok(None)
    }
}

/// MDBX implementation of [`HashedCursor`] for account state using the reth tables
#[derive(Debug, Constructor)]
pub struct RethAccountCursor<C, P> {
    block_number: u64,
    address_lookup_cursor: C,
    reth_provider: P,
}

impl<C, P> HashedCursor for RethAccountCursor<C, P>
where
    C: DbCursorRO<AddressLookup> + Send + Sync,
    P: RethHistoryProvider<Key = Address, Value = Account> + Send + Sync,
{
    type Value = Account;

    fn seek(&mut self, key: B256) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        if let Some((hash, address)) = self.address_lookup_cursor.seek(key)? {
            if let Some((_, v)) = self.reth_provider.latest_value_at(address, self.block_number)? {
                return Ok(Some((hash, v)));
            }
            return self.next();
        }
        Ok(None)
    }

    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        while let Some((hash, address)) = self.address_lookup_cursor.next()? {
            if let Some((_, v)) = self.reth_provider.latest_value_at(address, self.block_number)? {
                return Ok(Some((hash, v)));
            }
        }
        Ok(None)
    }

    fn reset(&mut self) {
        todo!()
    }
}

/// MDBX implementation of [`HashedCursor`] for storage state using the reth tables
#[derive(Debug, Constructor)]
pub struct RethStorageCursor<C, P> {
    block_number: u64,
    address: Address,
    address_lookup_cursor: C,
    reth_provider: P,
}

impl<C, P> HashedCursor for RethStorageCursor<C, P>
where
    C: DbCursorRO<AddressLookup> + Send + Sync,
    P: RethHistoryProvider<Key = (Address, B256), Value = U256> + Send + Sync,
{
    type Value = U256;

    fn seek(&mut self, key: B256) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        if let Some((k, v)) =
            self.reth_provider.latest_value_at((self.address, key), self.block_number)?
        {
            // TODO: return value must return the key as well because seek may diverge to next slot
            return Ok(Some((k.1, v)));
        }
        self.next()
    }

    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        Ok(self.reth_provider.next_latest_value_at(self.block_number)?.map(|(k, v)| (k.1, v)))
    }

    fn reset(&mut self) {
        todo!()
    }
}

pub enum HybridAccountHashedCursor<P, R> {
    ProofStorage(P),
    Reth(R),
}

impl<P, R> HashedCursor for HybridAccountHashedCursor<P, R>
where
    P: HashedCursor<Value = Account>,
    R: HashedCursor<Value = Account>,
{
    type Value = Account;

    fn seek(&mut self, key: B256) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        match self {
            Self::ProofStorage(c) => c.seek(key),
            Self::Reth(c) => c.seek(key),
        }
    }

    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, DatabaseError> {
        match self {
            Self::ProofStorage(c) => c.next(),
            Self::Reth(c) => c.next(),
        }
    }

    fn reset(&mut self) {
        match self {
            Self::ProofStorage(c) => c.reset(),
            Self::Reth(c) => c.reset(),
        }
    }
}
