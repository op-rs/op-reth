//! Backfill job for proofs storage. Handles storing the existing state into the proofs storage.

use super::storage::OpProofsStorage;
use alloy_primitives::{b256, B256, U256};
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO},
    tables,
    transaction::DbTx,
    DatabaseError,
};
use reth_primitives_traits::{Account, StorageEntry};
use reth_provider::DBProvider;
use reth_trie::{BranchNodeCompact, Nibbles, StorageTrieEntry, StoredNibbles, StoredNibblesSubKey};
use std::{collections::HashMap, fmt::Debug, time::Instant};
use tracing::info;

/// Batch size threshold for storing entries during backfill
/// Reduced to avoid excessive memory usage in MDBX transactions
const BACKFILL_STORAGE_THRESHOLD: usize = 10000;

/// Threshold for logging progress during backfill
const BACKFILL_LOG_THRESHOLD: usize = 100000;

/// Threshold for recreating cursors to prevent long-lived read transactions
const CURSOR_RECREATION_THRESHOLD: usize = 1_000_000;

/// Backfill job for external storage.
#[derive(Debug)]
pub struct BackfillJob<'a, Provider, S: OpProofsStorage + Send> {
    storage: &'a S,
    provider: &'a Provider,
}

/// Macro to generate simple cursor iterators for tables
macro_rules! define_simple_cursor_iter {
    ($iter_name:ident, $table:ty, $key_type:ty, $value_type:ty) => {
        struct $iter_name<C>(C);

        impl<C> $iter_name<C> {
            const fn new(cursor: C) -> Self {
                Self(cursor)
            }
        }

        impl<C: DbCursorRO<$table>> Iterator for $iter_name<C> {
            type Item = Result<($key_type, $value_type), DatabaseError>;

            fn next(&mut self) -> Option<Self::Item> {
                self.0.next().transpose()
            }
        }
    };
}

// Generate iterators for all 4 table types
define_simple_cursor_iter!(HashedAccountsIter, tables::HashedAccounts, B256, Account);
define_simple_cursor_iter!(HashedStoragesIter, tables::HashedStorages, B256, StorageEntry);
define_simple_cursor_iter!(
    AccountsTrieIter,
    tables::AccountsTrie,
    StoredNibbles,
    BranchNodeCompact
);
define_simple_cursor_iter!(StoragesTrieIter, tables::StoragesTrie, B256, StorageTrieEntry);

// Create an iterator for HashedStorages that also returns the storage key
struct HashedStoragesIterWithStorageKey<C>(HashedStoragesIter<C>);

impl<C> HashedStoragesIterWithStorageKey<C> {
    const fn new(cursor: HashedStoragesIter<C>) -> Self {
        Self(cursor)
    }
}

impl<C: DbDupCursorRO<tables::HashedStorages> + DbCursorRO<tables::HashedStorages>> Iterator
    for HashedStoragesIterWithStorageKey<C>
{
    type Item = Result<((B256, B256), U256), DatabaseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let Some(Ok((address, entry))) = self.0.next() else {
            return None;
        };
        Some(Ok(((address, entry.key), entry.value)))
    }
}

// Create an iterator for StoragesTrie that also returns the storage key
struct StoragesTrieIterWithStorageKey<C>(StoragesTrieIter<C>);

impl<C> StoragesTrieIterWithStorageKey<C> {
    const fn new(cursor: StoragesTrieIter<C>) -> Self {
        Self(cursor)
    }
}

impl<C: DbDupCursorRO<tables::StoragesTrie> + DbCursorRO<tables::StoragesTrie>> Iterator
    for StoragesTrieIterWithStorageKey<C>
{
    type Item = Result<((B256, Nibbles), BranchNodeCompact), DatabaseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let Some(Ok((address, entry))) = self.0.next() else {
            return None;
        };
        Some(Ok(((address, entry.nibbles.0), entry.node)))
    }
}
/// Trait to estimate the progress of a backfill job based on the key.
trait CompletionEstimatable {
    // Returns a progress estimate as a percentage (0.0 to 1.0)
    fn estimate_progress(&self) -> f64;
}

impl CompletionEstimatable for B256 {
    fn estimate_progress(&self) -> f64 {
        // use the first 3 bytes as a progress estimate
        let progress = self.0[..3].to_vec();
        let mut val: u64 = 0;
        for nibble in &progress {
            val = (val << 8) | *nibble as u64;
        }
        val as f64 / (256u64.pow(3)) as f64
    }
}

impl CompletionEstimatable for StoredNibbles {
    fn estimate_progress(&self) -> f64 {
        // use the first 6 nibbles as a progress estimate
        let progress_nibbles =
            if self.0.is_empty() { Nibbles::new() } else { self.0.slice(0..(self.0.len().min(6))) };
        let mut val: u64 = 0;
        for nibble in progress_nibbles.iter() {
            val = (val << 4) | nibble as u64;
        }
        val as f64 / (16u64.pow(progress_nibbles.len() as u32)) as f64
    }
}

impl<T> CompletionEstimatable for (B256, T) {
    fn estimate_progress(&self) -> f64 {
        // use the first 3 bytes of the hashed account address as a progress estimate
        self.0.estimate_progress()
    }
}

/// Backfill a table from a source iterator to a storage function. Handles batching and logging.
/// Returns the last key processed (if any) for potential resumption.
async fn backfill<
    S: Iterator<Item = Result<(Key, Value), DatabaseError>>,
    F: Future<Output = eyre::Result<()>> + Send,
    Key: CompletionEstimatable + Clone + Debug + 'static,
    Value: Clone + Debug + 'static,
>(
    name: &str,
    source: S,
    storage_threshold: usize,
    log_threshold: usize,
    cursor_recreation_threshold: usize,
    save_fn: impl Fn(Vec<(Key, Value)>) -> F,
) -> eyre::Result<(u64, Option<Key>)> {
    let mut entries = Vec::new();
    let mut total_entries: u64 = 0;
    let mut entries_since_cursor_recreation: usize = 0;

    info!("Starting {} backfill", name);
    let start_time = Instant::now();

    let mut source = source.peekable();
    let initial_progress = source
        .peek()
        .map(|entry| entry.clone().map(|entry| entry.0.estimate_progress()))
        .transpose()?;

    for entry in source {
        let Some(initial_progress) = initial_progress else {
            // If there are any items, there must be an initial progress
            unreachable!();
        };
        let entry = entry?;

        entries.push(entry.clone());
        total_entries += 1;
        entries_since_cursor_recreation += 1;
        let last_key = &entry.0;

        if total_entries.is_multiple_of(log_threshold as u64) {
            let progress = entry.0.estimate_progress();
            let elapsed = start_time.elapsed();
            let elapsed_secs = elapsed.as_secs_f64();

            let progress_per_second = if elapsed_secs.is_normal() {
                (progress - initial_progress) / elapsed_secs
            } else {
                0.0
            };
            let estimated_total_time = if progress_per_second.is_normal() {
                (1.0 - progress) / progress_per_second
            } else {
                0.0
            };
            let progress_pct = progress * 100.0;
            info!(
                "Processed {} {}, progress: {progress_pct:.2}%, ETA: {}s",
                name, total_entries, estimated_total_time,
            );
        }

        // Signal cursor recreation needed
        if entries_since_cursor_recreation >= cursor_recreation_threshold {
            println!(
                "{} backfill: processed {} entries, cursor recreation suggested",
                name, total_entries
            );
            // info!(
            //     "{} backfill: processed {} entries, cursor recreation suggested",
            //     name, total_entries
            // );
            // Save any pending entries before signaling recreation
            if !entries.is_empty() {
                save_fn(entries).await?;
                return Ok((total_entries, Some(last_key.clone())));
            }
        }

        if entries.len() >= storage_threshold {
            println!("Storing {} entries, total entries: {}", name, total_entries);
            save_fn(entries).await?;
            entries = Vec::new();
        }
    }

    if !entries.is_empty() {
        info!("Storing final {} entries", name);
        save_fn(entries).await?;
    }

    info!("{} backfill segment complete: {} entries", name, total_entries);
    Ok((total_entries, None))
}

impl<'a, Provider, S> BackfillJob<'a, Provider, S>
where
    Provider: reth_provider::DatabaseProviderFactory,
    <Provider as reth_provider::DatabaseProviderFactory>::Provider: DBProvider,
    S: OpProofsStorage + Send,
{
    /// Create a new backfill job.
    pub const fn new(storage: &'a S, provider: &'a Provider) -> Self {
        Self { storage, provider }
    }

    /// Backfill hashed accounts data
    async fn backfill_hashed_accounts(&self) -> eyre::Result<()> {
        let mut total_processed = 0u64;
        let last_key: Option<B256> = self.storage.get_last_stored_hashed_account().await?;

        let mut cursor = self
            .provider
            .database_provider_ro()?
            .tx_ref()
            .cursor_read::<tables::HashedAccounts>()?;

        // Seek to last processed key if resuming
        if let Some(ref key) = last_key {
            cursor.seek(*key)?;
        }

        loop {
            let source = HashedAccountsIter::new(cursor);
            let save_fn = async |entries: Vec<(B256, Account)>| -> eyre::Result<()> {
                self.storage
                    .store_hashed_accounts(
                        entries
                            .into_iter()
                            .map(|(address, account)| (address, Some(account)))
                            .collect(),
                        0,
                    )
                    .await?;
                Ok(())
            };

            let (processed, new_last_key) = backfill(
                "hashed accounts",
                source,
                BACKFILL_STORAGE_THRESHOLD,
                BACKFILL_LOG_THRESHOLD,
                CURSOR_RECREATION_THRESHOLD,
                save_fn,
            )
            .await?;

            total_processed += processed;

            // If we got a last key, we need to recreate cursor and continue
            if let Some(key) = new_last_key {
                info!(
                    "Recreating cursor for hashed accounts, total processed: {}",
                    total_processed
                );

                cursor = self
                    .provider
                    .database_provider_ro()?
                    .tx_ref()
                    .cursor_read::<tables::HashedAccounts>()?;

                cursor.seek(key)?;
            } else {
                // No more entries, we're done
                break;
            }
        }

        info!("Hashed accounts backfill complete: {} total entries", total_processed);
        Ok(())
    }

    /// Backfill hashed storage data
    async fn backfill_hashed_storages(&self) -> eyre::Result<()> {
        let mut total_processed = 0u64;

        let last_key: Option<(B256, B256)> = self.storage.get_last_stored_hashed_storage().await?;

        let mut cursor = self
            .provider
            .database_provider_ro()?
            .tx_ref()
            .cursor_dup_read::<tables::HashedStorages>()?;

        if let Some(ref key) = last_key {
            info!("Seeking to last processed key for hashed storage: {:?}", key);
            cursor.seek_by_key_subkey(key.0, key.1)?;
        }

        loop {
            let source = HashedStoragesIterWithStorageKey::new(HashedStoragesIter::new(cursor));
            let save_fn = async |entries: Vec<((B256, B256), U256)>| -> eyre::Result<()> {
                info!("Saving {} entries for hashed storage", entries.len());
                info!("first entry key: {:?}", entries[0].0);
                info!("last entry key: {:?}", entries[entries.len() - 1].0);
                // Group entries by hashed address
                let mut by_address: HashMap<B256, Vec<(B256, alloy_primitives::U256)>> =
                    HashMap::default();
                for ((address, storage_key), value) in entries {
                    by_address.entry(address).or_default().push((storage_key, value));
                }

                // Store each address's storage entries
                for (address, storages) in by_address {
                    self.storage.store_hashed_storages(address, storages, 0).await?;
                }
                Ok(())
            };

            let (processed, new_last_key) = backfill(
                "hashed storage",
                source,
                BACKFILL_STORAGE_THRESHOLD,
                BACKFILL_LOG_THRESHOLD,
                CURSOR_RECREATION_THRESHOLD,
                save_fn,
            )
            .await?;

            println!("Processed {} entries for hashed storage", processed);

            total_processed += processed;

            // If we got a last key, we need to recreate cursor and continue
            if let Some(key) = new_last_key {
                println!(
                    "Recreating cursor for hashed storage, total processed: {}",
                    total_processed
                );

                cursor = self
                    .provider
                    .database_provider_ro()?
                    .tx_ref()
                    .cursor_dup_read::<tables::HashedStorages>()?;

                cursor.seek_by_key_subkey(key.0, key.1)?;
            } else {
                // No more entries, we're done
                break;
            }
        }

        info!("Hashed storage backfill complete: {} total entries", total_processed);
        Ok(())
    }

    /// Backfill accounts trie data
    async fn backfill_accounts_trie(&self) -> eyre::Result<()> {
        let mut total_processed = 0u64;
        let last_key: Option<Nibbles> = self.storage.get_last_stored_account_branch().await?;

        let mut cursor =
            self.provider.database_provider_ro()?.tx_ref().cursor_read::<tables::AccountsTrie>()?;

        if let Some(ref key) = last_key {
            cursor.seek(StoredNibbles(key.clone()))?;
        }

        loop {
            let source = AccountsTrieIter::new(cursor);
            let save_fn =
                async |entries: Vec<(StoredNibbles, BranchNodeCompact)>| -> eyre::Result<()> {
                    self.storage
                        .store_account_branches(
                            0,
                            entries
                                .into_iter()
                                .map(|(path, branch)| (path.0, Some(branch)))
                                .collect(),
                        )
                        .await?;
                    Ok(())
                };

            let (processed, new_last_key) = backfill(
                "accounts trie",
                source,
                BACKFILL_STORAGE_THRESHOLD,
                BACKFILL_LOG_THRESHOLD,
                CURSOR_RECREATION_THRESHOLD,
                save_fn,
            )
            .await?;

            total_processed += processed;

            // If we got a last key, we need to recreate cursor and continue
            if let Some(key) = new_last_key {
                info!("Recreating cursor for accounts trie, total processed: {}", total_processed);

                cursor = self
                    .provider
                    .database_provider_ro()?
                    .tx_ref()
                    .cursor_read::<tables::AccountsTrie>()?;

                cursor.seek(StoredNibbles(key.0.clone()))?;
            } else {
                // No more entries, we're done
                break;
            }
        }

        info!("Accounts trie backfill complete: {} total entries", total_processed);
        Ok(())
    }

    /// Backfill storage trie data
    async fn backfill_storages_trie(&self) -> eyre::Result<()> {
        let mut total_processed = 0u64;
        let last_key: Option<(B256, Nibbles)> =
            self.storage.get_last_stored_storage_branch().await?;

        let mut cursor = self
            .provider
            .database_provider_ro()?
            .tx_ref()
            .cursor_dup_read::<tables::StoragesTrie>()?;

        // Seek to last processed key if resuming
        if let Some(ref key) = last_key {
            cursor.seek_by_key_subkey(key.0, StoredNibblesSubKey(key.1))?;
        }
        loop {
            let source = StoragesTrieIter::new(cursor);
            let source = StoragesTrieIterWithStorageKey::new(source);
            let save_fn =
                async |entries: Vec<((B256, Nibbles), BranchNodeCompact)>| -> eyre::Result<()> {
                    // Group entries by hashed address
                    let mut by_address: HashMap<B256, Vec<(Nibbles, Option<BranchNodeCompact>)>> =
                        HashMap::default();
                    for ((hashed_address, storage_path), branch) in entries {
                        by_address
                            .entry(hashed_address)
                            .or_default()
                            .push((storage_path, Some(branch)));
                    }

                    // Store each address's storage trie branches
                    for (address, branches) in by_address {
                        self.storage.store_storage_branches(0, address, branches).await?;
                    }
                    Ok(())
                };

            let (processed, new_last_key) = backfill(
                "storage trie",
                source,
                BACKFILL_STORAGE_THRESHOLD,
                BACKFILL_LOG_THRESHOLD,
                CURSOR_RECREATION_THRESHOLD,
                save_fn,
            )
            .await?;

            total_processed += processed;

            // If we got a last key, we need to recreate cursor and continue
            if let Some(key) = new_last_key {
                info!("Recreating cursor for storage trie, total processed: {}", total_processed);

                cursor = self
                    .provider
                    .database_provider_ro()?
                    .tx_ref()
                    .cursor_dup_read::<tables::StoragesTrie>()?;

                cursor.seek_by_key_subkey(key.0, StoredNibblesSubKey(key.1))?;
            } else {
                // No more entries, we're done
                break;
            }
        }

        info!("Storage trie backfill complete: {} total entries", total_processed);
        Ok(())
    }

    /// Run complete backfill of all preimage data
    async fn backfill_trie(&self) -> eyre::Result<()> {
        // 0xfa20ab5b5127e4d3eff33dfa7aef06cd9c821eccf7307445e6df385a8a7e99fa, storage key =
        // b05289c3e8a3470d3ec787e451bc5dca755037715bf1d8bd0f667fc6fc381cf5

        self.backfill_accounts_trie().await?;
        self.backfill_storages_trie().await?;
        self.backfill_hashed_accounts().await?;
        self.backfill_hashed_storages().await?;

        Ok(())
    }

    /// Run the backfill job.
    pub async fn run(&self, best_number: u64, best_hash: B256) -> eyre::Result<()> {
        if self.storage.get_earliest_block_number().await?.is_none() {
            self.backfill_trie().await?;

            self.storage.set_earliest_block_number(best_number, best_hash).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        in_memory::InMemoryProofsStorage,
        storage::{OpProofsHashedCursor, OpProofsTrieCursor},
    };
    use alloy_primitives::{keccak256, Address, U256};
    use reth_db::Database;
    use reth_db_api::{cursor::DbCursorRW, transaction::DbTxMut};
    use reth_primitives_traits::Account;
    use reth_provider::{test_utils::create_test_provider_factory, DatabaseProviderFactory};
    use reth_trie::{BranchNodeCompact, StorageTrieEntry, StoredNibbles, StoredNibblesSubKey};
    use std::sync::Arc;

    /// Helper function to create a test branch node
    fn create_test_branch_node() -> BranchNodeCompact {
        let mut state_mask = reth_trie::TrieMask::default();
        state_mask.set_bit(0);
        state_mask.set_bit(1);

        BranchNodeCompact {
            state_mask,
            tree_mask: reth_trie::TrieMask::default(),
            hash_mask: reth_trie::TrieMask::default(),
            hashes: Arc::new(vec![]),
            root_hash: None,
        }
    }

    #[tokio::test]
    async fn test_backfill_hashed_accounts() {
        let provider = create_test_provider_factory();
        let db = provider.db_ref();
        let storage = InMemoryProofsStorage::new();

        // Insert test accounts into database
        let tx = db.tx_mut().unwrap();
        let mut cursor = tx.cursor_write::<tables::HashedAccounts>().unwrap();

        let mut accounts = vec![
            (
                keccak256(Address::repeat_byte(0x01)),
                Account { nonce: 1, balance: U256::from(100), bytecode_hash: None },
            ),
            (
                keccak256(Address::repeat_byte(0x02)),
                Account { nonce: 2, balance: U256::from(200), bytecode_hash: None },
            ),
            (
                keccak256(Address::repeat_byte(0x03)),
                Account { nonce: 3, balance: U256::from(300), bytecode_hash: None },
            ),
        ];

        // Sort accounts by address for cursor.append (which requires sorted order)
        accounts.sort_by_key(|(addr, _)| *addr);

        for (addr, account) in &accounts {
            cursor.append(*addr, account).unwrap();
        }
        drop(cursor);
        tx.commit().unwrap();

        // Run backfill
        let job = BackfillJob::new(&storage, &provider);
        job.backfill_hashed_accounts().await.unwrap();

        // Verify data was stored (will be in sorted order)
        let mut account_cursor = storage.account_hashed_cursor(100).unwrap();
        let mut count = 0;
        while let Some((key, account)) = account_cursor.next().unwrap() {
            // Find matching account in our test data
            let expected = accounts.iter().find(|(addr, _)| *addr == key).unwrap();
            assert_eq!((key, account), *expected);
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_backfill_hashed_storage() {
        let provider = create_test_provider_factory();
        let db = provider.db_ref();
        let storage = InMemoryProofsStorage::new();

        // Insert test storage into database
        let tx = db.tx_mut().unwrap();
        let mut cursor = tx.cursor_dup_write::<tables::HashedStorages>().unwrap();

        let addr1 = keccak256(Address::repeat_byte(0x01));
        let addr2 = keccak256(Address::repeat_byte(0x02));

        let storage_entries = vec![
            (
                addr1,
                StorageEntry { key: keccak256(B256::repeat_byte(0x10)), value: U256::from(100) },
            ),
            (
                addr1,
                StorageEntry { key: keccak256(B256::repeat_byte(0x20)), value: U256::from(200) },
            ),
            (
                addr2,
                StorageEntry { key: keccak256(B256::repeat_byte(0x30)), value: U256::from(300) },
            ),
        ];

        for (addr, entry) in &storage_entries {
            cursor.upsert(*addr, entry).unwrap();
        }
        drop(cursor);
        tx.commit().unwrap();

        // Run backfill
        let job = BackfillJob::new(&storage, &provider);
        job.backfill_hashed_storages().await.unwrap();

        // Verify data was stored for addr1
        let mut storage_cursor = storage.storage_hashed_cursor(addr1, 100).unwrap();
        let mut found = vec![];
        while let Some((key, value)) = storage_cursor.next().unwrap() {
            found.push((key, value));
        }
        assert_eq!(found.len(), 2);
        assert_eq!(found[0], (storage_entries[0].1.key, storage_entries[0].1.value));
        assert_eq!(found[1], (storage_entries[1].1.key, storage_entries[1].1.value));

        // Verify data was stored for addr2
        let mut storage_cursor = storage.storage_hashed_cursor(addr2, 100).unwrap();
        let mut found = vec![];
        while let Some((key, value)) = storage_cursor.next().unwrap() {
            found.push((key, value));
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], (storage_entries[2].1.key, storage_entries[2].1.value));
    }

    #[tokio::test]
    async fn test_backfill_accounts_trie() {
        let provider = create_test_provider_factory();
        let db = provider.db_ref();
        let storage = InMemoryProofsStorage::new();

        // Insert test trie nodes into database
        let tx = db.tx_mut().unwrap();
        let mut cursor = tx.cursor_write::<tables::AccountsTrie>().unwrap();

        let branch = create_test_branch_node();
        let nodes = vec![
            (StoredNibbles(Nibbles::from_nibbles_unchecked(vec![1])), branch.clone()),
            (StoredNibbles(Nibbles::from_nibbles_unchecked(vec![2])), branch.clone()),
            (StoredNibbles(Nibbles::from_nibbles_unchecked(vec![3])), branch.clone()),
        ];

        for (path, node) in &nodes {
            cursor.append(path.clone(), node).unwrap();
        }
        drop(cursor);
        tx.commit().unwrap();

        // Run backfill
        let job = BackfillJob::new(&storage, &provider);
        job.backfill_accounts_trie().await.unwrap();

        // Verify data was stored
        let mut trie_cursor = storage.account_trie_cursor(100).unwrap();
        let mut count = 0;
        while let Some((path, _node)) = trie_cursor.next().unwrap() {
            assert_eq!(path, nodes[count].0 .0);
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_backfill_storages_trie() {
        let provider = create_test_provider_factory();
        let db = provider.db_ref();
        let storage = InMemoryProofsStorage::new();

        // Insert test storage trie nodes into database
        let tx = db.tx_mut().unwrap();
        let mut cursor = tx.cursor_dup_write::<tables::StoragesTrie>().unwrap();

        let branch = create_test_branch_node();
        let addr1 = keccak256(Address::repeat_byte(0x01));
        let addr2 = keccak256(Address::repeat_byte(0x02));

        let nodes = vec![
            (
                addr1,
                StorageTrieEntry {
                    nibbles: StoredNibblesSubKey(Nibbles::from_nibbles_unchecked(vec![1])),
                    node: branch.clone(),
                },
            ),
            (
                addr1,
                StorageTrieEntry {
                    nibbles: StoredNibblesSubKey(Nibbles::from_nibbles_unchecked(vec![2])),
                    node: branch.clone(),
                },
            ),
            (
                addr2,
                StorageTrieEntry {
                    nibbles: StoredNibblesSubKey(Nibbles::from_nibbles_unchecked(vec![3])),
                    node: branch.clone(),
                },
            ),
        ];

        for (addr, entry) in &nodes {
            cursor.upsert(*addr, entry).unwrap();
        }
        drop(cursor);
        tx.commit().unwrap();

        // Run backfill
        let job = BackfillJob::new(&storage, &provider);
        job.backfill_storages_trie().await.unwrap();

        // Verify data was stored for addr1
        let mut trie_cursor = storage.storage_trie_cursor(addr1, 100).unwrap();
        let mut found = vec![];
        while let Some((path, _node)) = trie_cursor.next().unwrap() {
            found.push(path);
        }
        assert_eq!(found.len(), 2);
        assert_eq!(found[0], nodes[0].1.nibbles.0);
        assert_eq!(found[1], nodes[1].1.nibbles.0);

        // Verify data was stored for addr2
        let mut trie_cursor = storage.storage_trie_cursor(addr2, 100).unwrap();
        let mut found = vec![];
        while let Some((path, _node)) = trie_cursor.next().unwrap() {
            found.push(path);
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], nodes[2].1.nibbles.0);
    }

    #[tokio::test]
    async fn test_full_backfill_run() {
        let provider = create_test_provider_factory();
        let db = provider.db_ref();
        let storage = InMemoryProofsStorage::new();

        // Insert some test data
        let tx = db.tx_mut().unwrap();

        // Add accounts
        let mut cursor = tx.cursor_write::<tables::HashedAccounts>().unwrap();
        let addr = keccak256(Address::repeat_byte(0x01));
        cursor
            .append(addr, &Account { nonce: 1, balance: U256::from(100), bytecode_hash: None })
            .unwrap();
        drop(cursor);

        // Add storage
        let mut cursor = tx.cursor_dup_write::<tables::HashedStorages>().unwrap();
        cursor
            .upsert(
                addr,
                &StorageEntry { key: keccak256(B256::repeat_byte(0x10)), value: U256::from(100) },
            )
            .unwrap();
        drop(cursor);

        // Add account trie
        let mut cursor = tx.cursor_write::<tables::AccountsTrie>().unwrap();
        cursor
            .append(
                StoredNibbles(Nibbles::from_nibbles_unchecked(vec![1])),
                &create_test_branch_node(),
            )
            .unwrap();
        drop(cursor);

        // Add storage trie
        let mut cursor = tx.cursor_dup_write::<tables::StoragesTrie>().unwrap();
        cursor
            .upsert(
                addr,
                &StorageTrieEntry {
                    nibbles: StoredNibblesSubKey(Nibbles::from_nibbles_unchecked(vec![1])),
                    node: create_test_branch_node(),
                },
            )
            .unwrap();
        drop(cursor);

        tx.commit().unwrap();

        // Run full backfill
        let job = BackfillJob::new(&storage, &provider);
        let best_number = 100;
        let best_hash = B256::repeat_byte(0x42);

        // Should be None initially
        assert_eq!(storage.get_earliest_block_number().await.unwrap(), None);

        job.run(best_number, best_hash).await.unwrap();

        // Should be set after backfill
        assert_eq!(
            storage.get_earliest_block_number().await.unwrap(),
            Some((best_number, best_hash))
        );

        // Verify data was backfilled
        let mut account_cursor = storage.account_hashed_cursor(100).unwrap();
        assert!(account_cursor.next().unwrap().is_some());

        let mut storage_cursor = storage.storage_hashed_cursor(addr, 100).unwrap();
        assert!(storage_cursor.next().unwrap().is_some());

        let mut trie_cursor = storage.account_trie_cursor(100).unwrap();
        assert!(trie_cursor.next().unwrap().is_some());

        let mut storage_trie_cursor = storage.storage_trie_cursor(addr, 100).unwrap();
        assert!(storage_trie_cursor.next().unwrap().is_some());
    }

    #[tokio::test]
    async fn test_backfill_run_skips_if_already_done() {
        let provider = create_test_provider_factory();
        let storage = InMemoryProofsStorage::new();

        // Set earliest block to simulate already backfilled
        storage.set_earliest_block_number(50, B256::repeat_byte(0x01)).await.unwrap();

        let job = BackfillJob::new(&storage, &provider);

        // Run backfill - should skip
        job.run(100, B256::repeat_byte(0x42)).await.unwrap();

        // Should still have old earliest block
        assert_eq!(
            storage.get_earliest_block_number().await.unwrap(),
            Some((50, B256::repeat_byte(0x01)))
        );
    }
}
