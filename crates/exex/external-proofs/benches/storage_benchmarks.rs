//! Benchmarks for storage operations in external-proofs.
//!
//! Run with: cargo bench --bench storage_benchmarks

use alloy_primitives::{B256, U256};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use external_proofs::{
    in_memory::InMemoryProofsStorage,
    storage::{OpProofsHashedCursor, OpProofsStorage, OpProofsTrieCursor},
};
use reth_primitives_traits::Account;
use reth_trie::{BranchNodeCompact, Nibbles};
use std::sync::Arc;
use tokio::runtime::Runtime;

/// Helper to create test account
fn create_test_account(nonce: u64) -> Account {
    Account { nonce, balance: U256::from(1000u64), bytecode_hash: None }
}

/// Helper to create test branch node
fn create_test_branch() -> BranchNodeCompact {
    // Create a simple branch with no children (empty node)
    // This is valid and commonly used for intermediate trie nodes
    BranchNodeCompact::new(
        0b0000_0000_0000_0000, // no children
        0b0000_0000_0000_0000, // no tree masks
        0b0000_0000_0000_0000, // no hash masks
        vec![],                // no hashes
        None,
    )
}

/// Benchmark storing account branches
fn bench_store_account_branches(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_account_branches");

    for size in [10, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let rt = Runtime::new().unwrap();
            b.to_async(&rt).iter(|| async {
                let storage = Arc::new(InMemoryProofsStorage::new());

                // Initialize storage
                storage.set_earliest_block_number(0, B256::ZERO).await.unwrap();

                let updates: Vec<_> = (0..size)
                    .map(|i| {
                        let nibbles = Nibbles::from_nibbles_unchecked(vec![i as u8 % 16; 8]);
                        (nibbles, Some(create_test_branch()))
                    })
                    .collect();

                storage.store_account_branches(1, updates).await.unwrap();
            });
        });
    }

    group.finish();
}

/// Benchmark storing storage branches
fn bench_store_storage_branches(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_storage_branches");

    for size in [10, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let rt = Runtime::new().unwrap();
            b.to_async(&rt).iter(|| async {
                let storage = Arc::new(InMemoryProofsStorage::new());

                // Initialize storage
                storage.set_earliest_block_number(0, B256::ZERO).await.unwrap();

                let hashed_address = B256::random();
                let updates: Vec<_> = (0..size)
                    .map(|i| {
                        let nibbles = Nibbles::from_nibbles_unchecked(vec![i as u8 % 16; 8]);
                        (nibbles, Some(create_test_branch()))
                    })
                    .collect();

                storage.store_storage_branches(1, hashed_address, updates).await.unwrap();
            });
        });
    }

    group.finish();
}

/// Benchmark storing hashed accounts
fn bench_store_hashed_accounts(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_hashed_accounts");

    for size in [10, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let rt = Runtime::new().unwrap();
            b.to_async(&rt).iter(|| async {
                let storage = Arc::new(InMemoryProofsStorage::new());

                // Initialize storage
                storage.set_earliest_block_number(0, B256::ZERO).await.unwrap();

                let accounts: Vec<_> = (0..size)
                    .map(|i| {
                        let addr = B256::from_slice(&[i as u8; 32]);
                        (addr, Some(create_test_account(i as u64)))
                    })
                    .collect();

                storage.store_hashed_accounts(accounts, 1).await.unwrap();
            });
        });
    }

    group.finish();
}

/// Benchmark storing hashed storages
fn bench_store_hashed_storages(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_hashed_storages");

    for size in [10, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let rt = Runtime::new().unwrap();
            b.to_async(&rt).iter(|| async {
                let storage = Arc::new(InMemoryProofsStorage::new());

                // Initialize storage
                storage.set_earliest_block_number(0, B256::ZERO).await.unwrap();

                let hashed_address = B256::random();
                let storages: Vec<_> = (0..size)
                    .map(|i| {
                        let key = B256::from_slice(&[i as u8; 32]);
                        (key, U256::from(i))
                    })
                    .collect();

                storage.store_hashed_storages(hashed_address, storages, 1).await.unwrap();
            });
        });
    }

    group.finish();
}

/// Benchmark account trie cursor operations
fn bench_account_trie_cursor(c: &mut Criterion) {
    let mut group = c.benchmark_group("account_trie_cursor");

    let rt = Runtime::new().unwrap();

    // Pre-populate storage
    let storage = Arc::new(InMemoryProofsStorage::new());
    rt.block_on(async {
        storage.set_earliest_block_number(0, B256::ZERO).await.unwrap();

        let updates: Vec<_> = (0..1000)
            .map(|i| {
                let nibbles = Nibbles::from_nibbles_unchecked(vec![i as u8 % 16; 8]);
                (nibbles, Some(create_test_branch()))
            })
            .collect();
        storage.store_account_branches(1, updates).await.unwrap();
    });

    group.bench_function("create_cursor", |b| {
        b.iter(|| {
            let _cursor = storage.account_trie_cursor(1).unwrap();
        });
    });

    group.bench_function("seek_and_iterate", |b| {
        b.iter(|| {
            let mut cursor = storage.account_trie_cursor(1).unwrap();
            let target = Nibbles::from_nibbles_unchecked(vec![5; 8]);
            OpProofsTrieCursor::seek(&mut cursor, target).unwrap();

            // Iterate through 10 entries
            for _ in 0..10 {
                if OpProofsTrieCursor::next(&mut cursor).unwrap().is_none() {
                    break;
                }
            }
        });
    });

    group.finish();
}

/// Benchmark account hashed cursor operations
fn bench_account_hashed_cursor(c: &mut Criterion) {
    let mut group = c.benchmark_group("account_hashed_cursor");

    let rt = Runtime::new().unwrap();

    // Pre-populate storage
    let storage = Arc::new(InMemoryProofsStorage::new());
    rt.block_on(async {
        storage.set_earliest_block_number(0, B256::ZERO).await.unwrap();

        let accounts: Vec<_> = (0..1000)
            .map(|i| {
                let addr = B256::from_slice(&[(i % 256) as u8; 32]);
                (addr, Some(create_test_account(i as u64)))
            })
            .collect();
        storage.store_hashed_accounts(accounts, 1).await.unwrap();
    });

    group.bench_function("create_cursor", |b| {
        b.iter(|| {
            let _cursor = storage.account_hashed_cursor(1).unwrap();
        });
    });

    group.bench_function("seek_and_iterate", |b| {
        b.iter(|| {
            let mut cursor = storage.account_hashed_cursor(1).unwrap();
            OpProofsHashedCursor::seek(&mut cursor, B256::from_slice(&[128; 32])).unwrap();

            // Iterate through 10 entries
            for _ in 0..10 {
                if OpProofsHashedCursor::next(&mut cursor).unwrap().is_none() {
                    break;
                }
            }
        });
    });

    group.finish();
}

/// Benchmark metadata operations
fn bench_metadata_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("metadata_operations");

    let rt = Runtime::new().unwrap();
    let storage = Arc::new(InMemoryProofsStorage::new());

    rt.block_on(async {
        storage.set_earliest_block_number(100, B256::random()).await.unwrap();
    });

    group.bench_function("get_earliest_block_number", |b| {
        b.to_async(&rt).iter(|| async {
            storage.get_earliest_block_number().await.unwrap();
        });
    });

    group.bench_function("get_latest_block_number", |b| {
        b.to_async(&rt).iter(|| async {
            storage.get_latest_block_number().await.unwrap();
        });
    });

    group.bench_function("set_earliest_block_number", |b| {
        b.to_async(&rt).iter(|| async {
            storage.set_earliest_block_number(200, B256::random()).await.unwrap();
        });
    });

    group.finish();
}

/// Benchmark full block state diff storage
fn bench_store_trie_updates(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_trie_updates");

    for num_accounts in [10, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_accounts),
            &num_accounts,
            |b, &num_accounts| {
                let rt = Runtime::new().unwrap();
                b.to_async(&rt).iter(|| async {
                    let storage = Arc::new(InMemoryProofsStorage::new());
                    storage.set_earliest_block_number(0, B256::ZERO).await.unwrap();

                    // Create trie updates
                    let mut trie_updates = reth_trie::updates::TrieUpdates::default();
                    for i in 0..num_accounts {
                        let nibbles = Nibbles::from_nibbles_unchecked(vec![i as u8 % 16; 8]);
                        trie_updates.account_nodes.insert(nibbles, create_test_branch());
                    }

                    // Create post state
                    let mut post_state = reth_trie::HashedPostState::default();
                    for i in 0..num_accounts {
                        let addr = B256::from_slice(&[(i % 256) as u8; 32]);
                        post_state.accounts.insert(addr, Some(create_test_account(i as u64)));
                    }

                    let block_state_diff =
                        external_proofs::storage::BlockStateDiff { trie_updates, post_state };

                    storage.store_trie_updates(1, block_state_diff).await.unwrap();
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_store_account_branches,
    bench_store_storage_branches,
    bench_store_hashed_accounts,
    bench_store_hashed_storages,
    bench_account_trie_cursor,
    bench_account_hashed_cursor,
    bench_metadata_operations,
    bench_store_trie_updates,
);
criterion_main!(benches);
