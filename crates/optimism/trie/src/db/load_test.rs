use crate::db::AddressMap;
use std::time::{Duration, Instant};

use alloy_eips::eip1898::BlockWithParent;
use alloy_eips::NumHash;
use alloy_primitives::{B256, U256};
use rand::{rngs::StdRng, Rng, SeedableRng};
use reth_db::cursor::DbCursorRO;
use reth_db::transaction::DbTx;
use reth_db::Database;
use reth_primitives_traits::Account;
use reth_trie::hashed_cursor::HashedCursor;
use reth_trie::HashedStorage;
use tempfile::TempDir;
use tracing::info;

use crate::{BlockStateDiff, OpProofsStore};
use crate::db::MdbxProofsStorage;
use crate::db::cursor::{RethAccountCursor, RethStorageCursor};

// Tune these constants to control total size.
const NUM_BLOCKS: u64 = 5000;              // number of blocks
const ACCOUNTS_PER_BLOCK: usize = 2_000;  // accounts per block
const SLOTS_PER_ACCOUNT: usize = 5;       // storage slots per account

fn make_block_ref(parent_hash: B256, number: u64, rng: &mut StdRng) -> BlockWithParent {
    let hash_bytes: [u8; 32] = rng.r#gen();
    let hash = B256::from(hash_bytes);
    BlockWithParent::new(parent_hash, NumHash::new(number, hash))
}

/// Deterministic way to derive an address from (block_number, account_index)
fn addr_for(block_number: u64, i: usize) -> B256 {
    let seed = ((block_number as u128) << 64) | (i as u128);
    B256::from(U256::from(seed))
}

/// Build a big BlockStateDiff with many accounts and storages for a given block.
fn make_block_diff(block_number: u64, _rng: &mut StdRng) -> BlockStateDiff {
    let mut diff = BlockStateDiff::default();

    for i in 0..ACCOUNTS_PER_BLOCK {
        let addr = addr_for(block_number, i);

        let account = Account {
            nonce: i as u64,
            balance: U256::from(block_number),
            ..Default::default()
        };
        diff.post_state.accounts.insert(addr, Some(account));

        let mut storage = HashedStorage::default();
        for slot_idx in 0..SLOTS_PER_ACCOUNT {
            let slot = B256::from(U256::from(slot_idx as u64));
            let value = U256::from(((block_number as u64) << 32) | (slot_idx as u64));
            storage.storage.insert(slot, value);
        }
        diff.post_state.storages.insert(addr, storage);
    }

    diff
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore] // heavy load; run manually
async fn heavy_load_store_and_load_tests() {
    let dir = TempDir::new().expect("temp dir");
    let db_path = dir.path().join("mdbx");
    std::fs::create_dir_all(&db_path).expect("create db dir");

    let store = MdbxProofsStorage::new(&db_path).expect("open db");

    let mut rng = StdRng::seed_from_u64(1);
    let mut parent_hash = B256::ZERO;

    // -------------------------------
    // Write phase: lots of blocks
    // -------------------------------
    for number in 1..=NUM_BLOCKS {
        let block = make_block_ref(parent_hash, number, &mut rng);
        let diff = make_block_diff(number, &mut rng);

        store
            .store_trie_updates(block, diff)
            .await
            .expect("store_trie_updates");

        parent_hash = block.block.hash;

        if number % 10 == 0 {
            info!("Writing = {}", number);
            eprintln!(
                "[WRITE] finished block {number}, accounts/block = {ACCOUNTS_PER_BLOCK}, slots/account = {SLOTS_PER_ACCOUNT}"
            );
        }
    }

    // -------------------------------------------------------
    // ACCOUNT CURSOR LOAD TESTS (SEEK and NEXT separately)
    //
    // Sample blocks: 100, 200, ... up to NUM_BLOCKS (clamped)
    // For each sample block B:
    //   - generate N keys that exist <= B
    //   - SEEK test: time only seek(key)
    //   - NEXT test: do seek(key) (not timed), then time 10x next()
    // -------------------------------------------------------

    const SAMPLE_BLOCK_STEP: u64 = 500;
    const SAMPLE_KEYS_PER_BLOCK: usize = 1_000;

    const ACCOUNT_NEXT_CALLS: usize = 5;

    let max_sample_block = (NUM_BLOCKS / SAMPLE_BLOCK_STEP) * SAMPLE_BLOCK_STEP;

    // Separate RNG so writes are deterministic regardless of this test
    let mut rng_keys = StdRng::seed_from_u64(42);

    // ================
    // ACCOUNT SEEK TEST
    // ================
    eprintln!("\n[ACCOUNT][SEEK] Starting Reth vs native seek-only test...");

    let mut total_account_seek_reth: u64 = 0;
    let mut total_account_seek_time_reth: Duration = Duration::ZERO;

    let mut total_account_seek_native: u64 = 0;
    let mut total_account_seek_time_native: Duration = Duration::ZERO;

    for block_number in (SAMPLE_BLOCK_STEP..=max_sample_block).step_by(SAMPLE_BLOCK_STEP as usize) {
        let mut keys = Vec::with_capacity(SAMPLE_KEYS_PER_BLOCK);
        for _ in 0..SAMPLE_KEYS_PER_BLOCK {
            let creation_block = rng_keys.gen_range(1..=block_number);
            let account_idx = rng_keys.gen_range(0..ACCOUNTS_PER_BLOCK as u64) as usize;
            keys.push(addr_for(creation_block, account_idx));
        }

        // Reth seek-only
        {
            let tx = store.env.tx().expect("tx (reth account seek)");
            let history_cursor = tx
                .cursor_read::<reth_db::tables::AccountsHistory>()
                .expect("AccountsHistory cursor");
            let change_set_cursor = tx
                .cursor_read::<reth_db::tables::AccountChangeSets>()
                .expect("AccountChangeSets cursor");
            let address_map_cursor = tx
                .cursor_read::<AddressMap>()
                .expect("AddressMap cursor");

            let mut cursor =
                RethAccountCursor::new(block_number, history_cursor, change_set_cursor, address_map_cursor);

            let t0 = Instant::now();
            for key in &keys {
                let _ = cursor.seek(*key);
            }
            let dt = t0.elapsed();

            total_account_seek_reth += keys.len() as u64;
            total_account_seek_time_reth += dt;

            eprintln!(
                "[ACCOUNT][SEEK][RETH] block {}: {} seeks in {:?} (avg {:?}/seek)",
                block_number,
                keys.len(),
                dt,
                dt / keys.len() as u32
            );
        }

        // Native seek-only
        {
            let mut cursor = store.account_hashed_cursor(block_number).expect("account_hashed_cursor");

            let t0 = Instant::now();
            for key in &keys {
                let _ = cursor.seek(*key);
            }
            let dt = t0.elapsed();

            total_account_seek_native += keys.len() as u64;
            total_account_seek_time_native += dt;

            eprintln!(
                "[ACCOUNT][SEEK][NATIVE] block {}: {} seeks in {:?} (avg {:?}/seek)",
                block_number,
                keys.len(),
                dt,
                dt / keys.len() as u32
            );
        }
    }

    eprintln!("\n========== ACCOUNT SEEK SUMMARY ==========");
    eprintln!("Reth:");
    eprintln!("  Total seeks : {}", total_account_seek_reth);
    eprintln!("  Total time  : {:?}", total_account_seek_time_reth);
    if total_account_seek_reth > 0 {
        eprintln!(
            "  Avg latency/seek : {:?}",
            total_account_seek_time_reth / total_account_seek_reth as u32
        );
    }
    eprintln!("\nNative:");
    eprintln!("  Total seeks : {}", total_account_seek_native);
    eprintln!("  Total time  : {:?}", total_account_seek_time_native);
    if total_account_seek_native > 0 {
        eprintln!(
            "  Avg latency/seek : {:?}",
            total_account_seek_time_native / total_account_seek_native as u32
        );
    }
    eprintln!("=========================================\n");

    // ================
    // ACCOUNT NEXT TEST
    // ================
    eprintln!("\n[ACCOUNT][NEXT] Starting Reth vs native next-only test (seek once then 10× next)...");

    let mut total_account_next_reth: u64 = 0;
    let mut total_account_next_time_reth: Duration = Duration::ZERO;

    let mut total_account_next_native: u64 = 0;
    let mut total_account_next_time_native: Duration = Duration::ZERO;

    // Reset RNG so we use comparable key distribution as seek test (optional, but nice)
    let mut rng_keys_next = StdRng::seed_from_u64(42);

    for block_number in (SAMPLE_BLOCK_STEP..=max_sample_block).step_by(SAMPLE_BLOCK_STEP as usize) {
        let mut keys = Vec::with_capacity(SAMPLE_KEYS_PER_BLOCK);
        for _ in 0..SAMPLE_KEYS_PER_BLOCK {
            let creation_block = rng_keys_next.gen_range(1..=block_number);
            let account_idx = rng_keys_next.gen_range(0..ACCOUNTS_PER_BLOCK as u64) as usize;
            keys.push(addr_for(creation_block, account_idx));
        }

        // Reth next-only
        {
            let tx = store.env.tx().expect("tx (reth account next)");
            let history_cursor = tx
                .cursor_read::<reth_db::tables::AccountsHistory>()
                .expect("AccountsHistory cursor");
            let change_set_cursor = tx
                .cursor_read::<reth_db::tables::AccountChangeSets>()
                .expect("AccountChangeSets cursor");
            let address_map_cursor = tx
                .cursor_read::<AddressMap>()
                .expect("AddressMap cursor");

            let mut cursor =
                RethAccountCursor::new(block_number, history_cursor, change_set_cursor, address_map_cursor);

            let mut next_calls = 0u64;
            let t0 = Instant::now();

            for key in &keys {
                // seek is NOT timed here
                let res = cursor.seek(*key).expect("seek");
                if res.is_none() {
                    continue;
                }

                for _ in 0..ACCOUNT_NEXT_CALLS {
                    let r = cursor.next().expect("next");
                    next_calls += 1;
                    if r.is_none() {
                        break;
                    }
                }
            }

            let dt = t0.elapsed();
            total_account_next_reth += next_calls;
            total_account_next_time_reth += dt;

            eprintln!(
                "[ACCOUNT][NEXT][RETH] block {}: {} next() calls in {:?} (avg {:?}/next)",
                block_number,
                next_calls,
                dt,
                if next_calls > 0 { dt / next_calls as u32 } else { Duration::ZERO }
            );
        }

        // Native next-only
        {
            let mut cursor = store.account_hashed_cursor(block_number).expect("account_hashed_cursor");

            let mut next_calls = 0u64;
            let t0 = Instant::now();

            for key in &keys {
                let res = cursor.seek(*key).expect("seek");
                if res.is_none() {
                    continue;
                }

                for _ in 0..ACCOUNT_NEXT_CALLS {
                    let r = cursor.next().expect("next");
                    next_calls += 1;
                    if r.is_none() {
                        break;
                    }
                }
            }

            let dt = t0.elapsed();
            total_account_next_native += next_calls;
            total_account_next_time_native += dt;

            eprintln!(
                "[ACCOUNT][NEXT][NATIVE] block {}: {} next() calls in {:?} (avg {:?}/next)",
                block_number,
                next_calls,
                dt,
                if next_calls > 0 { dt / next_calls as u32 } else { Duration::ZERO }
            );
        }
    }

    eprintln!("\n========== ACCOUNT NEXT SUMMARY ==========");
    eprintln!("Reth:");
    eprintln!("  Total next() calls : {}", total_account_next_reth);
    eprintln!("  Total time         : {:?}", total_account_next_time_reth);
    if total_account_next_reth > 0 {
        eprintln!(
            "  Avg latency/next : {:?}",
            total_account_next_time_reth / total_account_next_reth as u32
        );
    }
    eprintln!("\nNative:");
    eprintln!("  Total next() calls : {}", total_account_next_native);
    eprintln!("  Total time         : {:?}", total_account_next_time_native);
    if total_account_next_native > 0 {
        eprintln!(
            "  Avg latency/next : {:?}",
            total_account_next_time_native / total_account_next_native as u32
        );
    }
    eprintln!("=========================================\n");

    // -------------------------------------------------------
    // STORAGE CURSOR LOAD TESTS (SEEK and NEXT separately)
    //
    // For each sample block B:
    //   - pick M hashed addresses that exist <= B
    //   - SEEK test: time only seek(slot_i) for a couple slots
    //   - NEXT test: do seek(slot0) (not timed), then time 5× next()
    // -------------------------------------------------------

    const SAMPLE_STORAGE_ADDRS_PER_BLOCK: usize = 500;

    const STORAGE_NEXT_CALLS: usize = 5;

    // ================
    // STORAGE SEEK TEST
    // ================
    eprintln!("\n[STORAGE][SEEK] Starting Reth vs native seek-only test...");

    let mut total_storage_seek_reth: u64 = 0;
    let mut total_storage_seek_time_reth: Duration = Duration::ZERO;

    let mut total_storage_seek_native: u64 = 0;
    let mut total_storage_seek_time_native: Duration = Duration::ZERO;

    // Use a separate RNG stream for storage sampling
    let mut rng_storage = StdRng::seed_from_u64(777);

    for block_number in (SAMPLE_BLOCK_STEP..=max_sample_block).step_by(SAMPLE_BLOCK_STEP as usize) {
        let mut addrs = Vec::with_capacity(SAMPLE_STORAGE_ADDRS_PER_BLOCK);
        for _ in 0..SAMPLE_STORAGE_ADDRS_PER_BLOCK {
            let creation_block = rng_storage.gen_range(1..=block_number);
            let account_idx = rng_storage.gen_range(0..ACCOUNTS_PER_BLOCK as u64) as usize;
            addrs.push(addr_for(creation_block, account_idx));
        }

        // Reth storage seek-only
        {
            let tx = store.env.tx().expect("tx (reth storage seek)");
            let mut address_map_cursor = tx.cursor_read::<AddressMap>().expect("AddressMap cursor");

            let mut seeks = 0u64;
            let t0 = Instant::now();

            for hashed_addr in &addrs {
                let Some((_h, addr)) = address_map_cursor.seek_exact(*hashed_addr).expect("AddressMap seek_exact") else {
                    continue;
                };

                let history_cursor = tx
                    .cursor_read::<reth_db::tables::StoragesHistory>()
                    .expect("StoragesHistory cursor");
                let change_set_cursor = tx
                    .cursor_read::<reth_db::tables::StorageChangeSets>()
                    .expect("StorageChangeSets cursor");

                let mut cursor =
                    RethStorageCursor::new(*hashed_addr, addr, block_number, history_cursor, change_set_cursor);

                for slot_idx in 0..SLOTS_PER_ACCOUNT {
                    let slot = B256::from(U256::from(slot_idx as u64));
                    let _ = cursor.seek(slot);
                    seeks += 1;
                }
            }

            let dt = t0.elapsed();
            total_storage_seek_reth += seeks;
            total_storage_seek_time_reth += dt;

            eprintln!(
                "[STORAGE][SEEK][RETH] block {}: {} seeks in {:?} (avg {:?}/seek)",
                block_number,
                seeks,
                dt,
                if seeks > 0 { dt / seeks as u32 } else { Duration::ZERO }
            );
        }

        // Native storage seek-only
        {
            let mut seeks = 0u64;
            let t0 = Instant::now();

            for hashed_addr in &addrs {
                let mut cursor = store
                    .storage_hashed_cursor(*hashed_addr, block_number)
                    .expect("storage_hashed_cursor");

                for slot_idx in 0..SLOTS_PER_ACCOUNT {
                    let slot = B256::from(U256::from(slot_idx as u64));
                    let _ = cursor.seek(slot);
                    seeks += 1;
                }
            }

            let dt = t0.elapsed();
            total_storage_seek_native += seeks;
            total_storage_seek_time_native += dt;

            eprintln!(
                "[STORAGE][SEEK][NATIVE] block {}: {} seeks in {:?} (avg {:?}/seek)",
                block_number,
                seeks,
                dt,
                if seeks > 0 { dt / seeks as u32 } else { Duration::ZERO }
            );
        }
    }

    eprintln!("\n========== STORAGE SEEK SUMMARY ==========");
    eprintln!("Reth:");
    eprintln!("  Total seeks : {}", total_storage_seek_reth);
    eprintln!("  Total time  : {:?}", total_storage_seek_time_reth);
    if total_storage_seek_reth > 0 {
        eprintln!(
            "  Avg latency/seek : {:?}",
            total_storage_seek_time_reth / total_storage_seek_reth as u32
        );
    }
    eprintln!("\nNative:");
    eprintln!("  Total seeks : {}", total_storage_seek_native);
    eprintln!("  Total time  : {:?}", total_storage_seek_time_native);
    if total_storage_seek_native > 0 {
        eprintln!(
            "  Avg latency/seek : {:?}",
            total_storage_seek_time_native / total_storage_seek_native as u32
        );
    }
    eprintln!("=========================================\n");

    // ================
    // STORAGE NEXT TEST
    // ================
    eprintln!("\n[STORAGE][NEXT] Starting Reth vs native next-only test (seek once then 5× next)...");

    let mut total_storage_next_reth: u64 = 0;
    let mut total_storage_next_time_reth: Duration = Duration::ZERO;

    let mut total_storage_next_native: u64 = 0;
    let mut total_storage_next_time_native: Duration = Duration::ZERO;

    // reset rng for comparable address sampling (optional)
    let mut rng_storage_next = StdRng::seed_from_u64(777);

    for block_number in (SAMPLE_BLOCK_STEP..=max_sample_block).step_by(SAMPLE_BLOCK_STEP as usize) {
        let mut addrs = Vec::with_capacity(SAMPLE_STORAGE_ADDRS_PER_BLOCK);
        for _ in 0..SAMPLE_STORAGE_ADDRS_PER_BLOCK {
            let creation_block = rng_storage_next.gen_range(1..=block_number);
            let account_idx = rng_storage_next.gen_range(0..ACCOUNTS_PER_BLOCK as u64) as usize;
            addrs.push(addr_for(creation_block, account_idx));
        }

        // Reth storage next-only
        {
            let tx = store.env.tx().expect("tx (reth storage next)");
            let mut address_map_cursor = tx.cursor_read::<AddressMap>().expect("AddressMap cursor");

            let mut next_calls = 0u64;
            let t0 = Instant::now();

            for hashed_addr in &addrs {
                let Some((_h, addr)) = address_map_cursor.seek_exact(*hashed_addr).expect("AddressMap seek_exact") else {
                    continue;
                };

                let history_cursor = tx
                    .cursor_read::<reth_db::tables::StoragesHistory>()
                    .expect("StoragesHistory cursor");
                let change_set_cursor = tx
                    .cursor_read::<reth_db::tables::StorageChangeSets>()
                    .expect("StorageChangeSets cursor");

                let mut cursor =
                    RethStorageCursor::new(*hashed_addr, addr, block_number, history_cursor, change_set_cursor);

                // seek is NOT timed here
                let first_slot = B256::from(U256::from(0u64));
                let res = cursor.seek(first_slot).expect("seek");
                if res.is_none() {
                    continue;
                }

                for _ in 0..STORAGE_NEXT_CALLS {
                    let r = cursor.next().expect("next");
                    next_calls += 1;
                    if r.is_none() {
                        break;
                    }
                }
            }

            let dt = t0.elapsed();
            total_storage_next_reth += next_calls;
            total_storage_next_time_reth += dt;

            eprintln!(
                "[STORAGE][NEXT][RETH] block {}: {} next() calls in {:?} (avg {:?}/next)",
                block_number,
                next_calls,
                dt,
                if next_calls > 0 { dt / next_calls as u32 } else { Duration::ZERO }
            );
        }

        // Native storage next-only
        {
            let mut next_calls = 0u64;
            let t0 = Instant::now();

            for hashed_addr in &addrs {
                let mut cursor = store
                    .storage_hashed_cursor(*hashed_addr, block_number)
                    .expect("storage_hashed_cursor");

                let first_slot = B256::from(U256::from(0u64));
                let res = cursor.seek(first_slot).expect("seek");
                if res.is_none() {
                    continue;
                }

                for _ in 0..STORAGE_NEXT_CALLS {
                    let r = cursor.next().expect("next");
                    next_calls += 1;
                    if r.is_none() {
                        break;
                    }
                }
            }

            let dt = t0.elapsed();
            total_storage_next_native += next_calls;
            total_storage_next_time_native += dt;

            eprintln!(
                "[STORAGE][NEXT][NATIVE] block {}: {} next() calls in {:?} (avg {:?}/next)",
                block_number,
                next_calls,
                dt,
                if next_calls > 0 { dt / next_calls as u32 } else { Duration::ZERO }
            );
        }
    }

    eprintln!("\n========== STORAGE NEXT SUMMARY ==========");
    eprintln!("Reth:");
    eprintln!("  Total next() calls : {}", total_storage_next_reth);
    eprintln!("  Total time         : {:?}", total_storage_next_time_reth);
    if total_storage_next_reth > 0 {
        eprintln!(
            "  Avg latency/next : {:?}",
            total_storage_next_time_reth / total_storage_next_reth as u32
        );
    }
    eprintln!("\nNative:");
    eprintln!("  Total next() calls : {}", total_storage_next_native);
    eprintln!("  Total time         : {:?}", total_storage_next_time_native);
    if total_storage_next_native > 0 {
        eprintln!(
            "  Avg latency/next : {:?}",
            total_storage_next_time_native / total_storage_next_native as u32
        );
    }
    eprintln!("=========================================\n");
}
