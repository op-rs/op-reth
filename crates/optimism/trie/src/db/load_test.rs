use crate::db::AddressMap;
use std::time::{Duration, Instant};
use alloy_eips::eip1898::BlockWithParent;
use alloy_eips::NumHash;
use rand::{rngs::StdRng, Rng, SeedableRng};
use reth_trie::HashedStorage;
use alloy_primitives::{B256, U256};
use tracing::info;
use tempfile::TempDir;
use reth_db::Database;
use reth_db::transaction::DbTx;
use reth_db::cursor::DbCursorRO;
use reth_primitives_traits::Account;
use reth_trie::hashed_cursor::HashedCursor;
use crate::{BlockStateDiff, OpProofsStore};
use crate::db::{HashedAccountHistory, MdbxProofsStorage};
use crate::db::cursor::{RethAccountCursor, RethStorageCursor};

// Tune these constants to control total size.
const NUM_BLOCKS: u64 = 5_000;           // number of blocks
const ACCOUNTS_PER_BLOCK: usize = 2_000; // accounts per block
const SLOTS_PER_ACCOUNT: usize = 2;      // storage slots per account

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

        // Account row
        let account = Account {
            nonce: i as u64,
            balance: U256::from(block_number),
            ..Default::default()
        };
        diff.post_state.accounts.insert(addr, Some(account));

        // Storage rows under this address
        let mut storage = HashedStorage::default();
        for slot_idx in 0..SLOTS_PER_ACCOUNT {
            let slot = B256::from(U256::from(slot_idx as u64));
            let value = U256::from(((block_number as u64) << 32) | (slot_idx as u64));
            storage.storage.insert(slot, value);
        }
        diff.post_state.storages.insert(addr, storage);
    }

    // For pure load we don't *have to* stress trie nodes; post_state is enough
    // to fill HashedAccountHistory + HashedStorageHistory + BlockChangeSet.
    diff
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore] // IMPORTANT: heavy load, only run manually
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
                "[WRITE] finished block {number}, accounts/block = {ACCOUNTS_PER_BLOCK}, \
                 slots/account = {SLOTS_PER_ACCOUNT}"
            );
        }
    }

    // -------------------------------------------------------
    // Reth Account Hashed Cursor Load Test vs native cursor
    //
    // - Sample at blocks 100, 200, 300, ... up to NUM_BLOCKS
    // - For each sample block B, pick N random account keys that
    //   were created at or before B (so they actually exist).
    // -------------------------------------------------------

    const SAMPLE_BLOCK_STEP: u64 = 100;
    const SAMPLE_KEYS_PER_BLOCK: usize = 1_000;

    eprintln!("\n[CURSOR] Starting Reth vs native account cursor load test...");

    let mut total_seeks_reth: u64 = 0;
    let mut total_time_reth: Duration = Duration::ZERO;

    let mut total_seeks_native: u64 = 0;
    let mut total_time_native: Duration = Duration::ZERO;

    // Separate RNG so writes are deterministic regardless of this test
    let mut rng_keys = StdRng::seed_from_u64(42);

    let max_sample_block = NUM_BLOCKS / SAMPLE_BLOCK_STEP * SAMPLE_BLOCK_STEP;

    for block_number in (SAMPLE_BLOCK_STEP..=max_sample_block).step_by(SAMPLE_BLOCK_STEP as usize) {
        // Generate SAMPLE_KEYS_PER_BLOCK keys that exist at `block_number`
        let mut keys = Vec::with_capacity(SAMPLE_KEYS_PER_BLOCK);
        for _ in 0..SAMPLE_KEYS_PER_BLOCK {
            // Creation block must be <= block_number
            let creation_block = rng_keys.gen_range(1..=block_number);
            let account_idx =
                rng_keys.gen_range(0..ACCOUNTS_PER_BLOCK as u64) as usize;
            let key = addr_for(creation_block, account_idx);
            keys.push(key);
        }

        // ----- Reth Account Cursor path -----
        {
            let tx = store.env.tx().expect("tx (reth cursor)");
            let history_cursor = tx
                .cursor_read::<reth_db::tables::AccountsHistory>()
                .expect("AccountsHistory cursor");
            let change_set_cursor = tx
                .cursor_read::<reth_db::tables::AccountChangeSets>()
                .expect("AccountChangeSets cursor");

            let address_map_cursor = tx
                .cursor_read::<AddressMap>()
                .expect("AddressMap cursor");

            let mut account_cursor =
                RethAccountCursor::new(block_number, history_cursor, change_set_cursor, address_map_cursor);

            let t0 = Instant::now();
            for key in &keys {
                let _ = account_cursor.seek(*key);
            }
            let dt = t0.elapsed();

            total_seeks_reth += keys.len() as u64;
            total_time_reth += dt;

            eprintln!(
                "[CURSOR RETH] block {}: {} seeks in {:?} (avg {:?}/seek)",
                block_number,
                keys.len(),
                dt,
                dt / keys.len() as u32
            );
        }

        // ----- Native account_hashed_cursor path -----
        {
            let mut account_cursor_native = store
                .account_hashed_cursor(block_number)
                .expect("account_hashed_cursor");

            let t0 = Instant::now();
            for key in &keys {
                let _ = account_cursor_native.seek(*key);
            }
            let dt = t0.elapsed();

            total_seeks_native += keys.len() as u64;
            total_time_native += dt;

            eprintln!(
                "[CURSOR NATIVE] block {}: {} seeks in {:?} (avg {:?}/seek)",
                block_number,
                keys.len(),
                dt,
                dt / keys.len() as u32
            );
        }
    }

    eprintln!("\n========== ACCOUNT CURSOR SUMMARY ==========");
    eprintln!("Reth cursor:");
    eprintln!("  Total seeks : {}", total_seeks_reth);
    eprintln!("  Total time  : {:?}", total_time_reth);
    if total_seeks_reth > 0 {
        eprintln!(
            "  Avg latency/seek : {:?}",
            total_time_reth / total_seeks_reth as u32
        );
    }

    eprintln!("\nNative cursor:");
    eprintln!("  Total seeks : {}", total_seeks_native);
    eprintln!("  Total time  : {:?}", total_time_native);
    if total_seeks_native > 0 {
        eprintln!(
            "  Avg latency/seek : {:?}",
            total_time_native / total_seeks_native as u32
        );
    }
    eprintln!("===========================================\n");

    // -------------------------------------------------------
    // Hashed Storage Cursor Load Test (Reth vs native)
    //
    // - Sample same blocks: 100, 200, 300, ...
    // - For each sample block B:
    //     * pick some random account addresses that exist at or before B
    //     * for each address, hit multiple different slots under that address
    // -------------------------------------------------------

    const SAMPLE_STORAGE_ADDRS_PER_BLOCK: usize = 500; // each with SLOTS_PER_ACCOUNT slots

    eprintln!("\n[CURSOR] Starting Reth vs native STORAGE cursor load test...");

    let mut total_storage_seeks_reth: u64 = 0;
    let mut total_storage_time_reth: Duration = Duration::ZERO;

    let mut total_storage_seeks_native: u64 = 0;
    let mut total_storage_time_native: Duration = Duration::ZERO;

    // reuse rng_keys; pattern doesn’t matter, just determinism
    for block_number in (SAMPLE_BLOCK_STEP..=max_sample_block).step_by(SAMPLE_BLOCK_STEP as usize) {
        // Generate SAMPLE_STORAGE_ADDRS_PER_BLOCK addresses that exist at `block_number`
        let mut addrs = Vec::with_capacity(SAMPLE_STORAGE_ADDRS_PER_BLOCK);
        for _ in 0..SAMPLE_STORAGE_ADDRS_PER_BLOCK {
            let creation_block = rng_keys.gen_range(1..=block_number);
            let account_idx =
                rng_keys.gen_range(0..ACCOUNTS_PER_BLOCK as u64) as usize;
            let addr = addr_for(creation_block, account_idx);
            addrs.push(addr);
        }

        // ----- Reth Storage Cursor path -----
        {
            let tx = store.env.tx().expect("tx (reth storage cursor)");
            

            let mut seeks_for_block = 0u64;
            let t0 = Instant::now();

            for addr in &addrs {
                let history_cursor = tx
                    .cursor_read::<reth_db::tables::StoragesHistory>()
                    .expect("StoragesHistory cursor");
                let change_set_cursor = tx
                    .cursor_read::<reth_db::tables::StorageChangeSets>()
                    .expect("StorageChangeSets cursor");
                // cursor bound to a given (block_number, hashed_address)
                let address_option = tx.cursor_read::<AddressMap>().expect("AddressMap cursor").seek_exact(*addr).expect("seek_exact");
                if address_option.is_none() {
                    panic!("Address not found");
                }
                let mut storage_cursor =
                    RethStorageCursor::new(*addr, address_option.unwrap().1, block_number, history_cursor, change_set_cursor);

                for slot_idx in 0..SLOTS_PER_ACCOUNT {
                    let slot = B256::from(U256::from(slot_idx as u64));
                    let _ = storage_cursor.seek(slot);
                    seeks_for_block += 1;
                }
            }

            let dt = t0.elapsed();
            total_storage_seeks_reth += seeks_for_block;
            total_storage_time_reth += dt;

            eprintln!(
                "[STORAGE RETH] block {}: {} seeks ({} addrs × {} slots) in {:?} (avg {:?}/seek)",
                block_number,
                seeks_for_block,
                addrs.len(),
                SLOTS_PER_ACCOUNT,
                dt,
                dt / seeks_for_block as u32
            );
        }

        // ----- Native storage_hashed_cursor path -----
        {
            let mut seeks_for_block = 0u64;
            let t0 = Instant::now();

            for addr in &addrs {
                let mut storage_cursor_native = store
                    .storage_hashed_cursor(*addr, block_number)
                    .expect("storage_hashed_cursor");

                for slot_idx in 0..SLOTS_PER_ACCOUNT {
                    let slot = B256::from(U256::from(slot_idx as u64));
                    let _ = storage_cursor_native.seek(slot);
                    seeks_for_block += 1;
                }
            }

            let dt = t0.elapsed();
            total_storage_seeks_native += seeks_for_block;
            total_storage_time_native += dt;

            eprintln!(
                "[STORAGE NATIVE] block {}: {} seeks ({} addrs × {} slots) in {:?} (avg {:?}/seek)",
                block_number,
                seeks_for_block,
                addrs.len(),
                SLOTS_PER_ACCOUNT,
                dt,
                dt / seeks_for_block as u32
            );
        }
    }

    eprintln!("\n====== STORAGE CURSOR SUMMARY ======");
    eprintln!("Reth storage cursor:");
    eprintln!("  Total seeks : {}", total_storage_seeks_reth);
    eprintln!("  Total time  : {:?}", total_storage_time_reth);
    if total_storage_seeks_reth > 0 {
        eprintln!(
            "  Avg latency/seek : {:?}",
            total_storage_time_reth / total_storage_seeks_reth as u32
        );
    }

    eprintln!("\nNative storage cursor:");
    eprintln!("  Total seeks : {}", total_storage_seeks_native);
    eprintln!("  Total time  : {:?}", total_storage_time_native);
    if total_storage_seeks_native > 0 {
        eprintln!(
            "  Avg latency/seek : {:?}",
            total_storage_time_native / total_storage_seeks_native as u32
        );
    }
    eprintln!("====================================\n");

    // -------------------------------
    // A/B DELETION LOAD TEST
    // Compare delete_history_ranged vs delete_history_ranged_reth
    // -------------------------------

    let blocks_to_delete = NUM_BLOCKS / 2;      // delete first 50% of blocks
    let delete_in_each_steps: u64 = 20;         // chunk size

    eprintln!("Starting A/B deletion test for {blocks_to_delete} blocks...");

    // Stats for approach A (Optimism style)
    let mut total_deleted_a = 0u64;
    let mut total_duration_a = Duration::ZERO;

    // Stats for approach B (Reth style)
    let mut total_deleted_b = 0u64;
    let mut total_duration_b = Duration::ZERO;

    let tx = store.env.tx_mut().expect("tx_mut");

    let mut current_block = 1u64;
    let mut use_a = true;

    while current_block <= blocks_to_delete {
        let start = current_block;
        let mut end = start + delete_in_each_steps;
        // `start..end` is half-open, so end is exclusive.
        // Clamp to not exceed blocks_to_delete.
        if end > blocks_to_delete + 1 {
            end = blocks_to_delete + 1;
        }

        let blocks_in_range = end - start;

        let t0 = Instant::now();

        if use_a {
            // -----------------------------
            // APPROACH A
            // -----------------------------
            store
                .delete_history_ranged(&tx, start..end)
                .expect("delete_history_ranged failed");

            let dt = t0.elapsed();
            total_duration_a += dt;
            total_deleted_a += blocks_in_range;

            eprintln!(
                "[A] Deleted {} blocks ({}–{}) — took {:?}",
                blocks_in_range,
                start,
                end - 1,
                dt
            );
        } else {
            // -----------------------------
            // APPROACH B
            // -----------------------------
            store
                .delete_history_ranged_reth(&tx, start..end)
                .expect("delete_history_ranged_reth failed");

            let dt = t0.elapsed();
            total_duration_b += dt;
            total_deleted_b += blocks_in_range;

            eprintln!(
                "[B] Deleted {} blocks ({}–{}) — took {:?}",
                blocks_in_range,
                start,
                end - 1,
                dt
            );
        }

        // Alternate between A and B
        use_a = !use_a;

        // Move to next chunk (end is the first block NOT deleted)
        current_block = end;
    }

    // -------------------------------
    // FINAL DELETION SUMMARY
    // -------------------------------
    eprintln!("\n========== A/B DELETION SUMMARY ==========");

    eprintln!("Approach A (delete_history_ranged):");
    eprintln!("  Total blocks deleted : {}", total_deleted_a);
    eprintln!("  Total time taken     : {:?}", total_duration_a);
    if total_deleted_a > 0 {
        eprintln!(
            "  Avg latency/block    : {:?}",
            total_duration_a / total_deleted_a as u32
        );
    }

    eprintln!("\nApproach B (delete_history_ranged_reth):");
    eprintln!("  Total blocks deleted : {}", total_deleted_b);
    eprintln!("  Total time taken     : {:?}", total_duration_b);
    if total_deleted_b > 0 {
        eprintln!(
            "  Avg latency/block    : {:?}",
            total_duration_b / total_deleted_b as u32
        );
    }

    eprintln!("=========================================\n");
}
