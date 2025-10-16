//! Common test suite for `OpProofsStorage` implementations.

#[cfg(test)]
mod tests {
    use crate::{
        in_memory::InMemoryProofsStorage,
        mdbx::MdbxOpProofsStorage,
        storage::{
            BlockStateDiff, OpProofsHashedCursor, OpProofsStorage, OpProofsStorageError,
            OpProofsTrieCursor,
        },
    };
    use alloy_primitives::{map::HashMap, B256, U256};
    use reth_primitives_traits::Account;
    use reth_trie::{updates::TrieUpdates, BranchNodeCompact, HashedPostState, Nibbles, TrieMask};

    use std::sync::Arc;
    use test_case::test_case;

    /// Helper to create a simple test branch node
    fn create_test_branch() -> BranchNodeCompact {
        let mut state_mask = TrieMask::default();
        state_mask.set_bit(0);
        state_mask.set_bit(1);

        BranchNodeCompact {
            state_mask,
            tree_mask: TrieMask::default(),
            hash_mask: TrieMask::default(),
            hashes: Arc::new(vec![]),
            root_hash: None,
        }
    }

    /// Helper to create a variant test branch node for comparison tests
    fn create_test_branch_variant() -> BranchNodeCompact {
        let mut state_mask = TrieMask::default();
        state_mask.set_bit(5);
        state_mask.set_bit(6);

        BranchNodeCompact {
            state_mask,
            tree_mask: TrieMask::default(),
            hash_mask: TrieMask::default(),
            hashes: Arc::new(vec![]),
            root_hash: None,
        }
    }

    /// Helper to create nibbles from a vector of u8 values
    fn nibbles_from(vec: Vec<u8>) -> Nibbles {
        Nibbles::from_nibbles_unchecked(vec)
    }

    /// Helper to create a test account
    fn create_test_account() -> Account {
        Account {
            nonce: 42,
            balance: U256::from(1000000),
            bytecode_hash: Some(B256::repeat_byte(0xBB)),
        }
    }

    /// Helper to create a test account with custom values
    fn create_test_account_with_values(nonce: u64, balance: u64, code_hash_byte: u8) -> Account {
        Account {
            nonce,
            balance: U256::from(balance),
            bytecode_hash: Some(B256::repeat_byte(code_hash_byte)),
        }
    }

    /// Test basic storage and retrieval of earliest block number
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_earliest_block_operations<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        // Initially should be None
        let earliest = storage.get_earliest_block_number().await?;
        assert!(earliest.is_none());

        // Set earliest block
        let block_hash = B256::repeat_byte(0x42);
        storage.set_earliest_block_number(100, block_hash).await?;

        // Should retrieve the same values
        let earliest = storage.get_earliest_block_number().await?;
        assert_eq!(earliest, Some((100, block_hash)));

        Ok(())
    }

    /// Test storing and retrieving trie updates
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_trie_updates_operations<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let block_number = 50;
        let trie_updates = TrieUpdates::default();
        let post_state = HashedPostState::default();
        let block_state_diff =
            BlockStateDiff { trie_updates: trie_updates.clone(), post_state: post_state.clone() };

        // Store trie updates
        storage.store_trie_updates(block_number, block_state_diff).await?;

        // Retrieve and verify
        let retrieved_diff = storage.fetch_trie_updates(block_number).await?;
        assert_eq!(retrieved_diff.trie_updates, trie_updates);
        assert_eq!(retrieved_diff.post_state, post_state);

        Ok(())
    }

    // =============================================================================
    // 1. Basic Cursor Operations
    // =============================================================================

    /// Test cursor operations on empty trie
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_cursor_empty_trie<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let mut cursor = storage.account_trie_cursor(100)?;

        // All operations should return None on empty trie
        assert!(cursor.seek_exact(Nibbles::default())?.is_none());
        assert!(cursor.seek(Nibbles::default())?.is_none());
        assert!(cursor.next()?.is_none());
        assert!(cursor.current()?.is_none());

        Ok(())
    }

    /// Test cursor operations with single entry
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_cursor_single_entry<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path = nibbles_from(vec![1, 2, 3]);
        let branch = create_test_branch();

        // Store single entry
        storage.store_account_branches(50, vec![(path, Some(branch.clone()))]).await?;

        let mut cursor = storage.account_trie_cursor(100)?;

        // Test seek_exact
        let result = cursor.seek_exact(path)?.unwrap();
        assert_eq!(result.0, path);

        // Test current position
        assert_eq!(cursor.current()?.unwrap(), path);

        // Test next from end should return None
        assert!(cursor.next()?.is_none());

        Ok(())
    }

    /// Test cursor operations with multiple entries
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_cursor_multiple_entries<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let paths = vec![
            nibbles_from(vec![1]),
            nibbles_from(vec![1, 2]),
            nibbles_from(vec![2]),
            nibbles_from(vec![2, 3]),
        ];
        let branch = create_test_branch();

        // Store multiple entries
        for path in &paths {
            storage.store_account_branches(50, vec![(*path, Some(branch.clone()))]).await?;
        }

        let mut cursor = storage.account_trie_cursor(100)?;

        // Test that we can iterate through all entries
        let mut found_paths = Vec::new();
        while let Some((path, _)) = cursor.next()? {
            found_paths.push(path);
        }

        assert_eq!(found_paths.len(), 4);
        // Paths should be in lexicographic order
        for i in 0..paths.len() {
            assert_eq!(found_paths[i], paths[i]);
        }

        Ok(())
    }

    // =============================================================================
    // 2. Seek Operations
    // =============================================================================

    /// Test `seek_exact` with existing path
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_seek_exact_existing_path<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path = nibbles_from(vec![1, 2, 3]);
        let branch = create_test_branch();

        storage.store_account_branches(50, vec![(path, Some(branch.clone()))]).await?;

        let mut cursor = storage.account_trie_cursor(100)?;
        let result = cursor.seek_exact(path)?.unwrap();
        assert_eq!(result.0, path);

        Ok(())
    }

    /// Test `seek_exact` with non-existing path
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_seek_exact_non_existing_path<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path = nibbles_from(vec![1, 2, 3]);
        let branch = create_test_branch();

        storage.store_account_branches(50, vec![(path, Some(branch.clone()))]).await?;

        let mut cursor = storage.account_trie_cursor(100)?;
        let non_existing = nibbles_from(vec![4, 5, 6]);
        assert!(cursor.seek_exact(non_existing)?.is_none());

        Ok(())
    }

    /// Test `seek_exact` with empty path
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_seek_exact_empty_path<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path = nibbles_from(vec![]);
        let branch = create_test_branch();

        storage.store_account_branches(50, vec![(path, Some(branch.clone()))]).await?;

        let mut cursor = storage.account_trie_cursor(100)?;
        let result = cursor.seek_exact(Nibbles::default())?.unwrap();
        assert_eq!(result.0, Nibbles::default());

        Ok(())
    }

    /// Test seek to existing path
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_seek_to_existing_path<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path = nibbles_from(vec![1, 2, 3]);
        let branch = create_test_branch();

        storage.store_account_branches(50, vec![(path, Some(branch.clone()))]).await?;

        let mut cursor = storage.account_trie_cursor(100)?;
        let result = cursor.seek(path)?.unwrap();
        assert_eq!(result.0, path);

        Ok(())
    }

    /// Test seek between existing nodes
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_seek_between_existing_nodes<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path1 = nibbles_from(vec![1]);
        let path2 = nibbles_from(vec![3]);
        let branch = create_test_branch();

        storage.store_account_branches(50, vec![(path1, Some(branch.clone()))]).await?;
        storage.store_account_branches(50, vec![(path2, Some(branch.clone()))]).await?;

        let mut cursor = storage.account_trie_cursor(100)?;
        // Seek to path between 1 and 3, should return path 3
        let seek_path = nibbles_from(vec![2]);
        let result = cursor.seek(seek_path)?.unwrap();
        assert_eq!(result.0, path2);

        Ok(())
    }

    /// Test seek after all nodes
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_seek_after_all_nodes<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path = nibbles_from(vec![1]);
        let branch = create_test_branch();

        storage.store_account_branches(50, vec![(path, Some(branch.clone()))]).await?;

        let mut cursor = storage.account_trie_cursor(100)?;
        // Seek to path after all nodes
        let seek_path = nibbles_from(vec![9]);
        assert!(cursor.seek(seek_path)?.is_none());

        Ok(())
    }

    /// Test seek before all nodes
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_seek_before_all_nodes<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path = nibbles_from(vec![5]);
        let branch = create_test_branch();

        storage.store_account_branches(50, vec![(path, Some(branch.clone()))]).await?;

        let mut cursor = storage.account_trie_cursor(100)?;
        // Seek to path before all nodes, should return first node
        let seek_path = nibbles_from(vec![1]);
        let result = cursor.seek(seek_path)?.unwrap();
        assert_eq!(result.0, path);

        Ok(())
    }

    // =============================================================================
    // 3. Navigation Tests
    // =============================================================================

    /// Test next without prior seek
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_next_without_prior_seek<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path = nibbles_from(vec![1, 2]);
        let branch = create_test_branch();

        storage.store_account_branches(50, vec![(path, Some(branch.clone()))]).await?;

        let mut cursor = storage.account_trie_cursor(100)?;
        // next() without prior seek should start from beginning
        let result = cursor.next()?.unwrap();
        assert_eq!(result.0, path);

        Ok(())
    }

    /// Test next after seek
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_next_after_seek<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path1 = nibbles_from(vec![1]);
        let path2 = nibbles_from(vec![2]);
        let branch = create_test_branch();

        storage.store_account_branches(50, vec![(path1, Some(branch.clone()))]).await?;
        storage.store_account_branches(50, vec![(path2, Some(branch.clone()))]).await?;

        let mut cursor = storage.account_trie_cursor(100)?;
        cursor.seek(path1)?;

        // next() should return second node
        let result = cursor.next()?.unwrap();
        assert_eq!(result.0, path2);

        Ok(())
    }

    /// Test next at end of trie
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_next_at_end_of_trie<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path = nibbles_from(vec![1]);
        let branch = create_test_branch();

        storage.store_account_branches(50, vec![(path, Some(branch.clone()))]).await?;

        let mut cursor = storage.account_trie_cursor(100)?;
        cursor.seek(path)?;

        // next() at end should return None
        assert!(cursor.next()?.is_none());

        Ok(())
    }

    /// Test multiple consecutive next calls
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_multiple_consecutive_next<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let paths = vec![nibbles_from(vec![1]), nibbles_from(vec![2]), nibbles_from(vec![3])];
        let branch = create_test_branch();

        for path in &paths {
            storage.store_account_branches(50, vec![(*path, Some(branch.clone()))]).await?;
        }

        let mut cursor = storage.account_trie_cursor(100)?;

        // Iterate through all with consecutive next() calls
        for expected_path in &paths {
            let result = cursor.next()?.unwrap();
            assert_eq!(result.0, *expected_path);
        }

        // Final next() should return None
        assert!(cursor.next()?.is_none());

        Ok(())
    }

    /// Test current after operations
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_current_after_operations<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path1 = nibbles_from(vec![1]);
        let path2 = nibbles_from(vec![2]);
        let branch = create_test_branch();

        storage.store_account_branches(50, vec![(path1, Some(branch.clone()))]).await?;
        storage.store_account_branches(50, vec![(path2, Some(branch.clone()))]).await?;

        let mut cursor = storage.account_trie_cursor(100)?;

        // Current should be None initially
        assert!(cursor.current()?.is_none());

        // After seek, current should track position
        cursor.seek(path1)?;
        assert_eq!(cursor.current()?.unwrap(), path1);

        // After next, current should update
        cursor.next()?;
        assert_eq!(cursor.current()?.unwrap(), path2);

        Ok(())
    }

    /// Test current with no prior operations
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_current_no_prior_operations<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let mut cursor = storage.account_trie_cursor(100)?;

        // Current should be None when no operations performed
        assert!(cursor.current()?.is_none());

        Ok(())
    }

    // =============================================================================
    // 4. Block Number Filtering
    // =============================================================================

    /// Test same path with different blocks
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_same_path_different_blocks<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path = nibbles_from(vec![1, 2]);
        let branch1 = create_test_branch();
        let branch2 = create_test_branch_variant();

        // Store same path at different blocks
        storage.store_account_branches(50, vec![(path, Some(branch1.clone()))]).await?;
        storage.store_account_branches(100, vec![(path, Some(branch2.clone()))]).await?;

        // Cursor with max_block_number=75 should see only block 50 data
        let mut cursor75 = storage.account_trie_cursor(75)?;
        let result75 = cursor75.seek_exact(path)?.unwrap();
        assert_eq!(result75.0, path);

        // Cursor with max_block_number=150 should see block 100 data (latest)
        let mut cursor150 = storage.account_trie_cursor(150)?;
        let result150 = cursor150.seek_exact(path)?.unwrap();
        assert_eq!(result150.0, path);

        Ok(())
    }

    /// Test deleted branch nodes
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_deleted_branch_nodes<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path = nibbles_from(vec![1, 2]);
        let branch = create_test_branch();

        // Store branch node, then delete it (store None)
        storage.store_account_branches(50, vec![(path, Some(branch.clone()))]).await?;
        storage.store_account_branches(100, vec![(path, None)]).await?;

        // Cursor before deletion should see the node
        let mut cursor75 = storage.account_trie_cursor(75)?;
        assert!(cursor75.seek_exact(path)?.is_some());

        // Cursor after deletion should not see the node
        let mut cursor150 = storage.account_trie_cursor(150)?;
        assert!(cursor150.seek_exact(path)?.is_none());

        Ok(())
    }

    // =============================================================================
    // 5. Hashed Address Filtering
    // =============================================================================

    /// Test account-specific cursor
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_account_specific_cursor<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path = nibbles_from(vec![1, 2]);
        let addr1 = B256::repeat_byte(0x01);
        let addr2 = B256::repeat_byte(0x02);
        let branch = create_test_branch();

        // Store same path for different accounts (using storage branches)
        storage.store_storage_branches(50, addr1, vec![(path, Some(branch.clone()))]).await?;
        storage.store_storage_branches(50, addr2, vec![(path, Some(branch.clone()))]).await?;

        // Cursor for addr1 should only see addr1 data
        let mut cursor1 = storage.storage_trie_cursor(addr1, 100)?;
        let result1 = cursor1.seek_exact(path)?.unwrap();
        assert_eq!(result1.0, path);

        // Cursor for addr2 should only see addr2 data
        let mut cursor2 = storage.storage_trie_cursor(addr2, 100)?;
        let result2 = cursor2.seek_exact(path)?.unwrap();
        assert_eq!(result2.0, path);

        // Cursor for addr1 should not see addr2 data when iterating
        let mut cursor1_iter = storage.storage_trie_cursor(addr1, 100)?;
        let mut found_count = 0;
        while cursor1_iter.next()?.is_some() {
            found_count += 1;
        }
        assert_eq!(found_count, 1); // Should only see one entry (for addr1)

        Ok(())
    }

    /// Test state trie cursor
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_state_trie_cursor<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path = nibbles_from(vec![1, 2]);
        let addr = B256::repeat_byte(0x01);
        let branch = create_test_branch();

        // Store data for account trie and state trie
        storage.store_storage_branches(50, addr, vec![(path, Some(branch.clone()))]).await?;
        storage.store_account_branches(50, vec![(path, Some(branch.clone()))]).await?;

        // State trie cursor (None address) should only see state trie data
        let mut state_cursor = storage.account_trie_cursor(100)?;
        let result = state_cursor.seek_exact(path)?.unwrap();
        assert_eq!(result.0, path);

        // Verify state cursor doesn't see account data when iterating
        let mut state_cursor_iter = storage.account_trie_cursor(100)?;
        let mut found_count = 0;
        while state_cursor_iter.next()?.is_some() {
            found_count += 1;
        }

        assert_eq!(found_count, 1); // Should only see state trie entry

        Ok(())
    }

    /// Test mixed account and state data
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_mixed_account_state_data<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let path1 = nibbles_from(vec![1]);
        let path2 = nibbles_from(vec![2]);
        let addr = B256::repeat_byte(0x01);
        let branch = create_test_branch();

        // Store mixed account and state trie data
        storage.store_storage_branches(50, addr, vec![(path1, Some(branch.clone()))]).await?;
        storage.store_account_branches(50, vec![(path2, Some(branch.clone()))]).await?;

        // Account cursor should only see account data
        let mut account_cursor = storage.storage_trie_cursor(addr, 100)?;
        let mut account_paths = Vec::new();
        while let Some((path, _)) = account_cursor.next()? {
            account_paths.push(path);
        }
        assert_eq!(account_paths.len(), 1);
        assert_eq!(account_paths[0], path1);

        // State cursor should only see state data
        let mut state_cursor = storage.account_trie_cursor(100)?;
        let mut state_paths = Vec::new();
        while let Some((path, _)) = state_cursor.next()? {
            state_paths.push(path);
        }
        assert_eq!(state_paths.len(), 1);
        assert_eq!(state_paths[0], path2);

        Ok(())
    }

    // =============================================================================
    // 6. Path Ordering Tests
    // =============================================================================

    /// Test lexicographic ordering
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_lexicographic_ordering<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let paths = vec![
            nibbles_from(vec![3, 1]),
            nibbles_from(vec![1, 2]),
            nibbles_from(vec![2]),
            nibbles_from(vec![1]),
        ];
        let branch = create_test_branch();

        // Store paths in random order
        for path in &paths {
            storage.store_account_branches(50, vec![(*path, Some(branch.clone()))]).await?;
        }

        let mut cursor = storage.account_trie_cursor(100)?;
        let mut found_paths = Vec::new();
        while let Some((path, _)) = cursor.next()? {
            found_paths.push(path);
        }

        // Should be returned in lexicographic order: [1], [1,2], [2], [3,1]
        let expected_order = vec![
            nibbles_from(vec![1]),
            nibbles_from(vec![1, 2]),
            nibbles_from(vec![2]),
            nibbles_from(vec![3, 1]),
        ];

        assert_eq!(found_paths, expected_order);

        Ok(())
    }

    /// Test path prefix scenarios
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_path_prefix_scenarios<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let paths = vec![
            nibbles_from(vec![1]),       // Prefix of next
            nibbles_from(vec![1, 2]),    // Extends first
            nibbles_from(vec![1, 2, 3]), // Extends second
        ];
        let branch = create_test_branch();

        for path in &paths {
            storage.store_account_branches(50, vec![(*path, Some(branch.clone()))]).await?;
        }

        let mut cursor = storage.account_trie_cursor(100)?;

        // Seek to prefix should find exact match
        let result = cursor.seek_exact(paths[0])?.unwrap();
        assert_eq!(result.0, paths[0]);

        // Next should go to next path, not skip prefixed paths
        let result = cursor.next()?.unwrap();
        assert_eq!(result.0, paths[1]);

        let result = cursor.next()?.unwrap();
        assert_eq!(result.0, paths[2]);

        Ok(())
    }

    /// Test complex nibble combinations
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_complex_nibble_combinations<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        // Test various nibble patterns including edge values
        let paths = vec![
            nibbles_from(vec![0]),
            nibbles_from(vec![0, 15]),
            nibbles_from(vec![15]),
            nibbles_from(vec![15, 0]),
            nibbles_from(vec![7, 8, 9]),
        ];
        let branch = create_test_branch();

        for path in &paths {
            storage.store_account_branches(50, vec![(*path, Some(branch.clone()))]).await?;
        }

        let mut cursor = storage.account_trie_cursor(100)?;
        let mut found_paths = Vec::new();
        while let Some((path, _)) = cursor.next()? {
            found_paths.push(path);
        }

        // All paths should be found and in correct order
        assert_eq!(found_paths.len(), 5);

        // Verify specific ordering for edge cases
        assert_eq!(found_paths[0], nibbles_from(vec![0]));
        assert_eq!(found_paths[1], nibbles_from(vec![0, 15]));
        assert_eq!(found_paths[4], nibbles_from(vec![15, 0]));

        Ok(())
    }

    // =============================================================================
    // 7. Leaf Node Tests (Hashed Accounts and Storage)
    // =============================================================================

    /// Test store and retrieve single account
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_store_and_retrieve_single_account<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let account_key = B256::repeat_byte(0x01);
        let account = create_test_account();

        // Store account
        storage.store_hashed_accounts(vec![(account_key, Some(account))], 50).await?;

        // Retrieve via cursor
        let mut cursor = storage.account_hashed_cursor(100)?;
        let result = cursor.seek(account_key)?.unwrap();

        assert_eq!(result.0, account_key);
        assert_eq!(result.1.nonce, account.nonce);
        assert_eq!(result.1.balance, account.balance);
        assert_eq!(result.1.bytecode_hash, account.bytecode_hash);

        Ok(())
    }

    /// Test account cursor navigation
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_account_cursor_navigation<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let accounts = [
            (B256::repeat_byte(0x01), create_test_account()),
            (B256::repeat_byte(0x03), create_test_account()),
            (B256::repeat_byte(0x05), create_test_account()),
        ];

        // Store accounts
        let accounts_to_store: Vec<_> = accounts.iter().map(|(k, v)| (*k, Some(*v))).collect();
        storage.store_hashed_accounts(accounts_to_store, 50).await?;

        let mut cursor = storage.account_hashed_cursor(100)?;

        // Test seeking to exact key
        let result = cursor.seek(accounts[1].0)?.unwrap();
        assert_eq!(result.0, accounts[1].0);

        // Test seeking to key that doesn't exist (should return next greater)
        let seek_key = B256::repeat_byte(0x02);
        let result = cursor.seek(seek_key)?.unwrap();
        assert_eq!(result.0, accounts[1].0); // Should find 0x03

        // Test next() navigation
        let result = cursor.next()?.unwrap();
        assert_eq!(result.0, accounts[2].0); // Should find 0x05

        // Test next() at end
        assert!(cursor.next()?.is_none());

        Ok(())
    }

    /// Test account block versioning
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_account_block_versioning<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let account_key = B256::repeat_byte(0x01);
        let account_v1 = create_test_account_with_values(1, 100, 0xBB);
        let account_v2 = create_test_account_with_values(2, 200, 0xDD);

        // Store account at different blocks
        storage.store_hashed_accounts(vec![(account_key, Some(account_v1))], 50).await?;
        storage.store_hashed_accounts(vec![(account_key, Some(account_v2))], 100).await?;

        // Cursor with max_block_number=75 should see v1
        let mut cursor75 = storage.account_hashed_cursor(75)?;
        let result75 = cursor75.seek(account_key)?.unwrap();
        assert_eq!(result75.1.nonce, account_v1.nonce);
        assert_eq!(result75.1.balance, account_v1.balance);

        // Cursor with max_block_number=150 should see v2
        let mut cursor150 = storage.account_hashed_cursor(150)?;
        let result150 = cursor150.seek(account_key)?.unwrap();
        assert_eq!(result150.1.nonce, account_v2.nonce);
        assert_eq!(result150.1.balance, account_v2.balance);

        Ok(())
    }

    /// Test store and retrieve storage
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_store_and_retrieve_storage<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let hashed_address = B256::repeat_byte(0x01);
        let storage_slots = vec![
            (B256::repeat_byte(0x10), U256::from(100)),
            (B256::repeat_byte(0x20), U256::from(200)),
            (B256::repeat_byte(0x30), U256::from(300)),
        ];

        // Store storage slots
        storage.store_hashed_storages(hashed_address, storage_slots.clone(), 50).await?;

        // Retrieve via cursor
        let mut cursor = storage.storage_hashed_cursor(hashed_address, 100)?;

        // Test seeking to each slot
        for (key, expected_value) in &storage_slots {
            let result = cursor.seek(*key)?.unwrap();
            assert_eq!(result.0, *key);
            assert_eq!(result.1, *expected_value);
        }

        Ok(())
    }

    /// Test storage cursor navigation
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_storage_cursor_navigation<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let hashed_address = B256::repeat_byte(0x01);
        let storage_slots = vec![
            (B256::repeat_byte(0x10), U256::from(100)),
            (B256::repeat_byte(0x30), U256::from(300)),
            (B256::repeat_byte(0x50), U256::from(500)),
        ];

        storage.store_hashed_storages(hashed_address, storage_slots.clone(), 50).await?;

        let mut cursor = storage.storage_hashed_cursor(hashed_address, 100)?;

        // Start from beginning with next()
        let mut found_slots = Vec::new();
        while let Some((key, value)) = cursor.next()? {
            found_slots.push((key, value));
        }

        assert_eq!(found_slots.len(), 3);
        assert_eq!(found_slots[0], storage_slots[0]);
        assert_eq!(found_slots[1], storage_slots[1]);
        assert_eq!(found_slots[2], storage_slots[2]);

        Ok(())
    }

    /// Test storage account isolation
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_storage_account_isolation<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let address1 = B256::repeat_byte(0x01);
        let address2 = B256::repeat_byte(0x02);
        let storage_key = B256::repeat_byte(0x10);

        // Store same storage key for different accounts
        storage.store_hashed_storages(address1, vec![(storage_key, U256::from(100))], 50).await?;
        storage.store_hashed_storages(address2, vec![(storage_key, U256::from(200))], 50).await?;

        // Verify each account sees only its own storage
        let mut cursor1 = storage.storage_hashed_cursor(address1, 100)?;
        let result1 = cursor1.seek(storage_key)?.unwrap();
        assert_eq!(result1.1, U256::from(100));

        let mut cursor2 = storage.storage_hashed_cursor(address2, 100)?;
        let result2 = cursor2.seek(storage_key)?.unwrap();
        assert_eq!(result2.1, U256::from(200));

        // Verify cursor1 doesn't see address2's storage
        let mut cursor1_iter = storage.storage_hashed_cursor(address1, 100)?;
        let mut count = 0;
        while cursor1_iter.next()?.is_some() {
            count += 1;
        }
        assert_eq!(count, 1); // Should only see one entry

        Ok(())
    }

    /// Test storage block versioning
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_storage_block_versioning<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let hashed_address = B256::repeat_byte(0x01);
        let storage_key = B256::repeat_byte(0x10);

        // Store storage at different blocks
        storage
            .store_hashed_storages(hashed_address, vec![(storage_key, U256::from(100))], 50)
            .await?;
        storage
            .store_hashed_storages(hashed_address, vec![(storage_key, U256::from(200))], 100)
            .await?;

        // Cursor with max_block_number=75 should see old value
        let mut cursor75 = storage.storage_hashed_cursor(hashed_address, 75)?;
        let result75 = cursor75.seek(storage_key)?.unwrap();
        assert_eq!(result75.1, U256::from(100));

        // Cursor with max_block_number=150 should see new value
        let mut cursor150 = storage.storage_hashed_cursor(hashed_address, 150)?;
        let result150 = cursor150.seek(storage_key)?.unwrap();
        assert_eq!(result150.1, U256::from(200));

        Ok(())
    }

    /// Test storage trie zero value deletion
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_storage_trie_zero_value_deletion<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let hashed_address = B256::repeat_byte(0x01);
        let prev_storage_key = nibbles_from(vec![0x02]);
        let storage_key = nibbles_from(vec![0x03]);

        let branch = create_test_branch();

        // Store non-zero value
        storage
            .store_storage_branches(
                50,
                hashed_address,
                vec![(prev_storage_key, Some(branch.clone())), (storage_key, Some(branch.clone()))],
            )
            .await?;

        // "Delete" by storing zero value
        storage.store_storage_branches(100, hashed_address, vec![(storage_key, None)]).await?;

        // Cursor before deletion should see the value
        let mut cursor75 = storage.storage_trie_cursor(hashed_address, 75)?;
        let result75 = cursor75.seek(storage_key)?.unwrap();
        assert_eq!(result75.1, branch);

        // Cursor after deletion should NOT see the entry (zero values are skipped)
        let mut cursor150 = storage.storage_trie_cursor(hashed_address, 150)?;
        let result150 = cursor150.seek(storage_key)?;
        assert!(result150.is_none(), "Zero values should be skipped/deleted");

        // next() should skip the zero value
        let mut cursor150_iter = storage.storage_trie_cursor(hashed_address, 150)?;
        let mut count = 0;
        while cursor150_iter.next()?.is_some() {
            count += 1;
        }
        assert_eq!(count, 1); // Should only see one entry

        Ok(())
    }

    /// Test storage zero value deletion
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_storage_zero_value_deletion<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let hashed_address = B256::repeat_byte(0x01);
        let prev_storage_key = B256::repeat_byte(0x02);
        let storage_key = B256::repeat_byte(0x10);

        // Store non-zero value
        storage
            .store_hashed_storages(
                hashed_address,
                vec![(prev_storage_key, U256::from(100)), (storage_key, U256::from(100))],
                50,
            )
            .await?;

        // "Delete" by storing zero value
        storage.store_hashed_storages(hashed_address, vec![(storage_key, U256::ZERO)], 100).await?;

        // Cursor before deletion should see the value
        let mut cursor75 = storage.storage_hashed_cursor(hashed_address, 75)?;
        let result75 = cursor75.seek(storage_key)?.unwrap();
        assert_eq!(result75.1, U256::from(100));

        // Cursor after deletion should NOT see the entry (zero values are skipped)
        let mut cursor150 = storage.storage_hashed_cursor(hashed_address, 150)?;
        let result150 = cursor150.seek(storage_key)?;
        assert!(result150.is_none(), "Zero values should be skipped/deleted");

        // next() should skip the zero value
        let mut cursor150_iter = storage.storage_hashed_cursor(hashed_address, 150)?;

        let mut count = 0;
        while cursor150_iter.next()?.is_some() {
            count += 1;
        }
        assert_eq!(count, 1); // Should only see one entry

        Ok(())
    }

    /// Test that zero values are skipped during iteration
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_storage_cursor_skips_zero_values<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let hashed_address = B256::repeat_byte(0x01);

        // Create a mix of non-zero and zero value storage slots
        let storage_slots = vec![
            (B256::repeat_byte(0x10), U256::from(100)), // Non-zero
            (B256::repeat_byte(0x20), U256::ZERO),      // Zero value - should be skipped
            (B256::repeat_byte(0x30), U256::from(300)), // Non-zero
            (B256::repeat_byte(0x40), U256::ZERO),      // Zero value - should be skipped
            (B256::repeat_byte(0x50), U256::from(500)), // Non-zero
        ];

        // Store all slots
        storage.store_hashed_storages(hashed_address, storage_slots.clone(), 50).await?;

        // Create cursor and iterate through all entries
        let mut cursor = storage.storage_hashed_cursor(hashed_address, 100)?;
        let mut found_slots = Vec::new();
        while let Some((key, value)) = cursor.next()? {
            found_slots.push((key, value));
        }

        // Should only find 3 non-zero values
        assert_eq!(found_slots.len(), 3, "Zero values should be skipped during iteration");

        // Verify the non-zero values are the ones we stored
        assert_eq!(found_slots[0], (B256::repeat_byte(0x10), U256::from(100)));
        assert_eq!(found_slots[1], (B256::repeat_byte(0x30), U256::from(300)));
        assert_eq!(found_slots[2], (B256::repeat_byte(0x50), U256::from(500)));

        // Verify seeking to a zero-value slot returns None or skips to next non-zero
        let mut seek_cursor = storage.storage_hashed_cursor(hashed_address, 100)?;
        let seek_result = seek_cursor.seek(B256::repeat_byte(0x20))?;

        // Should either return None or skip to the next non-zero value (0x30)
        if let Some((key, value)) = seek_result {
            assert_eq!(
                key,
                B256::repeat_byte(0x30),
                "Should skip zero value and find next non-zero"
            );
            assert_eq!(value, U256::from(300));
        }

        Ok(())
    }

    /// Test empty cursors
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_empty_cursors<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        // Test empty account cursor
        let mut account_cursor = storage.account_hashed_cursor(100)?;
        assert!(account_cursor.seek(B256::repeat_byte(0x01))?.is_none());
        assert!(account_cursor.next()?.is_none());

        // Test empty storage cursor
        let mut storage_cursor = storage.storage_hashed_cursor(B256::repeat_byte(0x01), 100)?;
        assert!(storage_cursor.seek(B256::repeat_byte(0x10))?.is_none());
        assert!(storage_cursor.next()?.is_none());

        Ok(())
    }

    /// Test cursor boundary conditions
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_cursor_boundary_conditions<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        let account_key = B256::repeat_byte(0x80); // Middle value
        let account = create_test_account();

        storage.store_hashed_accounts(vec![(account_key, Some(account))], 50).await?;

        let mut cursor = storage.account_hashed_cursor(100)?;

        // Seek to minimum key should find our account
        let result = cursor.seek(B256::ZERO)?.unwrap();
        assert_eq!(result.0, account_key);

        // Seek to maximum key should find nothing
        assert!(cursor.seek(B256::repeat_byte(0xFF))?.is_none());

        // Seek to key just before our account should find our account
        let just_before = B256::repeat_byte(0x7F);
        let result = cursor.seek(just_before)?.unwrap();
        assert_eq!(result.0, account_key);

        Ok(())
    }

    /// Test large batch operations
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_large_batch_operations<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        // Create large batch of accounts
        let mut accounts = Vec::new();
        for i in 0..100 {
            let key = B256::from([i as u8; 32]);
            let account = create_test_account_with_values(i, i * 1000, (i + 1) as u8);
            accounts.push((key, Some(account)));
        }

        // Store in batch
        storage.store_hashed_accounts(accounts.clone(), 50).await?;

        // Verify all accounts can be retrieved
        let mut cursor = storage.account_hashed_cursor(100)?;
        let mut found_count = 0;
        while cursor.next()?.is_some() {
            found_count += 1;
        }
        assert_eq!(found_count, 100);

        // Test specific account retrieval
        let test_key = B256::from([42u8; 32]);
        let result = cursor.seek(test_key)?.unwrap();
        assert_eq!(result.0, test_key);
        assert_eq!(result.1.nonce, 42);

        Ok(())
    }

    /// Test wiped storage in `HashedPostState`
    ///
    /// When `store_trie_updates` receives a `HashedPostState` with wiped=true for a storage entry,
    /// it should iterate all existing values for that address and create deletion entries for them.
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[tokio::test]
    async fn test_store_trie_updates_with_wiped_storage<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        use reth_trie::HashedStorage;

        let hashed_address = B256::repeat_byte(0x01);

        // First, store some storage values at block 50
        let storage_slots = vec![
            (B256::repeat_byte(0x10), U256::from(100)),
            (B256::repeat_byte(0x20), U256::from(200)),
            (B256::repeat_byte(0x30), U256::from(300)),
            (B256::repeat_byte(0x40), U256::from(400)),
        ];

        storage.store_hashed_storages(hashed_address, storage_slots.clone(), 50).await?;

        // Verify all values are present at block 75
        let mut cursor75 = storage.storage_hashed_cursor(hashed_address, 75)?;
        let mut found_slots = Vec::new();
        while let Some((key, value)) = cursor75.next()? {
            found_slots.push((key, value));
        }
        assert_eq!(found_slots.len(), 4, "All storage slots should be present before wipe");
        assert_eq!(found_slots[0], (B256::repeat_byte(0x10), U256::from(100)));
        assert_eq!(found_slots[1], (B256::repeat_byte(0x20), U256::from(200)));
        assert_eq!(found_slots[2], (B256::repeat_byte(0x30), U256::from(300)));
        assert_eq!(found_slots[3], (B256::repeat_byte(0x40), U256::from(400)));

        // Now create a HashedPostState with wiped=true for this address at block 100
        let mut post_state = HashedPostState::default();
        let wiped_storage = HashedStorage::new(true); // wiped=true, empty storage map
        post_state.storages.insert(hashed_address, wiped_storage);

        let block_state_diff = BlockStateDiff { trie_updates: TrieUpdates::default(), post_state };

        // Store the wiped state
        storage.store_trie_updates(100, block_state_diff).await?;

        // After wiping, cursor at block 150 should see NO storage values
        let mut cursor150 = storage.storage_hashed_cursor(hashed_address, 150)?;
        let mut found_slots_after_wipe = Vec::new();
        while let Some((key, value)) = cursor150.next()? {
            found_slots_after_wipe.push((key, value));
        }

        assert_eq!(
            found_slots_after_wipe.len(),
            0,
            "All storage slots should be deleted after wipe. Found: {:?}",
            found_slots_after_wipe
        );

        // Verify individual seeks also return None
        for (slot, _) in &storage_slots {
            let mut seek_cursor = storage.storage_hashed_cursor(hashed_address, 150)?;
            let result = seek_cursor.seek(*slot)?;
            assert!(
                result.is_none() || result.unwrap().0 != *slot,
                "Storage slot {:?} should be deleted after wipe",
                slot
            );
        }

        // Verify cursor at block 75 (before wipe) still sees all values
        let mut cursor75_after = storage.storage_hashed_cursor(hashed_address, 75)?;
        let mut found_slots_before_wipe = Vec::new();
        while let Some((key, value)) = cursor75_after.next()? {
            found_slots_before_wipe.push((key, value));
        }
        assert_eq!(
            found_slots_before_wipe.len(),
            4,
            "All storage slots should still be present when querying before wipe block"
        );

        Ok(())
    }

    /// Test that `store_trie_updates` properly stores branch nodes, leaf nodes, and removals
    ///
    /// This test verifies that all data stored via `store_trie_updates` can be read back
    /// through the cursor APIs.
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[tokio::test]
    async fn test_store_trie_updates_comprehensive<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        use reth_trie::{updates::StorageTrieUpdates, HashedStorage};

        let block_number = 100;

        // Create comprehensive trie updates with branches, leaves, and removals
        let mut trie_updates = TrieUpdates::default();

        // Add account branch nodes
        let account_path1 = nibbles_from(vec![1, 2, 3]);
        let account_path2 = nibbles_from(vec![4, 5, 6]);
        let account_branch1 = create_test_branch();
        let account_branch2 = create_test_branch_variant();

        trie_updates.account_nodes.insert(account_path1, account_branch1.clone());
        trie_updates.account_nodes.insert(account_path2, account_branch2.clone());

        // Add removed account nodes
        let removed_account_path = nibbles_from(vec![7, 8, 9]);
        trie_updates.removed_nodes.insert(removed_account_path);

        // Add storage branch nodes for an address
        let hashed_address = B256::repeat_byte(0x42);
        let storage_path1 = nibbles_from(vec![1, 1]);
        let storage_path2 = nibbles_from(vec![2, 2]);
        let storage_branch = create_test_branch();

        let mut storage_trie = StorageTrieUpdates::default();
        storage_trie.storage_nodes.insert(storage_path1, storage_branch.clone());
        storage_trie.storage_nodes.insert(storage_path2, storage_branch.clone());

        // Add removed storage node
        let removed_storage_path = nibbles_from(vec![3, 3]);
        storage_trie.removed_nodes.insert(removed_storage_path);

        trie_updates.insert_storage_updates(hashed_address, storage_trie);

        // Create post state with accounts and storage
        let mut post_state = HashedPostState::default();

        // Add accounts
        let account1_addr = B256::repeat_byte(0x10);
        let account2_addr = B256::repeat_byte(0x20);
        let account1 = create_test_account_with_values(1, 1000, 0xAA);
        let account2 = create_test_account_with_values(2, 2000, 0xBB);

        post_state.accounts.insert(account1_addr, Some(account1));
        post_state.accounts.insert(account2_addr, Some(account2));

        // Add deleted account
        let deleted_account_addr = B256::repeat_byte(0x30);
        post_state.accounts.insert(deleted_account_addr, None);

        // Add storage for an address
        let storage_addr = B256::repeat_byte(0x50);
        let mut hashed_storage = HashedStorage::new(false);
        hashed_storage.storage.insert(B256::repeat_byte(0x01), U256::from(111));
        hashed_storage.storage.insert(B256::repeat_byte(0x02), U256::from(222));
        hashed_storage.storage.insert(B256::repeat_byte(0x03), U256::ZERO); // Deleted storage
        post_state.storages.insert(storage_addr, hashed_storage);

        let block_state_diff = BlockStateDiff { trie_updates, post_state };

        // Store the updates
        storage.store_trie_updates(block_number, block_state_diff).await?;

        // ========== Verify Account Branch Nodes ==========
        let mut account_trie_cursor = storage.account_trie_cursor(block_number + 10)?;

        // Should find the added branches
        let result1 = account_trie_cursor.seek_exact(account_path1)?;
        assert!(result1.is_some(), "Account branch node 1 should be found");
        assert_eq!(result1.unwrap().0, account_path1);

        let result2 = account_trie_cursor.seek_exact(account_path2)?;
        assert!(result2.is_some(), "Account branch node 2 should be found");
        assert_eq!(result2.unwrap().0, account_path2);

        // Removed node should not be found
        let removed_result = account_trie_cursor.seek_exact(removed_account_path)?;
        assert!(removed_result.is_none(), "Removed account node should not be found");

        // ========== Verify Storage Branch Nodes ==========
        let mut storage_trie_cursor =
            storage.storage_trie_cursor(hashed_address, block_number + 10)?;

        let storage_result1 = storage_trie_cursor.seek_exact(storage_path1)?;
        assert!(storage_result1.is_some(), "Storage branch node 1 should be found");

        let storage_result2 = storage_trie_cursor.seek_exact(storage_path2)?;
        assert!(storage_result2.is_some(), "Storage branch node 2 should be found");

        // Removed storage node should not be found
        let removed_storage_result = storage_trie_cursor.seek_exact(removed_storage_path)?;
        assert!(removed_storage_result.is_none(), "Removed storage node should not be found");

        // ========== Verify Account Leaves ==========
        let mut account_cursor = storage.account_hashed_cursor(block_number + 10)?;

        let acc1_result = account_cursor.seek(account1_addr)?;
        assert!(acc1_result.is_some(), "Account 1 should be found");
        assert_eq!(acc1_result.unwrap().0, account1_addr);
        assert_eq!(acc1_result.unwrap().1.nonce, 1);
        assert_eq!(acc1_result.unwrap().1.balance, U256::from(1000));

        let acc2_result = account_cursor.seek(account2_addr)?;
        assert!(acc2_result.is_some(), "Account 2 should be found");
        assert_eq!(acc2_result.unwrap().1.nonce, 2);

        // Deleted account should not be found
        let deleted_acc_result = account_cursor.seek(deleted_account_addr)?;
        assert!(
            deleted_acc_result.is_none() || deleted_acc_result.unwrap().0 != deleted_account_addr,
            "Deleted account should not be found"
        );

        // ========== Verify Storage Leaves ==========
        let mut storage_cursor = storage.storage_hashed_cursor(storage_addr, block_number + 10)?;

        let slot1_result = storage_cursor.seek(B256::repeat_byte(0x01))?;
        assert!(slot1_result.is_some(), "Storage slot 1 should be found");
        assert_eq!(slot1_result.unwrap().1, U256::from(111));

        let slot2_result = storage_cursor.seek(B256::repeat_byte(0x02))?;
        assert!(slot2_result.is_some(), "Storage slot 2 should be found");
        assert_eq!(slot2_result.unwrap().1, U256::from(222));

        // Zero-valued storage should not be found (deleted)
        let slot3_result = storage_cursor.seek(B256::repeat_byte(0x03))?;
        assert!(
            slot3_result.is_none() || slot3_result.unwrap().0 != B256::repeat_byte(0x03),
            "Zero-valued storage slot should not be found"
        );

        // ========== Verify fetch_trie_updates can retrieve the data ==========
        let fetched_diff = storage.fetch_trie_updates(block_number).await?;

        // Check that trie updates are stored
        assert_eq!(
            fetched_diff.trie_updates.account_nodes_ref().len(),
            2,
            "Should have 2 account nodes"
        );
        assert_eq!(
            fetched_diff.trie_updates.storage_tries_ref().len(),
            1,
            "Should have 1 storage trie"
        );

        // Check that post state is stored
        assert_eq!(
            fetched_diff.post_state.accounts.len(),
            3,
            "Should have 3 accounts (including deleted)"
        );
        assert_eq!(fetched_diff.post_state.storages.len(), 1, "Should have 1 storage entry");

        Ok(())
    }

    /// Test that pure deletions (nodes only in removed_nodes) are properly stored
    ///
    /// This test verifies that when a node appears only in `removed_nodes` (not in updates),
    /// it is properly stored as a deletion and subsequent queries return None for that path.
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_pure_deletions_stored_correctly<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        use reth_trie::updates::StorageTrieUpdates;

        // ========== Setup: Store initial branch nodes at block 50 ==========
        let account_path1 = nibbles_from(vec![1, 2, 3]);
        let account_path2 = nibbles_from(vec![4, 5, 6]);
        let storage_path1 = nibbles_from(vec![7, 8, 9]);
        let storage_path2 = nibbles_from(vec![10, 11, 12]);
        let storage_address = B256::repeat_byte(0x42);

        let initial_branch = create_test_branch();

        let mut initial_trie_updates = TrieUpdates::default();
        initial_trie_updates.account_nodes.insert(account_path1, initial_branch.clone());
        initial_trie_updates.account_nodes.insert(account_path2, initial_branch.clone());

        let mut storage_trie = StorageTrieUpdates::default();
        storage_trie.storage_nodes.insert(storage_path1, initial_branch.clone());
        storage_trie.storage_nodes.insert(storage_path2, initial_branch.clone());
        initial_trie_updates.insert_storage_updates(storage_address, storage_trie);

        let initial_diff = BlockStateDiff {
            trie_updates: initial_trie_updates,
            post_state: HashedPostState::default(),
        };

        storage.store_trie_updates(50, initial_diff).await?;

        // Verify initial state exists at block 75
        let mut cursor_75 = storage.account_trie_cursor(75)?;
        assert!(
            cursor_75.seek_exact(account_path1)?.is_some(),
            "Initial account branch 1 should exist at block 75"
        );
        assert!(
            cursor_75.seek_exact(account_path2)?.is_some(),
            "Initial account branch 2 should exist at block 75"
        );

        let mut storage_cursor_75 = storage.storage_trie_cursor(storage_address, 75)?;
        assert!(
            storage_cursor_75.seek_exact(storage_path1)?.is_some(),
            "Initial storage branch 1 should exist at block 75"
        );
        assert!(
            storage_cursor_75.seek_exact(storage_path2)?.is_some(),
            "Initial storage branch 2 should exist at block 75"
        );

        // ========== At block 100: Mark paths as deleted (ONLY in removed_nodes) ==========
        let mut deletion_trie_updates = TrieUpdates::default();

        // Add to removed_nodes ONLY (no updates)
        deletion_trie_updates.removed_nodes.insert(account_path1);

        // Do the same for storage branch
        let mut deletion_storage_trie = StorageTrieUpdates::default();
        deletion_storage_trie.removed_nodes.insert(storage_path1);
        deletion_trie_updates.insert_storage_updates(storage_address, deletion_storage_trie);

        let deletion_diff = BlockStateDiff {
            trie_updates: deletion_trie_updates,
            post_state: HashedPostState::default(),
        };

        storage.store_trie_updates(100, deletion_diff).await?;

        // ========== Verify that deleted nodes return None at block 150 ==========

        // Deleted account branch should not be found
        let mut cursor_150 = storage.account_trie_cursor(150)?;
        let account_result = cursor_150.seek_exact(account_path1)?;
        assert!(account_result.is_none(), "Deleted account branch should return None at block 150");

        // Non-deleted account branch should still exist
        let account_result2 = cursor_150.seek_exact(account_path2)?;
        assert!(
            account_result2.is_some(),
            "Non-deleted account branch should still exist at block 150"
        );

        // Deleted storage branch should not be found
        let mut storage_cursor_150 = storage.storage_trie_cursor(storage_address, 150)?;
        let storage_result = storage_cursor_150.seek_exact(storage_path1)?;
        assert!(storage_result.is_none(), "Deleted storage branch should return None at block 150");

        // Non-deleted storage branch should still exist
        let storage_result2 = storage_cursor_150.seek_exact(storage_path2)?;
        assert!(
            storage_result2.is_some(),
            "Non-deleted storage branch should still exist at block 150"
        );

        // ========== Verify that the nodes still exist at block 75 (before deletion) ==========
        let mut cursor_75_after = storage.account_trie_cursor(75)?;
        assert!(
            cursor_75_after.seek_exact(account_path1)?.is_some(),
            "Deleted node should still exist at block 75 (before deletion)"
        );

        let mut storage_cursor_75_after = storage.storage_trie_cursor(storage_address, 75)?;
        assert!(
            storage_cursor_75_after.seek_exact(storage_path1)?.is_some(),
            "Deleted storage node should still exist at block 75 (before deletion)"
        );

        // ========== Verify iteration skips deleted nodes ==========
        let mut cursor_iter = storage.account_trie_cursor(150)?;
        let mut found_paths = Vec::new();
        while let Some((path, _)) = cursor_iter.next()? {
            found_paths.push(path);
        }

        assert!(!found_paths.contains(&account_path1), "Iteration should skip deleted node");
        assert!(found_paths.contains(&account_path2), "Iteration should include non-deleted node");

        Ok(())
    }

    /// Test that updates take precedence over removals when both are present
    ///
    /// This test verifies that when a path appears in both `removed_nodes` and `account_nodes`,
    /// the update from `account_nodes` takes precedence. This is critical for correctness
    /// when processing trie updates that both remove and update the same node.
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_updates_take_precedence_over_removals<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        use reth_trie::updates::StorageTrieUpdates;

        // ========== Setup: Store initial branch nodes at block 50 ==========
        let account_path = nibbles_from(vec![1, 2, 3]);
        let storage_path = nibbles_from(vec![4, 5, 6]);
        let storage_address = B256::repeat_byte(0x42);

        let initial_branch = create_test_branch();

        let mut initial_trie_updates = TrieUpdates::default();
        initial_trie_updates.account_nodes.insert(account_path, initial_branch.clone());

        let mut storage_trie = StorageTrieUpdates::default();
        storage_trie.storage_nodes.insert(storage_path, initial_branch.clone());
        initial_trie_updates.insert_storage_updates(storage_address, storage_trie);

        let initial_diff = BlockStateDiff {
            trie_updates: initial_trie_updates,
            post_state: HashedPostState::default(),
        };

        storage.store_trie_updates(50, initial_diff).await?;

        // Verify initial state exists at block 75
        let mut cursor_75 = storage.account_trie_cursor(75)?;
        assert!(
            cursor_75.seek_exact(account_path)?.is_some(),
            "Initial account branch should exist at block 75"
        );

        let mut storage_cursor_75 = storage.storage_trie_cursor(storage_address, 75)?;
        assert!(
            storage_cursor_75.seek_exact(storage_path)?.is_some(),
            "Initial storage branch should exist at block 75"
        );

        // ========== At block 100: Add paths to BOTH removed_nodes AND account_nodes ==========
        // This simulates a scenario where a node is both removed and updated
        // The update should take precedence
        let updated_branch = create_test_branch_variant();

        let mut conflicting_trie_updates = TrieUpdates::default();

        // Add to removed_nodes
        conflicting_trie_updates.removed_nodes.insert(account_path);

        // Also add to account_nodes (this should take precedence)
        conflicting_trie_updates.account_nodes.insert(account_path, updated_branch.clone());

        // Do the same for storage branch
        let mut conflicting_storage_trie = StorageTrieUpdates::default();
        conflicting_storage_trie.removed_nodes.insert(storage_path);
        conflicting_storage_trie.storage_nodes.insert(storage_path, updated_branch.clone());
        conflicting_trie_updates.insert_storage_updates(storage_address, conflicting_storage_trie);

        let conflicting_diff = BlockStateDiff {
            trie_updates: conflicting_trie_updates,
            post_state: HashedPostState::default(),
        };

        storage.store_trie_updates(100, conflicting_diff).await?;

        // ========== Verify that updates took precedence at block 150 ==========

        // Account branch should exist (not deleted) with the updated value
        let mut cursor_150 = storage.account_trie_cursor(150)?;
        let account_result = cursor_150.seek_exact(account_path)?;
        assert!(
            account_result.is_some(),
            "Account branch should exist at block 150 (update should take precedence over removal)"
        );
        let (found_path, found_branch) = account_result.unwrap();
        assert_eq!(found_path, account_path);
        // Verify it's the updated branch, not the initial one
        assert_eq!(
            found_branch.state_mask, updated_branch.state_mask,
            "Account branch should be the updated version, not the initial one"
        );

        // Storage branch should exist (not deleted) with the updated value
        let mut storage_cursor_150 = storage.storage_trie_cursor(storage_address, 150)?;
        let storage_result = storage_cursor_150.seek_exact(storage_path)?;
        assert!(
            storage_result.is_some(),
            "Storage branch should exist at block 150 (update should take precedence over removal)"
        );
        let (found_storage_path, found_storage_branch) = storage_result.unwrap();
        assert_eq!(found_storage_path, storage_path);
        // Verify it's the updated branch
        assert_eq!(
            found_storage_branch.state_mask, updated_branch.state_mask,
            "Storage branch should be the updated version, not the initial one"
        );

        // ========== Verify that the old version still exists at block 75 ==========
        let mut cursor_75_after = storage.account_trie_cursor(75)?;
        let result_75 = cursor_75_after.seek_exact(account_path)?;
        assert!(result_75.is_some(), "Initial version should still exist at block 75");
        let (_, branch_75) = result_75.unwrap();
        assert_eq!(
            branch_75.state_mask, initial_branch.state_mask,
            "Block 75 should see the initial branch, not the updated one"
        );

        Ok(())
    }

    /// Test that `replace_updates` properly applies hashed/trie storage updates to the DB
    ///
    /// This test verifies the bug fix where `replace_updates` was only storing `trie_updates`
    /// and `post_states` directly without populating the internal data structures
    /// (`hashed_accounts`, `hashed_storages`, `account_branches`, `storage_branches`).
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[tokio::test]
    async fn test_replace_updates_applies_all_updates<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        use reth_trie::{updates::StorageTrieUpdates, HashedStorage};

        // ========== Setup: Store initial state at blocks 50, 100, 101 ==========
        let initial_account_addr = B256::repeat_byte(0x10);
        let initial_account = create_test_account_with_values(1, 1000, 0xAA);

        let initial_storage_addr = B256::repeat_byte(0x20);
        let initial_storage_slot = B256::repeat_byte(0x01);
        let initial_storage_value = U256::from(100);

        let initial_branch_path = nibbles_from(vec![1, 2, 3]);
        let initial_branch = create_test_branch();

        // Store initial data at block 50
        let mut initial_trie_updates_50 = TrieUpdates::default();
        initial_trie_updates_50.account_nodes.insert(initial_branch_path, initial_branch.clone());

        let mut initial_post_state_50 = HashedPostState::default();
        initial_post_state_50.accounts.insert(initial_account_addr, Some(initial_account));

        let initial_diff_50 = BlockStateDiff {
            trie_updates: initial_trie_updates_50,
            post_state: initial_post_state_50,
        };
        storage.store_trie_updates(50, initial_diff_50).await?;

        // Store data at block 100 (common block)
        let mut initial_trie_updates_100 = TrieUpdates::default();
        let common_branch_path = nibbles_from(vec![4, 5, 6]);
        initial_trie_updates_100.account_nodes.insert(common_branch_path, initial_branch.clone());

        let mut initial_post_state_100 = HashedPostState::default();
        let mut initial_storage_100 = HashedStorage::new(false);
        initial_storage_100.storage.insert(initial_storage_slot, initial_storage_value);
        initial_post_state_100.storages.insert(initial_storage_addr, initial_storage_100);

        let initial_diff_100 = BlockStateDiff {
            trie_updates: initial_trie_updates_100,
            post_state: initial_post_state_100,
        };
        storage.store_trie_updates(100, initial_diff_100).await?;

        // Store data at block 101 (will be replaced)
        let mut initial_trie_updates_101 = TrieUpdates::default();
        let old_branch_path = nibbles_from(vec![7, 8, 9]);
        initial_trie_updates_101.account_nodes.insert(old_branch_path, initial_branch.clone());

        let mut initial_post_state_101 = HashedPostState::default();
        let old_account_addr = B256::repeat_byte(0x30);
        let old_account = create_test_account_with_values(99, 9999, 0xFF);
        initial_post_state_101.accounts.insert(old_account_addr, Some(old_account));

        let initial_diff_101 = BlockStateDiff {
            trie_updates: initial_trie_updates_101,
            post_state: initial_post_state_101,
        };
        storage.store_trie_updates(101, initial_diff_101).await?;

        // ========== Verify initial state exists ==========
        // Verify block 50 data exists
        let mut cursor_initial = storage.account_trie_cursor(75)?;
        assert!(
            cursor_initial.seek_exact(initial_branch_path)?.is_some(),
            "Initial branch should exist before replace"
        );

        // Verify block 101 old data exists
        let mut cursor_old = storage.account_trie_cursor(150)?;
        assert!(
            cursor_old.seek_exact(old_branch_path)?.is_some(),
            "Old branch at block 101 should exist before replace"
        );

        let mut account_cursor_old = storage.account_hashed_cursor(150)?;
        assert!(
            account_cursor_old.seek(old_account_addr)?.is_some(),
            "Old account at block 101 should exist before replace"
        );

        // ========== Call replace_updates to replace blocks after 100 ==========
        let mut blocks_to_add: HashMap<u64, BlockStateDiff> = HashMap::default();

        // New data for block 101
        let new_account_addr = B256::repeat_byte(0x40);
        let new_account = create_test_account_with_values(5, 5000, 0xCC);

        let new_storage_addr = B256::repeat_byte(0x50);
        let new_storage_slot = B256::repeat_byte(0x02);
        let new_storage_value = U256::from(999);

        let new_branch_path = nibbles_from(vec![10, 11, 12]);
        let new_branch = create_test_branch_variant();

        let storage_branch_path = nibbles_from(vec![5, 5]);
        let storage_hashed_addr = B256::repeat_byte(0x60);

        let mut new_trie_updates = TrieUpdates::default();
        new_trie_updates.account_nodes.insert(new_branch_path, new_branch.clone());

        // Add storage trie updates
        let mut storage_trie = StorageTrieUpdates::default();
        storage_trie.storage_nodes.insert(storage_branch_path, new_branch.clone());
        new_trie_updates.insert_storage_updates(storage_hashed_addr, storage_trie);

        let mut new_post_state = HashedPostState::default();
        new_post_state.accounts.insert(new_account_addr, Some(new_account));

        let mut new_storage = HashedStorage::new(false);
        new_storage.storage.insert(new_storage_slot, new_storage_value);
        new_post_state.storages.insert(new_storage_addr, new_storage);

        blocks_to_add.insert(
            101,
            BlockStateDiff { trie_updates: new_trie_updates, post_state: new_post_state },
        );

        // New data for block 102
        let block_102_account_addr = B256::repeat_byte(0x70);
        let block_102_account = create_test_account_with_values(10, 10000, 0xDD);

        let mut trie_updates_102 = TrieUpdates::default();
        let block_102_branch_path = nibbles_from(vec![15, 14, 13]);
        trie_updates_102.account_nodes.insert(block_102_branch_path, new_branch.clone());

        let mut post_state_102 = HashedPostState::default();
        post_state_102.accounts.insert(block_102_account_addr, Some(block_102_account));

        blocks_to_add.insert(
            102,
            BlockStateDiff { trie_updates: trie_updates_102, post_state: post_state_102 },
        );

        // Execute replace_updates
        storage.replace_updates(100, blocks_to_add).await?;

        // ========== Verify that data up to block 100 still exists ==========
        let mut cursor_50 = storage.account_trie_cursor(75)?;
        assert!(
            cursor_50.seek_exact(initial_branch_path)?.is_some(),
            "Block 50 branch should still exist after replace"
        );

        let mut cursor_100 = storage.account_trie_cursor(100)?;
        assert!(
            cursor_100.seek_exact(common_branch_path)?.is_some(),
            "Block 100 branch should still exist after replace"
        );

        let mut storage_cursor_100 = storage.storage_hashed_cursor(initial_storage_addr, 100)?;
        let result_100 = storage_cursor_100.seek(initial_storage_slot)?;
        assert!(result_100.is_some(), "Block 100 storage should still exist after replace");
        assert_eq!(
            result_100.unwrap().1,
            initial_storage_value,
            "Block 100 storage value should be unchanged"
        );

        // ========== Verify that old data after block 100 is gone ==========
        let mut cursor_old_gone = storage.account_trie_cursor(150)?;
        assert!(
            cursor_old_gone.seek_exact(old_branch_path)?.is_none(),
            "Old branch at block 101 should be removed after replace"
        );

        let mut account_cursor_old_gone = storage.account_hashed_cursor(150)?;
        let old_acc_result = account_cursor_old_gone.seek(old_account_addr)?;
        assert!(
            old_acc_result.is_none() || old_acc_result.unwrap().0 != old_account_addr,
            "Old account at block 101 should be removed after replace"
        );

        // ========== Verify new data is properly accessible via cursors ==========

        // Verify new account branch nodes
        let mut trie_cursor = storage.account_trie_cursor(150)?;
        let branch_result = trie_cursor.seek_exact(new_branch_path)?;
        assert!(branch_result.is_some(), "New account branch should be accessible via cursor");
        assert_eq!(branch_result.unwrap().0, new_branch_path);

        // Verify new storage branch nodes
        let mut storage_trie_cursor = storage.storage_trie_cursor(storage_hashed_addr, 150)?;
        let storage_branch_result = storage_trie_cursor.seek_exact(storage_branch_path)?;
        assert!(
            storage_branch_result.is_some(),
            "New storage branch should be accessible via cursor"
        );
        assert_eq!(storage_branch_result.unwrap().0, storage_branch_path);

        // Verify new hashed accounts
        let mut account_cursor = storage.account_hashed_cursor(150)?;
        let account_result = account_cursor.seek(new_account_addr)?;
        assert!(account_result.is_some(), "New account should be accessible via cursor");
        assert_eq!(account_result.as_ref().unwrap().0, new_account_addr);
        assert_eq!(account_result.as_ref().unwrap().1.nonce, new_account.nonce);
        assert_eq!(account_result.as_ref().unwrap().1.balance, new_account.balance);
        assert_eq!(account_result.as_ref().unwrap().1.bytecode_hash, new_account.bytecode_hash);

        // Verify new hashed storages
        let mut storage_cursor = storage.storage_hashed_cursor(new_storage_addr, 150)?;
        let storage_result = storage_cursor.seek(new_storage_slot)?;
        assert!(storage_result.is_some(), "New storage should be accessible via cursor");
        assert_eq!(storage_result.as_ref().unwrap().0, new_storage_slot);
        assert_eq!(storage_result.as_ref().unwrap().1, new_storage_value);

        // Verify block 102 data
        let mut trie_cursor_102 = storage.account_trie_cursor(150)?;
        let branch_result_102 = trie_cursor_102.seek_exact(block_102_branch_path)?;
        assert!(branch_result_102.is_some(), "Block 102 branch should be accessible");
        assert_eq!(branch_result_102.unwrap().0, block_102_branch_path);

        let mut account_cursor_102 = storage.account_hashed_cursor(150)?;
        let account_result_102 = account_cursor_102.seek(block_102_account_addr)?;
        assert!(account_result_102.is_some(), "Block 102 account should be accessible");
        assert_eq!(account_result_102.as_ref().unwrap().0, block_102_account_addr);
        assert_eq!(account_result_102.as_ref().unwrap().1.nonce, block_102_account.nonce);

        // Verify fetch_trie_updates returns the new data
        let fetched_101 = storage.fetch_trie_updates(101).await?;
        assert_eq!(
            fetched_101.trie_updates.account_nodes_ref().len(),
            1,
            "Should have 1 account branch node at block 101"
        );
        assert!(
            fetched_101.trie_updates.account_nodes_ref().contains_key(&new_branch_path),
            "New branch path should be in trie_updates"
        );
        assert_eq!(fetched_101.post_state.accounts.len(), 1, "Should have 1 account at block 101");
        assert!(
            fetched_101.post_state.accounts.contains_key(&new_account_addr),
            "New account should be in post_state"
        );

        Ok(())
    }

    /// Test block number ordering with many random updates using store_trie_updates
    ///
    /// This test creates many branch nodes via store_trie_updates, stores them OUT OF ORDER,
    /// and verifies that queries at different block numbers return the correct version.
    /// This is designed to catch bugs where `append_dup` is used instead of `upsert` in
    /// store_trie_updates, which would fail when blocks aren't stored in strict ascending order.
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_block_number_ordering_stress<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        use rand::{Rng, SeedableRng};

        // Use a fixed seed for reproducibility
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        // Create a set of paths to work with
        let num_paths = 50;
        let num_blocks = 100;
        let mut paths = Vec::new();
        for i in 0..num_paths {
            paths.push(nibbles_from(vec![
                (i % 16) as u8,
                ((i / 16) % 16) as u8,
                ((i / 256) % 16) as u8,
            ]));
        }

        // Track the expected state at each block for each path
        // None means deleted, Some(branch_variant) means present with that variant
        let mut block_updates: HashMap<u64, Vec<(Nibbles, Option<BranchNodeCompact>)>> =
            HashMap::default();

        // Initialize all paths at block 10
        let initial_branch = create_test_branch();
        for path in &paths {
            block_updates.entry(10).or_default().push((*path, Some(initial_branch.clone())));
        }

        // For each subsequent block, randomly update/delete some paths
        for block in 11..=num_blocks {
            // Randomly select which paths to update in this block
            let num_updates = rng.random_range(5..=20);
            let mut selected_indices = std::collections::HashSet::new();
            while selected_indices.len() < num_updates {
                let idx = rng.random_range(0..num_paths);
                selected_indices.insert(idx);
            }

            for idx in selected_indices {
                let path = paths[idx];
                let operation = rng.random_range(0..10);
                if operation < 3 {
                    // 30% chance: Delete the path
                    block_updates.entry(block).or_default().push((path, None));
                } else if operation < 7 {
                    // 40% chance: Update with variant branch
                    let variant_branch = create_test_branch_variant();
                    block_updates.entry(block).or_default().push((path, Some(variant_branch)));
                } else {
                    // 30% chance: Update with initial branch
                    let initial_branch = create_test_branch();
                    block_updates.entry(block).or_default().push((path, Some(initial_branch)));
                }
            }
        }

        // Store blocks in RANDOM ORDER to expose append_dup bug
        let mut block_numbers: Vec<u64> = (10..=num_blocks).collect();
        for i in (1..block_numbers.len()).rev() {
            let j = rng.random_range(0..=i);
            block_numbers.swap(i, j);
        }

        // Store using store_trie_updates (not store_account_branches)
        for block_number in &block_numbers {
            if let Some(updates) = block_updates.get(block_number) {
                let mut trie_updates = TrieUpdates::default();
                for (path, branch_opt) in updates {
                    if let Some(branch) = branch_opt {
                        trie_updates.account_nodes.insert(*path, branch.clone());
                    } else {
                        trie_updates.removed_nodes.insert(*path);
                    }
                }

                let block_state_diff =
                    BlockStateDiff { trie_updates, post_state: HashedPostState::default() };

                storage.store_trie_updates(*block_number, block_state_diff).await?;
            }
        }

        // Build the cumulative state at each block (applying updates in chronological order)
        let mut cumulative_state: HashMap<u64, HashMap<Nibbles, Option<u8>>> = HashMap::default();
        for block in 10..=num_blocks {
            let mut state = if block == 10 {
                HashMap::default()
            } else {
                cumulative_state.get(&(block - 1)).cloned().unwrap_or_default()
            };

            // Apply changes at this block
            if let Some(updates) = block_updates.get(&block) {
                for (path, branch_opt) in updates {
                    let variant = if let Some(branch) = branch_opt {
                        // Determine which variant it is
                        if branch.state_mask == create_test_branch().state_mask {
                            Some(0) // initial
                        } else {
                            Some(1) // variant
                        }
                    } else {
                        None // deleted
                    };
                    state.insert(*path, variant);
                }
            }

            cumulative_state.insert(block, state);
        }

        // Now verify that querying at each block returns the correct state
        for query_block in 10..=num_blocks {
            let mut cursor = storage.account_trie_cursor(query_block)?;
            let expected = cumulative_state.get(&query_block).unwrap();

            // Check each path individually
            for path in &paths {
                let result = cursor.seek_exact(*path)?;
                let expected_value = expected.get(path);

                match expected_value {
                    Some(Some(variant)) => {
                        assert!(
                            result.is_some(),
                            "Block {}: Path {:?} should exist but was not found",
                            query_block,
                            path
                        );
                        let (found_path, found_branch) = result.unwrap();
                        assert_eq!(found_path, *path);

                        // Verify it's the correct variant
                        let expected_branch = if *variant == 0 {
                            create_test_branch()
                        } else {
                            create_test_branch_variant()
                        };
                        assert_eq!(
                            found_branch.state_mask, expected_branch.state_mask,
                            "Block {}: Path {:?} has wrong variant (expected {}, found mask {:?})",
                            query_block, path, variant, found_branch.state_mask
                        );
                    }
                    Some(None) => {
                        assert!(
                            result.is_none(),
                            "Block {}: Path {:?} should be deleted but was found with value {:?}",
                            query_block,
                            path,
                            result
                        );
                    }
                    None => {
                        // Path has never been set at this block, should not exist
                        assert!(
                            result.is_none(),
                            "Block {}: Path {:?} should not exist but was found with value {:?}",
                            query_block,
                            path,
                            result
                        );
                    }
                }
            }

            // Verify iteration returns all non-deleted paths
            let mut cursor_iter = storage.account_trie_cursor(query_block)?;
            let mut found_paths = Vec::new();
            while let Some((path, _)) = cursor_iter.next()? {
                found_paths.push(path);
            }

            let expected_paths: Vec<_> = expected
                .iter()
                .filter_map(
                    |(path, value)| {
                        if matches!(value, Some(_)) {
                            Some(*path)
                        } else {
                            None
                        }
                    },
                )
                .collect();

            assert_eq!(
                found_paths.len(),
                expected_paths.len(),
                "Block {}: Iteration found {} paths but expected {}",
                query_block,
                found_paths.len(),
                expected_paths.len()
            );

            // Verify all expected paths are in found_paths
            for expected_path in &expected_paths {
                assert!(
                    found_paths.contains(expected_path),
                    "Block {}: Expected path {:?} not found in iteration",
                    query_block,
                    expected_path
                );
            }
        }

        Ok(())
    }

    /// Test block number ordering with storage branches
    ///
    /// Similar to the account branch test, but for storage branches which have both
    /// an address and a path component in the key.
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_storage_block_number_ordering_stress<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(123);

        // Create multiple addresses
        let addresses =
            vec![B256::repeat_byte(0x01), B256::repeat_byte(0x02), B256::repeat_byte(0x03)];

        // Create paths for each address
        let num_paths = 20;
        let num_blocks = 50;
        let mut paths = Vec::new();
        for i in 0..num_paths {
            paths.push(nibbles_from(vec![(i % 16) as u8, ((i / 16) % 16) as u8]));
        }

        // Track expected state: (address, path) -> block -> Option<variant>
        let mut expected_state: HashMap<(B256, Nibbles), HashMap<u64, Option<u8>>> =
            HashMap::default();

        // Initialize all combinations at block 10
        let initial_branch = create_test_branch();
        for addr in &addresses {
            for path in &paths {
                storage
                    .store_storage_branches(10, *addr, vec![(*path, Some(initial_branch.clone()))])
                    .await?;
                expected_state.entry((*addr, *path)).or_default().insert(10, Some(0));
            }
        }

        // Randomly update storage branches across blocks
        for block in 11..=num_blocks {
            // For each address, randomly update some paths
            for addr in &addresses {
                let num_updates = rng.random_range(3..=8);
                let mut selected_indices = std::collections::HashSet::new();
                while selected_indices.len() < num_updates {
                    let idx = rng.random_range(0..num_paths);
                    selected_indices.insert(idx);
                }

                let mut updates = Vec::new();
                for idx in selected_indices {
                    let path = paths[idx];
                    let operation = rng.random_range(0..10);
                    if operation < 2 {
                        // 20% chance: Delete
                        updates.push((path, None));
                        expected_state.entry((*addr, path)).or_default().insert(block, None);
                    } else if operation < 6 {
                        // 40% chance: Variant
                        let variant_branch = create_test_branch_variant();
                        updates.push((path, Some(variant_branch)));
                        expected_state.entry((*addr, path)).or_default().insert(block, Some(1));
                    } else {
                        // 40% chance: Initial
                        let initial_branch = create_test_branch();
                        updates.push((path, Some(initial_branch)));
                        expected_state.entry((*addr, path)).or_default().insert(block, Some(0));
                    }
                }

                if !updates.is_empty() {
                    storage.store_storage_branches(block, *addr, updates).await?;
                }
            }
        }

        // Verify results at each block
        for query_block in 10..=num_blocks {
            for addr in &addresses {
                let mut cursor = storage.storage_trie_cursor(*addr, query_block)?;

                for path in &paths {
                    // Find the latest value up to query_block
                    let mut latest_value = None;
                    if let Some(block_values) = expected_state.get(&(*addr, *path)) {
                        for block in 10..=query_block {
                            if let Some(value) = block_values.get(&block) {
                                latest_value = Some(*value);
                            }
                        }
                    }

                    let result = cursor.seek_exact(*path)?;

                    match latest_value {
                        Some(Some(variant)) => {
                            assert!(
                                result.is_some(),
                                "Block {}, Addr {:?}, Path {:?}: Expected variant {} but not found",
                                query_block,
                                addr,
                                path,
                                variant
                            );
                            let (found_path, found_branch) = result.unwrap();
                            assert_eq!(found_path, *path);

                            let expected_branch = if variant == 0 {
                                create_test_branch()
                            } else {
                                create_test_branch_variant()
                            };
                            assert_eq!(
                                found_branch.state_mask, expected_branch.state_mask,
                                "Block {}, Addr {:?}, Path {:?}: Wrong variant",
                                query_block, addr, path
                            );
                        }
                        Some(None) | None => {
                            assert!(
                                result.is_none(),
                                "Block {}, Addr {:?}, Path {:?}: Should be deleted",
                                query_block,
                                addr,
                                path
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Test hashed account block number ordering with many updates
    ///
    /// Tests that hashed accounts are correctly versioned across blocks even when
    /// the same address is updated multiple times.
    #[test_case(InMemoryProofsStorage::new(); "InMemory")]
    #[test_case(MdbxOpProofsStorage::new_test().unwrap(); "MDBX")]
    #[tokio::test]
    async fn test_hashed_account_block_ordering_stress<S: OpProofsStorage>(
        storage: S,
    ) -> Result<(), OpProofsStorageError> {
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(456);

        // Create a set of account addresses
        let num_accounts = 30;
        let num_blocks = 50;
        let mut addresses = Vec::new();
        for i in 0..num_accounts {
            addresses.push(B256::from([i as u8; 32]));
        }

        // Track expected state: address -> block -> Option<(nonce, balance)>
        let mut expected_state: HashMap<B256, HashMap<u64, Option<(u64, u64)>>> =
            HashMap::default();

        // Initialize all accounts at block 10
        for (i, addr) in addresses.iter().enumerate() {
            let account = create_test_account_with_values(i as u64, i as u64 * 100, 0xAA);
            storage.store_hashed_accounts(vec![(*addr, Some(account))], 10).await?;
            expected_state.entry(*addr).or_default().insert(10, Some((i as u64, i as u64 * 100)));
        }

        // Randomly update accounts across blocks
        for block in 11..=num_blocks {
            let num_updates = rng.random_range(8..=15);
            let mut selected_indices = std::collections::HashSet::new();
            while selected_indices.len() < num_updates {
                let idx = rng.random_range(0..num_accounts);
                selected_indices.insert(idx);
            }

            let mut updates = Vec::new();
            for idx in selected_indices {
                let addr = addresses[idx];
                let operation = rng.random_range(0..10);
                if operation < 2 {
                    // 20% chance: Delete account
                    updates.push((addr, None));
                    expected_state.entry(addr).or_default().insert(block, None);
                } else {
                    // 80% chance: Update account with new values
                    let nonce = block * 10 + rng.random_range(0..10);
                    let balance = block * 1000 + rng.random_range(0..1000);
                    let account = create_test_account_with_values(nonce, balance, 0xBB);
                    updates.push((addr, Some(account)));
                    expected_state.entry(addr).or_default().insert(block, Some((nonce, balance)));
                }
            }

            storage.store_hashed_accounts(updates, block).await?;
        }

        // Verify results at each block
        for query_block in 10..=num_blocks {
            let mut cursor = storage.account_hashed_cursor(query_block)?;

            for addr in &addresses {
                // Find the latest value up to query_block
                let mut latest_value = None;
                if let Some(block_values) = expected_state.get(addr) {
                    for block in 10..=query_block {
                        if let Some(value) = block_values.get(&block) {
                            latest_value = Some(*value);
                        }
                    }
                }

                let result = cursor.seek(*addr)?;

                match latest_value {
                    Some(Some((expected_nonce, expected_balance))) => {
                        assert!(
                            result.is_some(),
                            "Block {}, Addr {:?}: Account should exist",
                            query_block,
                            addr
                        );
                        let (found_addr, found_account) = result.unwrap();
                        assert_eq!(found_addr, *addr);
                        assert_eq!(
                            found_account.nonce, expected_nonce,
                            "Block {}, Addr {:?}: Wrong nonce",
                            query_block, addr
                        );
                        assert_eq!(
                            found_account.balance,
                            U256::from(expected_balance),
                            "Block {}, Addr {:?}: Wrong balance",
                            query_block,
                            addr
                        );
                    }
                    Some(None) | None => {
                        // Account should be deleted or not exist
                        if let Some((found_addr, _)) = result {
                            assert_ne!(
                                found_addr, *addr,
                                "Block {}, Addr {:?}: Account should be deleted",
                                query_block, addr
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
