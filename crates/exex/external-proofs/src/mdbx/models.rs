//! Custom data models for MDBX external storage
//!
//! This module defines composite key types used for efficient indexing in MDBX tables.

use alloy_primitives::B256;
use bytes::{Buf, BufMut};
use reth_codecs::Compact;
use reth_db_api::{
    table::{Compress, Decode, Decompress, Encode},
    DatabaseError,
};
use reth_primitives_traits::Account;
use reth_trie::{BranchNodeCompact, StoredNibbles, StoredNibblesSubKey};
use serde::{Deserialize, Serialize};

use super::codec::MaybeDeleted;

// ============================================================================
// Composite Keys for History Tables
// ============================================================================

/// Composite key: (hashed_address, path) for storage trie branches
///
/// Used to efficiently index storage branches by both account address and trie path.
/// The encoding ensures lexicographic ordering: first by address, then by path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StorageBranchSubKey {
    /// Hashed account address
    pub hashed_address: B256,
    /// Trie path as nibbles
    pub path: StoredNibbles,
}

impl StorageBranchSubKey {
    /// Create a new storage branch key
    pub const fn new(hashed_address: B256, path: StoredNibbles) -> Self {
        Self { hashed_address, path }
    }
}

impl Encode for StorageBranchSubKey {
    type Encoded = Vec<u8>;

    fn encode(self) -> Self::Encoded {
        let mut buf = Vec::with_capacity(32 + self.path.0.len());
        // First encode the address (32 bytes)
        buf.extend_from_slice(self.hashed_address.as_slice());
        // Then encode the path
        buf.extend_from_slice(&self.path.encode());
        buf
    }
}

impl Decode for StorageBranchSubKey {
    fn decode(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.len() < 32 {
            return Err(DatabaseError::Decode);
        }

        // First 32 bytes are the address
        let hashed_address = B256::from_slice(&value[..32]);

        // Remaining bytes are the path
        let path = StoredNibbles::decode(&value[32..])?;

        Ok(Self { hashed_address, path })
    }
}

/// Composite key: (hashed_address, hashed_storage_key) for hashed storage values
///
/// Used to efficiently index storage values by both account address and storage key.
/// The encoding ensures lexicographic ordering: first by address, then by storage key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HashedStorageSubKey {
    /// Hashed account address
    pub hashed_address: B256,
    /// Hashed storage key
    pub hashed_storage_key: B256,
}

impl HashedStorageSubKey {
    /// Create a new hashed storage key
    pub const fn new(hashed_address: B256, hashed_storage_key: B256) -> Self {
        Self { hashed_address, hashed_storage_key }
    }
}

impl Encode for HashedStorageSubKey {
    type Encoded = [u8; 64];

    fn encode(self) -> Self::Encoded {
        let mut buf = [0u8; 64];
        // First 32 bytes: address
        buf[..32].copy_from_slice(self.hashed_address.as_slice());
        // Next 32 bytes: storage key
        buf[32..].copy_from_slice(self.hashed_storage_key.as_slice());
        buf
    }
}

impl Decode for HashedStorageSubKey {
    fn decode(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.len() != 64 {
            return Err(DatabaseError::Decode);
        }

        let hashed_address = B256::from_slice(&value[..32]);
        let hashed_storage_key = B256::from_slice(&value[32..64]);

        Ok(Self { hashed_address, hashed_storage_key })
    }
}

// ============================================================================
// Metadata Keys
// ============================================================================

/// Metadata keys for tracking block ranges
///
/// Used to store earliest and latest block numbers in the external storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum MetadataKey {
    /// Earliest block number stored in external storage
    EarliestBlock = 0,
    /// Latest block number stored in external storage
    LatestBlock = 1,
}

impl Encode for MetadataKey {
    type Encoded = [u8; 1];

    fn encode(self) -> Self::Encoded {
        [self as u8]
    }
}

impl Decode for MetadataKey {
    fn decode(value: &[u8]) -> Result<Self, DatabaseError> {
        match value.first() {
            Some(&0) => Ok(Self::EarliestBlock),
            Some(&1) => Ok(Self::LatestBlock),
            _ => Err(DatabaseError::Decode),
        }
    }
}

// ============================================================================
// Composite Values for Changeset Tables
// ============================================================================

/// Changeset value: (StoredNibbles, MaybeDeleted<BranchNodeCompact>) for account branches
///
/// Used in ExternalAccountBranchesChangeset DupSort table.
/// Contains the path + branch data since SubKey is not stored in MDBX DupSort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredNibblesWithBranch(pub StoredNibbles, pub MaybeDeleted<BranchNodeCompact>);

impl Compress for StoredNibblesWithBranch {
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        // Store path using StoredNibblesSubKey encoding (Compact, no length prefix)
        // This ensures proper lexicographic sorting in DupSort
        let subkey = StoredNibblesSubKey(self.0 .0.clone());
        subkey.to_compact(buf);
        // Then store the branch
        self.1.compress_to_buf(buf);
    }
}

impl Decompress for StoredNibblesWithBranch {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.is_empty() {
            return Err(DatabaseError::Decode);
        }

        // Read the nibbles using Compact encoding (StoredNibblesSubKey)
        let (subkey, remaining_bytes) = StoredNibblesSubKey::from_compact(value, value.len());
        let path = StoredNibbles(subkey.0);

        // Remaining bytes are the branch
        let branch = MaybeDeleted::<BranchNodeCompact>::decompress(remaining_bytes)?;

        Ok(Self(path, branch))
    }
}

/// Changeset value: (StorageBranchSubKey, MaybeDeleted<BranchNodeCompact>) for storage branches
///
/// Used in ExternalStorageBranchesChangeset DupSort table.
/// Contains the (address, path) + branch data since SubKey is not stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBranchEntry(pub StorageBranchSubKey, pub MaybeDeleted<BranchNodeCompact>);

impl Compress for StorageBranchEntry {
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        // Encode address (32 bytes)
        buf.put_slice(self.0.hashed_address.as_slice());
        // Encode path using StoredNibblesSubKey (Compact, no length prefix)
        // This ensures proper lexicographic sorting in DupSort
        let subkey = StoredNibblesSubKey(self.0.path.0.clone());
        subkey.to_compact(buf);
        // Then encode the branch (MaybeDeleted)
        self.1.compress_to_buf(buf);
    }
}

impl Decompress for StorageBranchEntry {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.len() < 32 {
            // At least 32 bytes for address
            return Err(DatabaseError::Decode);
        }

        // Decode address (first 32 bytes)
        let hashed_address = B256::from_slice(&value[..32]);

        // Read path using Compact encoding (StoredNibblesSubKey)
        let (subkey, remaining_bytes) =
            StoredNibblesSubKey::from_compact(&value[32..], value.len() - 32);
        let path = StoredNibbles(subkey.0);

        let key = StorageBranchSubKey::new(hashed_address, path);

        // Remaining bytes are the branch
        let branch = MaybeDeleted::<BranchNodeCompact>::decompress(remaining_bytes)?;

        Ok(Self(key, branch))
    }
}

/// Changeset value: (B256, MaybeDeleted<Account>) for hashed accounts
///
/// Used in ExternalHashedAccountsChangeset DupSort table.
/// Contains the address + account data since SubKey is not stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashedAccountEntry(pub B256, pub MaybeDeleted<Account>);

impl Compress for HashedAccountEntry {
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        // Encode address first (32 bytes)
        buf.put_slice(self.0.as_slice());
        // Then encode the account (MaybeDeleted)
        self.1.compress_to_buf(buf);
    }
}

impl Decompress for HashedAccountEntry {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.len() < 32 {
            return Err(DatabaseError::Decode);
        }

        // First 32 bytes are the address
        let address = B256::from_slice(&value[..32]);

        // Remaining bytes are the account
        let account = MaybeDeleted::<Account>::decompress(&value[32..])?;

        Ok(Self(address, account))
    }
}

/// Changeset value: (HashedStorageSubKey, MaybeDeleted<B256>) for hashed storage
///
/// Used in ExternalHashedStoragesChangeset DupSort table.
/// Contains the (address, storage_key) + storage_value since SubKey is not stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashedStorageEntry(pub HashedStorageSubKey, pub MaybeDeleted<B256>);

impl Compress for HashedStorageEntry {
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        // Encode the composite key first (64 bytes)
        let key_bytes = self.0.clone().encode();
        buf.put_slice(&key_bytes);
        // Then encode the storage value (MaybeDeleted<B256>)
        self.1.compress_to_buf(buf);
    }
}

impl Decompress for HashedStorageEntry {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.len() < 64 {
            return Err(DatabaseError::Decode);
        }

        // First 64 bytes are the composite key
        let key = HashedStorageSubKey::decode(&value[..64])?;

        // Remaining bytes are the storage value
        let storage_value = MaybeDeleted::<B256>::decompress(&value[64..])?;

        Ok(Self(key, storage_value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_trie::Nibbles;

    #[test]
    fn test_storage_branch_subkey_encode_decode() {
        let addr = B256::from([1u8; 32]);
        let path = StoredNibbles(Nibbles::from_nibbles_unchecked(&[1, 2, 3, 4]));
        let key = StorageBranchSubKey::new(addr, path.clone());

        let encoded = key.clone().encode();
        let decoded = StorageBranchSubKey::decode(&encoded).unwrap();

        assert_eq!(key, decoded);
        assert_eq!(decoded.hashed_address, addr);
        assert_eq!(decoded.path, path);
    }

    #[test]
    fn test_storage_branch_subkey_ordering() {
        let addr1 = B256::from([1u8; 32]);
        let addr2 = B256::from([2u8; 32]);
        let path1 = StoredNibbles(Nibbles::from_nibbles_unchecked(&[1, 2]));
        let path2 = StoredNibbles(Nibbles::from_nibbles_unchecked(&[1, 3]));

        let key1 = StorageBranchSubKey::new(addr1, path1.clone());
        let key2 = StorageBranchSubKey::new(addr1, path2.clone());
        let key3 = StorageBranchSubKey::new(addr2, path1.clone());

        // Encoded bytes should be sortable: first by address, then by path
        let enc1 = key1.encode();
        let enc2 = key2.encode();
        let enc3 = key3.encode();

        assert!(enc1 < enc2, "Same address, path1 < path2");
        assert!(enc1 < enc3, "addr1 < addr2");
        assert!(enc2 < enc3, "addr1 < addr2 (even with larger path)");
    }

    #[test]
    fn test_hashed_storage_subkey_encode_decode() {
        let addr = B256::from([1u8; 32]);
        let storage_key = B256::from([2u8; 32]);
        let key = HashedStorageSubKey::new(addr, storage_key);

        let encoded = key.clone().encode();
        let decoded = HashedStorageSubKey::decode(&encoded).unwrap();

        assert_eq!(key, decoded);
        assert_eq!(decoded.hashed_address, addr);
        assert_eq!(decoded.hashed_storage_key, storage_key);
    }

    #[test]
    fn test_hashed_storage_subkey_ordering() {
        let addr1 = B256::from([1u8; 32]);
        let addr2 = B256::from([2u8; 32]);
        let storage1 = B256::from([10u8; 32]);
        let storage2 = B256::from([20u8; 32]);

        let key1 = HashedStorageSubKey::new(addr1, storage1);
        let key2 = HashedStorageSubKey::new(addr1, storage2);
        let key3 = HashedStorageSubKey::new(addr2, storage1);

        // Encoded bytes should be sortable: first by address, then by storage key
        let enc1 = key1.encode();
        let enc2 = key2.encode();
        let enc3 = key3.encode();

        assert!(enc1 < enc2, "Same address, storage1 < storage2");
        assert!(enc1 < enc3, "addr1 < addr2");
        assert!(enc2 < enc3, "addr1 < addr2 (even with larger storage key)");
    }

    #[test]
    fn test_hashed_storage_subkey_size() {
        let addr = B256::from([1u8; 32]);
        let storage_key = B256::from([2u8; 32]);
        let key = HashedStorageSubKey::new(addr, storage_key);

        let encoded = key.encode();
        assert_eq!(encoded.len(), 64, "Encoded size should be exactly 64 bytes");
    }

    #[test]
    fn test_metadata_key_encode_decode() {
        let key = MetadataKey::EarliestBlock;
        let encoded = key.encode();
        let decoded = MetadataKey::decode(&encoded).unwrap();
        assert_eq!(key, decoded);

        let key = MetadataKey::LatestBlock;
        let encoded = key.encode();
        let decoded = MetadataKey::decode(&encoded).unwrap();
        assert_eq!(key, decoded);
    }
}
