use reth_db::{
    table::{Compress, Decode, Decompress, Encode},
    DatabaseError,
};
use serde::{Deserialize, Serialize};

/// Subkey for identifying tables in `BlockChangeSet`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TableName {
    /// [`AccountTrieHistory`](super::AccountTrieHistory) table.
    AccountTrieHistory,
    /// [`StorageTrieHistory`](super::StorageTrieHistory) table.
    StorageTrieHistory,
    /// [`HashedAccountHistory`](super::HashedAccountHistory) table.
    HashedAccountHistory,
    /// [`HashedStorageHistory`](super::HashedStorageHistory) table.
    HashedStorageHistory,
}

impl Encode for TableName {
    type Encoded = Vec<u8>;

    fn encode(self) -> Self::Encoded {
        match self {
            Self::AccountTrieHistory => vec![0u8],
            Self::StorageTrieHistory => vec![1u8],
            Self::HashedAccountHistory => vec![2u8],
            Self::HashedStorageHistory => vec![3u8],
        }
    }
}

impl Decode for TableName {
    fn decode(value: &[u8]) -> Result<Self, DatabaseError> {
        match value.first() {
            Some(&0) => Ok(Self::AccountTrieHistory),
            Some(&1) => Ok(Self::StorageTrieHistory),
            Some(&2) => Ok(Self::HashedAccountHistory),
            Some(&3) => Ok(Self::HashedStorageHistory),
            _ => Err(DatabaseError::Decode),
        }
    }
}

/// All keys changed at a specific block for a given table.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TableChangeSet {
    /// The name of the table where the key is located.
    pub name: TableName,
    /// The key of the entry in the table.
    /// Mdbx stores encoded keys so we can store them as raw bytes
    /// And avoid dealing with different key types here.
    pub table_key: Vec<u8>,
}

impl Encode for TableChangeSet {
    type Encoded = Vec<u8>;

    fn encode(self) -> Self::Encoded {
        let mut buf = Vec::new();
        // Encode table name as a single byte (encoded as Vec<u8>)
        let table_bytes = self.name.encode();
        buf.extend_from_slice(&table_bytes);
        // Append the key bytes
        buf.extend_from_slice(&self.table_key);
        buf
    }
}

impl Decode for TableChangeSet {
    fn decode(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.is_empty() {
            return Err(DatabaseError::Decode);
        }

        let name = TableName::decode(&value[..1])?;
        let table_key = value[1..].to_vec();

        Ok(Self { name, table_key })
    }
}

impl Compress for TableChangeSet {
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let encoded = self.clone().encode();
        buf.put_slice(&encoded);
    }
}

impl Decompress for TableChangeSet {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        Self::decode(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_change_set_roundtrip() {
        let test_cases: Vec<_> = vec![
            TableChangeSet { name: TableName::AccountTrieHistory, table_key: vec![1, 2, 3] },
            TableChangeSet { name: TableName::StorageTrieHistory, table_key: vec![4, 5, 6] },
            TableChangeSet { name: TableName::AccountTrieHistory, table_key: vec![] },
        ];

        for original in test_cases {
            let encoded = original.clone().encode();
            let decoded = TableChangeSet::decode(&encoded).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn test_table_change_set_decode_error() {
        // Test decoding an empty slice
        assert!(TableChangeSet::decode(&[]).is_err());

        // Test decoding a slice with an invalid table identifier
        assert!(TableChangeSet::decode(&[4, 1, 2, 3]).is_err());
    }
}
