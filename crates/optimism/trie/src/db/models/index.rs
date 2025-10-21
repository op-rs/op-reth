use reth_db::{
    table::{Compress, Decode, Decompress, Encode},
    DatabaseError,
};
use serde::{Deserialize, Serialize};

/// Key for pruning entries from historical trie tables
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PruningTableName {
    /// AccountTrieHistory table.
    AccountTrieHistory,
    /// StorageTrieHistory table.
    StorageTrieHistory,
    /// HashedAccountHistory table.
    HashedAccountHistory,
    /// HashedStorageHistory table.
    HashedStorageHistory,
}

/// Composite key for pruning: (table name, key)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PruningKey {
    /// The name of the table where the key is located.
    pub table: PruningTableName,
    /// The key of the entry to be pruned.
    pub key: Vec<u8>,
}

impl Encode for PruningKey {
    type Encoded = Vec<u8>;

    fn encode(self) -> Self::Encoded {
        let mut buf = Vec::new();
        // Encode table name as a single byte
        let table_byte = match self.table {
            PruningTableName::AccountTrieHistory => 0u8,
            PruningTableName::StorageTrieHistory => 1u8,
            PruningTableName::HashedAccountHistory => 2u8,
            PruningTableName::HashedStorageHistory => 3u8,
        };
        buf.push(table_byte);
        // Append the key bytes
        buf.extend_from_slice(&self.key);
        buf
    }
}

impl Decode for PruningKey {
    fn decode(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.is_empty() {
            return Err(DatabaseError::Decode);
        }

        let table = match value[0] {
            0 => PruningTableName::AccountTrieHistory,
            1 => PruningTableName::StorageTrieHistory,
            2 => PruningTableName::HashedAccountHistory,
            3 => PruningTableName::HashedStorageHistory,
            _ => return Err(DatabaseError::Decode),
        };

        let key = value[1..].to_vec();

        Ok(Self { table, key })
    }
}

impl Compress for PruningKey {
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let encoded = self.clone().encode();
        buf.put_slice(&encoded);
    }
}

impl Decompress for PruningKey {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        Self::decode(value)
    }
}
