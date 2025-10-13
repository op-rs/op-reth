//! Storage abstractions for external proofs.
mod traits;
pub use traits::{
    BlockStateDiff, ExternalHashedCursor, ExternalStorage, ExternalStorageError,
    ExternalStorageResult, ExternalTrieCursor,
};

pub mod in_memory;
pub mod mdbx;
