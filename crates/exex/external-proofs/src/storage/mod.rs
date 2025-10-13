//! Storage abstractions for external proofs.
mod traits;
pub use traits::{ExternalStorage, ExternalStorageError, ExternalStorageResult, BlockStateDiff, ExternalTrieCursor, ExternalHashedCursor};

pub mod in_memory;
pub mod mdbx;