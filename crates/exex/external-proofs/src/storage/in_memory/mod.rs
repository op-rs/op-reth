//! In-memory implementation of ExternalStorage for testing purposes.
//!
//! This module provides a complete in-memory implementation of the 
//! [`ExternalStorage`](crate::storage::ExternalStorage) trait that can be used for 
//! testing and development. The implementation uses tokio async `RwLock`
//! for thread-safe concurrent access and stores all data in memory using `BTreeMap` collections.

mod in_memory;
pub use in_memory::InMemoryExternalStorage;

#[cfg(test)]
mod in_memory_tests;
