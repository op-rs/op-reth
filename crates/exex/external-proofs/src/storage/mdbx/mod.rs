//! MDBX implementation of ExternalStorage.
//!
//! This module provides a complete MDBX implementation of the
//! [`ExternalStorage`](crate::storage::ExternalStorage) trait. It uses the `reth_db` crate for
//! database interactions and defines the necessary tables and models for storing trie branches,
//! accounts, and storage leaves.

mod models;
pub use models::*;
