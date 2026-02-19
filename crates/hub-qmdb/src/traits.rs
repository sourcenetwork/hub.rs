//! Traits for QMDB store operations.

use std::future::Future;

/// Trait for reading values from a QMDB store.
pub trait QmdbGettable: Send + Sync {
    /// The key type for lookups.
    type Key: Send + Sync;
    /// The value type returned from lookups.
    type Value: Send + Sync;
    /// Error type for operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Get a value by key, returning None if not found.
    fn get(
        &self,
        key: &Self::Key,
    ) -> impl Future<Output = Result<Option<Self::Value>, Self::Error>> + Send;
}

/// Trait for batching writes to a QMDB store.
pub trait QmdbBatchable: QmdbGettable {
    /// Write a batch of key-value pairs. None values indicate deletion.
    fn write_batch<I>(&mut self, ops: I) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        I: IntoIterator<Item = (Self::Key, Option<Self::Value>)> + Send,
        I::IntoIter: Send;
}
