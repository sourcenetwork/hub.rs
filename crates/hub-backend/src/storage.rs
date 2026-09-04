//! Storage store bindings for commonware-storage.

use alloy_primitives::U256;
use commonware_cryptography::sha256::Digest as QmdbDigest;
use commonware_parallel::Sequential;
use commonware_storage::qmdb::any::VariableConfig;
use commonware_storage::translator::EightCap;
use hub_qmdb::{QmdbBatchable, QmdbGettable, StorageKey};

use crate::{
    BackendError,
    types::{
        Context, StorageDb, StorageDbDirty, StorageKey as StorageKeyBytes, StorageValue, StoreSlot,
    },
};

/// Storage partition backed by commonware-storage.
///
/// Stores contract storage slots as key-value pairs. Keys are composite tuples of
/// (address, generation, slot) encoded via [`StorageKey`], and values are 32-byte
/// [`U256`] integers.
///
/// Implements [`QmdbGettable`] for reads and [`QmdbBatchable`] for batch writes.
/// All writes are atomic and update the authenticated Merkle root.
pub struct StorageStore {
    inner: StoreSlot<StorageDb>,
}

pub(crate) struct StorageStoreDirty {
    inner: StoreSlot<StorageDbDirty>,
}

impl StorageStoreDirty {
    pub(crate) const fn new(inner: StorageDbDirty) -> Self {
        Self {
            inner: StoreSlot::new(inner),
        }
    }
}

impl StorageStore {
    /// Initialize the storage store.
    pub async fn init(
        context: Context,
        config: VariableConfig<EightCap, ((), ()), Sequential>,
    ) -> Result<Self, BackendError> {
        let inner = StorageDb::init(context, config)
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        Ok(Self {
            inner: StoreSlot::new(inner),
        })
    }

    /// Return the current authenticated root for the storage partition.
    pub fn root(&self) -> Result<QmdbDigest, BackendError> {
        Ok(self.inner.get()?.root())
    }

    pub(crate) fn into_dirty(self) -> Result<StorageStoreDirty, BackendError> {
        let inner = self.inner.into_inner()?;
        Ok(StorageStoreDirty::new(inner))
    }
}

impl StorageStoreDirty {
    pub(crate) fn root(&self) -> Result<QmdbDigest, BackendError> {
        Ok(self.inner.get()?.root())
    }
}

impl std::fmt::Debug for StorageStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageStore").finish_non_exhaustive()
    }
}

/// Error type for storage store operations.
pub type StorageStoreError = BackendError;

fn storage_key(key: StorageKey) -> StorageKeyBytes {
    StorageKeyBytes::new(key.to_bytes())
}

impl QmdbGettable for StorageStore {
    type Key = StorageKey;
    type Value = U256;
    type Error = StorageStoreError;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        let record = self
            .inner
            .get()?
            .get(&storage_key(*key))
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        Ok(record.map(|value| value.0))
    }
}

impl QmdbBatchable for StorageStore {
    async fn write_batch<I>(&mut self, ops: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = (Self::Key, Option<Self::Value>)> + Send,
        I::IntoIter: Send,
    {
        let inner = self.inner.take()?;
        let mapped = ops
            .into_iter()
            .map(|(key, value)| (storage_key(key), value.map(StorageValue)));
        let mut batch = inner.new_batch();
        for (key, value) in mapped {
            batch = batch.write(key, value);
        }
        let batch = batch
            .merkleize(&inner, None)
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        let (inner, _) = inner
            .apply_batch(batch)
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        let inner = inner
            .commit()
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        self.inner.restore(inner);
        Ok(())
    }
}

impl QmdbGettable for StorageStoreDirty {
    type Key = StorageKey;
    type Value = U256;
    type Error = StorageStoreError;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        let record = self
            .inner
            .get()?
            .get(&storage_key(*key))
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        Ok(record.map(|value| value.0))
    }
}

impl QmdbBatchable for StorageStoreDirty {
    async fn write_batch<I>(&mut self, ops: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = (Self::Key, Option<Self::Value>)> + Send,
        I::IntoIter: Send,
    {
        let inner = self.inner.take()?;
        let mapped = ops
            .into_iter()
            .map(|(key, value)| (storage_key(key), value.map(StorageValue)));
        let mut batch = inner.new_batch();
        for (key, value) in mapped {
            batch = batch.write(key, value);
        }
        let batch = batch
            .merkleize(&inner, None)
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        let (inner, _) = inner
            .apply_batch(batch)
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        self.inner.restore(inner);
        Ok(())
    }
}
