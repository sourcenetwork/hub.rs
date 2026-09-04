//! Account store bindings for commonware-storage.

use alloy_primitives::Address;
use commonware_cryptography::sha256::Digest as QmdbDigest;
use commonware_parallel::Sequential;
use commonware_storage::qmdb::any::VariableConfig;
use commonware_storage::translator::EightCap;
use hub_qmdb::{AccountEncoding, QmdbBatchable, QmdbGettable};

use crate::{
    BackendError,
    types::{AccountDb, AccountDbDirty, AccountKey, AccountValue, Context, StoreSlot},
};

/// Account partition backed by commonware-storage.
///
/// Stores account state including nonce, balance, code hash, and generation number.
/// Each account is keyed by its 20-byte address and encoded as a fixed 80-byte value
/// using [`AccountEncoding`](hub_qmdb::AccountEncoding).
///
/// Implements [`QmdbGettable`] for reads and [`QmdbBatchable`] for batch writes.
/// All writes are atomic and update the authenticated Merkle root.
pub struct AccountStore {
    inner: StoreSlot<AccountDb>,
}

pub(crate) struct AccountStoreDirty {
    inner: StoreSlot<AccountDbDirty>,
}

impl AccountStoreDirty {
    pub(crate) const fn new(inner: AccountDbDirty) -> Self {
        Self {
            inner: StoreSlot::new(inner),
        }
    }
}

impl AccountStore {
    /// Initialize the account store.
    pub async fn init(
        context: Context,
        config: VariableConfig<EightCap, ((), ()), Sequential>,
    ) -> Result<Self, BackendError> {
        let inner = AccountDb::init(context, config)
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        Ok(Self {
            inner: StoreSlot::new(inner),
        })
    }

    /// Return the current authenticated root for the account partition.
    pub fn root(&self) -> Result<QmdbDigest, BackendError> {
        Ok(self.inner.get()?.root())
    }

    pub(crate) fn into_dirty(self) -> Result<AccountStoreDirty, BackendError> {
        let inner = self.inner.into_inner()?;
        Ok(AccountStoreDirty::new(inner))
    }
}

impl AccountStoreDirty {
    pub(crate) fn root(&self) -> Result<QmdbDigest, BackendError> {
        Ok(self.inner.get()?.root())
    }
}

impl std::fmt::Debug for AccountStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountStore").finish_non_exhaustive()
    }
}

/// Error type for account store operations.
pub type AccountStoreError = BackendError;

const fn account_key(address: Address) -> AccountKey {
    AccountKey::new(address.into_array())
}

impl QmdbGettable for AccountStore {
    type Key = Address;
    type Value = [u8; AccountEncoding::SIZE];
    type Error = AccountStoreError;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        let record = self
            .inner
            .get()?
            .get(&account_key(*key))
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        Ok(record.map(|value| value.0))
    }
}

impl QmdbBatchable for AccountStore {
    async fn write_batch<I>(&mut self, ops: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = (Self::Key, Option<Self::Value>)> + Send,
        I::IntoIter: Send,
    {
        let inner = self.inner.take()?;
        let mapped = ops
            .into_iter()
            .map(|(address, value)| (account_key(address), value.map(AccountValue)));
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

impl QmdbGettable for AccountStoreDirty {
    type Key = Address;
    type Value = [u8; AccountEncoding::SIZE];
    type Error = AccountStoreError;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        let record = self
            .inner
            .get()?
            .get(&account_key(*key))
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        Ok(record.map(|value| value.0))
    }
}

impl QmdbBatchable for AccountStoreDirty {
    async fn write_batch<I>(&mut self, ops: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = (Self::Key, Option<Self::Value>)> + Send,
        I::IntoIter: Send,
    {
        let inner = self.inner.take()?;
        let mapped = ops
            .into_iter()
            .map(|(address, value)| (account_key(address), value.map(AccountValue)));
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
