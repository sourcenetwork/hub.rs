//! Committed EVM state, for RPC queries and mempool validation.
//!
//! Writes go through the stateful actor, so the write half of [`StateDb`]
//! only exists to satisfy the validator's bound and always errors.

use alloy_primitives::{Address, B256, Bytes, U256};
use hub_backend::{AccountKey, CodeKey, HubStateSet, StorageKey};
use hub_qmdb::ChangeSet;
use hub_qmdb::{AccountEncoding, StorageKey as StorageSlotKey};
use hub_traits::{StateDb, StateDbError, StateDbRead, StateDbWrite};

/// Committed EVM state read through the shared database set.
#[derive(Clone)]
pub struct CommittedState {
    set: HubStateSet,
}

impl std::fmt::Debug for CommittedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommittedState").finish_non_exhaustive()
    }
}

type AccountRecord = (u64, U256, B256, u64);

fn storage_err(e: impl std::fmt::Display) -> StateDbError {
    StateDbError::Storage(e.to_string())
}

impl CommittedState {
    /// Read committed state through `set`.
    pub const fn new(set: HubStateSet) -> Self {
        Self { set }
    }

    async fn account(&self, address: &Address) -> Result<Option<AccountRecord>, StateDbError> {
        let db = self.set.0.read().await;
        let record = db
            .get(&AccountKey::new(address.into_array()))
            .await
            .map_err(storage_err)?;
        record.map_or(Ok(None), |value| {
            AccountEncoding::decode(&value.0)
                .map(Some)
                .ok_or_else(|| StateDbError::Storage("undecodable account record".into()))
        })
    }

    async fn require_account(&self, address: &Address) -> Result<AccountRecord, StateDbError> {
        self.account(address)
            .await?
            .ok_or(StateDbError::AccountNotFound(*address))
    }
}

impl StateDbRead for CommittedState {
    async fn nonce(&self, address: &Address) -> Result<u64, StateDbError> {
        Ok(self.require_account(address).await?.0)
    }

    async fn balance(&self, address: &Address) -> Result<U256, StateDbError> {
        Ok(self.require_account(address).await?.1)
    }

    async fn code_hash(&self, address: &Address) -> Result<B256, StateDbError> {
        Ok(self.require_account(address).await?.2)
    }

    async fn code(&self, code_hash: &B256) -> Result<Bytes, StateDbError> {
        let db = self.set.2.read().await;
        db.get(&CodeKey::new(code_hash.0))
            .await
            .map_err(storage_err)?
            .map(Bytes::from)
            .ok_or(StateDbError::CodeNotFound(*code_hash))
    }

    async fn storage(&self, address: &Address, slot: &U256) -> Result<U256, StateDbError> {
        let Some((_, _, _, generation)) = self.account(address).await? else {
            return Ok(U256::ZERO);
        };
        let db = self.set.1.read().await;
        let key = StorageKey::new(StorageSlotKey::new(*address, generation, *slot).to_bytes());
        let value = db.get(&key).await.map_err(storage_err)?;
        Ok(value.map_or(U256::ZERO, |v| v.0))
    }
}

fn read_only() -> StateDbError {
    StateDbError::RootComputation("committed state is written by the stateful actor".into())
}

impl StateDbWrite for CommittedState {
    async fn commit(&self, _changes: ChangeSet) -> Result<B256, StateDbError> {
        Err(read_only())
    }

    async fn compute_root(&self, _changes: &ChangeSet) -> Result<B256, StateDbError> {
        Err(read_only())
    }

    fn merge_changes(&self, mut older: ChangeSet, newer: ChangeSet) -> ChangeSet {
        older.merge(newer);
        older
    }
}

impl StateDb for CommittedState {
    async fn state_root(&self) -> Result<B256, StateDbError> {
        Err(read_only())
    }
}
