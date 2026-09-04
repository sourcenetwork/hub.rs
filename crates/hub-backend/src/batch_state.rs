//! EVM state view over pending glue batches.
//!
//! [`BatchState`] lets the block executor read through a set of unmerkleized
//! batches (pending writes on top of committed state) and turns an executed
//! [`ChangeSet`] into batch writes ready to merkleize.

use std::sync::Arc;

use alloy_primitives::{Address, B256, Bytes, U256};
use commonware_glue::stateful::db::Unmerkleized as _;
use hub_qmdb::{AccountEncoding, ChangeSet, StorageKey as StorageSlotKey};
use hub_traits::{StateDb, StateDbError, StateDbRead, StateDbWrite};
use tokio::sync::Mutex;

use crate::{
    BackendError,
    state_set::{HubMerkleized, HubUnmerkleized},
    types::{AccountKey, AccountValue, CodeKey, StorageKey, StorageValue},
};

type AccountRecord = (u64, U256, B256, u64);

/// Pending EVM state: committed databases plus the batches forked for one block.
#[derive(Clone)]
pub struct BatchState {
    batches: Arc<Mutex<Option<HubUnmerkleized>>>,
}

impl std::fmt::Debug for BatchState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchState").finish_non_exhaustive()
    }
}

const fn account_key(address: Address) -> AccountKey {
    AccountKey::new(address.into_array())
}

const fn code_key(hash: B256) -> CodeKey {
    CodeKey::new(hash.0)
}

fn storage_key(address: Address, generation: u64, slot: U256) -> StorageKey {
    StorageKey::new(StorageSlotKey::new(address, generation, slot).to_bytes())
}

fn storage_err(e: impl std::fmt::Display) -> StateDbError {
    StateDbError::Storage(e.to_string())
}

impl BatchState {
    /// Wrap batches forked for one block.
    pub fn new(batches: HubUnmerkleized) -> Self {
        Self {
            batches: Arc::new(Mutex::new(Some(batches))),
        }
    }

    /// Take the batches back out once execution is done.
    pub async fn into_batches(self) -> Result<HubUnmerkleized, BackendError> {
        self.batches
            .lock()
            .await
            .take()
            .ok_or(BackendError::NotInitialized)
    }

    async fn account(&self, address: &Address) -> Result<Option<AccountRecord>, StateDbError> {
        let guard = self.batches.lock().await;
        let batches = guard.as_ref().ok_or(StateDbError::LockPoisoned)?;
        let record = batches
            .0
            .get(&account_key(*address))
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

    /// Write an executed change set into the batches, returning them for merkleization.
    pub async fn apply_changes(
        mut batches: HubUnmerkleized,
        changes: &ChangeSet,
    ) -> Result<HubUnmerkleized, BackendError> {
        for (address, update) in &changes.accounts {
            let key = account_key(*address);
            let current_generation = match batches.0.get(&key).await {
                Ok(Some(value)) => AccountEncoding::decode(&value.0)
                    .map(|(_, _, _, generation)| generation)
                    .unwrap_or(0),
                Ok(None) => 0,
                Err(e) => return Err(BackendError::Storage(e.to_string())),
            };
            let generation = if update.created || update.selfdestructed {
                current_generation.saturating_add(1)
            } else {
                current_generation
            };

            if update.selfdestructed {
                batches.0 = batches.0.write(key, None);
            } else {
                let encoded = AccountEncoding::encode(
                    update.nonce,
                    update.balance,
                    update.code_hash,
                    generation,
                );
                batches.0 = batches.0.write(key, Some(AccountValue(encoded)));
                if let Some(code) = &update.code {
                    batches.2 = batches
                        .2
                        .write(code_key(update.code_hash), Some(code.clone()));
                }
            }

            for (slot, value) in &update.storage {
                let key = storage_key(*address, generation, *slot);
                let value = (!value.is_zero()).then_some(StorageValue(*value));
                batches.1 = batches.1.write(key, value);
            }
        }
        Ok(batches)
    }

    /// Merkleize the three batches.
    pub async fn merkleize(batches: HubUnmerkleized) -> Result<HubMerkleized, BackendError> {
        let (accounts, storage, code) = batches;
        let accounts = accounts
            .merkleize()
            .await
            .map_err(|e| BackendError::Storage(format!("{e:?}")))?;
        let storage = storage
            .merkleize()
            .await
            .map_err(|e| BackendError::Storage(format!("{e:?}")))?;
        let code = code
            .merkleize()
            .await
            .map_err(|e| BackendError::Storage(format!("{e:?}")))?;
        Ok((accounts, storage, code))
    }
}

impl StateDbRead for BatchState {
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
        let guard = self.batches.lock().await;
        let batches = guard.as_ref().ok_or(StateDbError::LockPoisoned)?;
        batches
            .2
            .get(&code_key(*code_hash))
            .await
            .map_err(storage_err)?
            .map(Bytes::from)
            .ok_or(StateDbError::CodeNotFound(*code_hash))
    }

    async fn storage(&self, address: &Address, slot: &U256) -> Result<U256, StateDbError> {
        let Some((_, _, _, generation)) = self.account(address).await? else {
            return Ok(U256::ZERO);
        };
        let guard = self.batches.lock().await;
        let batches = guard.as_ref().ok_or(StateDbError::LockPoisoned)?;
        let value = batches
            .1
            .get(&storage_key(*address, generation, *slot))
            .await
            .map_err(storage_err)?;
        Ok(value.map_or(U256::ZERO, |v| v.0))
    }
}

impl StateDbWrite for BatchState {
    async fn commit(&self, _changes: ChangeSet) -> Result<B256, StateDbError> {
        Err(StateDbError::RootComputation(
            "batch state is committed by the stateful actor".into(),
        ))
    }

    async fn compute_root(&self, _changes: &ChangeSet) -> Result<B256, StateDbError> {
        Err(StateDbError::RootComputation(
            "batch state roots come from merkleized batches".into(),
        ))
    }

    fn merge_changes(&self, mut older: ChangeSet, newer: ChangeSet) -> ChangeSet {
        older.merge(newer);
        older
    }
}

impl StateDb for BatchState {
    async fn state_root(&self) -> Result<B256, StateDbError> {
        Err(StateDbError::RootComputation(
            "batch state roots come from merkleized batches".into(),
        ))
    }
}
