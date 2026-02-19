//! State database traits for consensus-facing operations.

use std::future::Future;

use alloy_primitives::{Address, B256, Bytes, U256};
use hub_qmdb::ChangeSet;

use crate::StateDbError;

/// Read-only access to blockchain state.
///
/// Provides account, storage, and code lookups without mutation.
pub trait StateDbRead: Clone + Send + Sync + 'static {
    /// Get account nonce.
    fn nonce(&self, address: &Address) -> impl Future<Output = Result<u64, StateDbError>> + Send;

    /// Get account balance.
    fn balance(&self, address: &Address)
    -> impl Future<Output = Result<U256, StateDbError>> + Send;

    /// Get account code hash.
    fn code_hash(
        &self,
        address: &Address,
    ) -> impl Future<Output = Result<B256, StateDbError>> + Send;

    /// Get account code by hash.
    fn code(&self, code_hash: &B256) -> impl Future<Output = Result<Bytes, StateDbError>> + Send;

    /// Get storage slot value.
    fn storage(
        &self,
        address: &Address,
        slot: &U256,
    ) -> impl Future<Output = Result<U256, StateDbError>> + Send;

    /// Check if an account exists.
    fn exists(&self, address: &Address) -> impl Future<Output = Result<bool, StateDbError>> + Send {
        let address = *address;
        async move {
            match self.nonce(&address).await {
                Ok(nonce) => Ok(nonce > 0 || !self.balance(&address).await?.is_zero()),
                Err(StateDbError::AccountNotFound(_)) => Ok(false),
                Err(e) => Err(e),
            }
        }
    }
}

/// Write access to blockchain state.
///
/// Provides atomic state mutations through change sets.
pub trait StateDbWrite: Clone + Send + Sync + 'static {
    /// Commit a set of changes atomically.
    ///
    /// Returns the new state root after applying changes.
    fn commit(&self, changes: ChangeSet)
    -> impl Future<Output = Result<B256, StateDbError>> + Send;

    /// Compute the state root that would result from applying changes.
    ///
    /// Does not persist changes.
    fn compute_root(
        &self,
        changes: &ChangeSet,
    ) -> impl Future<Output = Result<B256, StateDbError>> + Send;

    /// Merge two change sets.
    ///
    /// The `newer` changes override `older` where they conflict.
    fn merge_changes(&self, older: ChangeSet, newer: ChangeSet) -> ChangeSet;
}

/// Full state database interface for consensus operations.
///
/// Combines read and write access with additional metadata operations.
pub trait StateDb: StateDbRead + StateDbWrite {
    /// Get the current state root.
    fn state_root(&self) -> impl Future<Output = Result<B256, StateDbError>> + Send;
}
