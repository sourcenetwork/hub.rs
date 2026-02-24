use std::sync::Arc;

use alloy_primitives::{Address, U256};
use commonware_runtime::tokio::Context;
use hub_backend::{
    AccountStore, CodeStore, CommonwareBackend, CommonwareRootProvider, QmdbBackendConfig,
    StorageStore,
};
use hub_domain::StateRoot;
use hub_handlers::{HandleError, QmdbHandle, QmdbRefDb as HandlerQmdbRefDb};
use hub_traits::{StateDb, StateDbWrite};
use thiserror::Error;
use tokio::sync::RwLock;

/// QMDB configuration for the backend.
pub type QmdbConfig = QmdbBackendConfig;
/// QMDB change set type.
pub type QmdbChangeSet = hub_qmdb::ChangeSet;
/// QMDB handle type used as a state database.
pub type QmdbState = QmdbHandle<AccountStore, StorageStore, CodeStore>;
/// Tokio-backed REVM database wrapper for QMDB handles.
pub type QmdbRefDb = HandlerQmdbRefDb<AccountStore, StorageStore, CodeStore>;

type Handle = QmdbState;

/// QMDB ledger service backed by hub storage crates.
#[derive(Clone, Debug)]
pub struct QmdbLedger {
    handle: Handle,
}

/// Errors for QMDB ledger operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Backend error while opening QMDB storage.
    #[error("backend error: {0}")]
    Backend(#[from] hub_backend::BackendError),
    /// Handler error while applying state changes.
    #[error("handler error: {0}")]
    Handler(#[from] HandleError),
    /// State database error while computing or committing roots.
    #[error("state db error: {0}")]
    StateDb(#[from] hub_traits::StateDbError),
    /// Missing Tokio runtime needed for sync REVM database access.
    #[error("missing tokio runtime for async db bridge")]
    MissingRuntime,
}

impl QmdbLedger {
    /// Initializes the QMDB partitions and populates the genesis allocation.
    pub async fn init(
        context: Context,
        config: QmdbConfig,
        genesis_alloc: Vec<(Address, U256)>,
        genesis_storage: Vec<(Address, Vec<(U256, U256)>)>,
        genesis_code: Vec<(Address, Vec<u8>)>,
    ) -> Result<Self, Error> {
        let backend = CommonwareBackend::open(context.clone(), config.clone()).await?;
        let root_provider = CommonwareRootProvider::new(context, config);
        let (accounts, storage, code) = backend.into_stores();
        let handle = Handle::new(accounts, storage, code)
            .with_root_provider(Arc::new(RwLock::new(root_provider)));
        handle
            .init_genesis(genesis_alloc, genesis_storage, genesis_code)
            .await?;
        Ok(Self { handle })
    }

    /// Exposes a synchronous REVM database view backed by QMDB.
    pub fn database(&self) -> Result<QmdbRefDb, Error> {
        QmdbRefDb::new(self.handle.clone()).ok_or(Error::MissingRuntime)
    }

    /// Exposes the async state handle used by the block executor.
    pub fn state(&self) -> QmdbState {
        self.handle.clone()
    }

    /// Computes the root for a change set without committing.
    pub async fn compute_root(&self, changes: QmdbChangeSet) -> Result<StateRoot, Error> {
        let root = StateDbWrite::compute_root(&self.handle, &changes).await?;
        Ok(StateRoot(root))
    }

    /// Commits the provided changes to QMDB and returns the resulting root.
    pub async fn commit_changes(&self, changes: QmdbChangeSet) -> Result<StateRoot, Error> {
        let root = StateDbWrite::commit(&self.handle, changes).await?;
        Ok(StateRoot(root))
    }

    /// Returns the current authenticated root stored in QMDB.
    pub async fn root(&self) -> Result<StateRoot, Error> {
        let root = StateDb::state_root(&self.handle).await?;
        Ok(StateRoot(root))
    }
}
