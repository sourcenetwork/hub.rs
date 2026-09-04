//! Concrete storage backend for hub QMDB.

#![doc = include_str!("../README.md")]
#![doc(issue_tracker_base_url = "https://github.com/mizufinance/hub-commonware/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod accounts;
pub use accounts::{AccountStore, AccountStoreError};

mod types;
pub use types::{AccountKey, AccountValue, CodeKey, StorageKey, StorageValue};

mod backend;
mod batch_state;
pub use backend::{CommonwareBackend, CommonwareRootProvider};
pub use batch_state::BatchState;

mod code;
pub use code::{CodeDbConfig, CodeStore, CodeStoreError};

mod config;
pub use config::QmdbBackendConfig;

mod error;
pub use error::BackendError;

mod partition;
pub use partition::PartitionState;

mod state_set;
pub use state_set::{
    AccountsDb, CodeDb, Ctx, HubConfig, HubDatabases, HubMerkleized, HubReaders, HubStateSet,
    HubSyncTargets, HubUnmerkleized, MerkleizedTriple, StorageDb, combined_root, state_set_config,
};

mod storage;
pub use storage::{StorageStore, StorageStoreError};
