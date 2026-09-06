//! Concrete storage backend for hub QMDB.

#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/hub.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod types;
pub use types::{AccountKey, AccountValue, CodeKey, StorageKey, StorageValue};

mod batch_state;
pub use batch_state::BatchState;

mod error;
pub use error::BackendError;

mod state_set;
pub use state_set::{
    AccountsDb, CodeDb, Ctx, HubConfig, HubDatabases, HubMerkleized, HubReaders, HubStateSet,
    HubSyncTargets, HubUnmerkleized, MerkleizedTriple, StorageDb, combined_root, state_set_config,
};

/// Ordered native module storage and logical record changes.
pub mod native;
