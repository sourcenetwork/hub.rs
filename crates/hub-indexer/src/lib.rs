//! Block and transaction indexer for hub RPC queries.

#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/hub.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod error;
pub use error::IndexerError;

mod filter;
pub use filter::LogFilter;

mod light_block_store;
pub use light_block_store::{
    LightBlockIndex, MAX_CACHED_FINALIZATIONS, StoredEpochMaterial, StoredFinalization,
};

mod store;
pub use store::BlockIndex;

mod types;
pub use types::{IndexStats, IndexedBlock, IndexedLog, IndexedReceipt, IndexedTransaction};
