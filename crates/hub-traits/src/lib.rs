//! Core trait abstractions for hub storage and consensus.

#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/hub.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod error;
pub use error::StateDbError;

mod state;
pub use state::{StateDb, StateDbRead, StateDbWrite};
