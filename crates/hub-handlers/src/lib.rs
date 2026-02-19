//! Thread-safe database handles for hub.

#![doc = include_str!("../README.md")]
#![doc(issue_tracker_base_url = "https://github.com/mizufinance/hub-commonware/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod adapter;
pub use adapter::QmdbRefDb;

mod error;
pub use error::HandleError;

mod qmdb;
pub use qmdb::{QmdbHandle, RootProvider};

mod state;
