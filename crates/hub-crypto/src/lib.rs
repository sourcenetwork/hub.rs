//! Cryptographic utilities for hub.

#![doc = include_str!("../README.md")]
#![doc(issue_tracker_base_url = "https://github.com/mizufinance/hub-commonware/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

#[cfg(feature = "test-utils")]
mod test_utils;

#[cfg(feature = "test-utils")]
pub use test_utils::{ThresholdScheme, threshold_schemes};
