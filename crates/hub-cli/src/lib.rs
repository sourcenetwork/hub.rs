//! Minimal CLI utilities for the Hub binary.

#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/hub.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod backtrace;
pub use backtrace::Backtracing;
mod private_file;
pub use private_file::write_private;

#[cfg(unix)]
mod sigsegv;
#[cfg(unix)]
pub use sigsegv::SigsegvHandler;
