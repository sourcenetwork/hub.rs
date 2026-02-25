//! End-to-end test harness for hub.
//!
//! Re-exports `hub-harness` (from backbone) and provides workspace-relative
//! binary resolution so tests can find the locally-built `hubd`.

pub use hub_harness::{cluster, contracts, fault, observe};

/// Path to the `hubd` binary in this workspace's `target/debug/` directory.
///
/// Uses `CARGO_MANIFEST_DIR` (resolved at compile time) to locate the
/// workspace root, then appends `target/debug/hubd`.
pub fn hubd_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .unwrap_or(std::path::Path::new("."))
        .join("target")
        .join("debug")
        .join("hubd")
}
