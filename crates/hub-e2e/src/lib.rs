//! End-to-end test harness for hub.
//!
//! Re-exports `hub-harness` (from backbone) and provides workspace-relative
//! binary resolution so tests can find the locally-built `hubd`.

pub use hub_harness::{cluster, contracts, fault, observe, resolve_binary};
