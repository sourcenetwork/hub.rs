//! End-to-end test harness for hub.
//!
//! Re-exports `hub-harness` (from backbone) and provides workspace-relative
//! binary resolution so tests can find the locally-built `hubd`.

use std::time::Duration;

pub use hub_harness::{cluster, contracts, fault, observe, resolve_binary};

/// Receipt polling tuned for CI clusters, where forwarding to the current leader
/// can take multiple block intervals before the receipt becomes visible.
pub const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(300);
/// Maximum number of receipt polls before an e2e test gives up on a transaction.
pub const RECEIPT_POLL_ATTEMPTS: u32 = 400;
