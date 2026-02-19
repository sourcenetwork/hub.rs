#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

/// Wall-clock timestamp paired with block height.
///
/// Matches Go's `sourcehub.acp.Timestamp` — captures both the proposer's
/// wall-clock reading (unix seconds) and the block height at which the
/// record was created. Both values come from `BlockContext.header`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Timestamp {
    pub seconds: u64,
    pub block_height: u64,
}

/// A duration expressed either as wall-clock seconds or a block count.
///
/// Matches Go's `sourcehub.acp.Duration` oneof: modules that use
/// time-based expiration can express it in either unit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Duration {
    Seconds(u64),
    Blocks(u64),
}

impl Default for Duration {
    fn default() -> Self {
        Self::Seconds(0)
    }
}
