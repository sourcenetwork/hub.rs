#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

/// Wall-clock timestamp paired with block height.
///
/// The proposer's wall-clock reading (unix seconds) becomes authoritative
/// once validators sign the block. `block_height` replaces protobuf's
/// `nanos` — nanosecond precision is meaningless in consensus, while
/// block height gives total ordering. Both values come from
/// `BlockContext.header` (timestamp + number).
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
