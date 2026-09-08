//! Wire limits shared by submission, consensus and standalone verification.

/// Maximum signed request, including its authorization envelope.
pub const MAX_TX_BYTES: usize = (12 << 20) + 4096;
/// Maximum transactions in one block.
pub const MAX_BLOCK_TXS: usize = 64;
/// Combined encoded transactions, including their vector length prefix.
pub const MAX_BLOCK_TX_BYTES: usize = 16 << 20;
/// Encoded block budget, reserving space for consensus and epoch material.
pub const MAX_BLOCK_BYTES: usize = MAX_BLOCK_TX_BYTES + (1 << 20);
/// P2P envelope budget for a complete block.
pub const MAX_MESSAGE_BYTES: u32 = (MAX_BLOCK_BYTES + (64 << 10)) as u32;
/// JSON submission budget, including hex encoding and request metadata.
pub const SUBMISSION_REQUEST_BYTES: u32 = (2 * MAX_TX_BYTES + 4096) as u32;
