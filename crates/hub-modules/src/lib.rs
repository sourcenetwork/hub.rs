//! Hub module implementations — ACP, Bulletin, and Hub.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use alloy_primitives as _;

mod borsh_did;
/// Shared key encoding helpers (length prefix, sanitization).
pub mod key_encoding;
/// Shared types used across modules (Timestamp, Duration).
pub mod types;

/// Access Control Policy module (precompile `0x0810`).
pub mod acp;
/// Bulletin module (precompile `0x0811`).
pub mod bulletin;
/// Hub module (precompile `0x0812`).
pub mod hub;
/// Shared module state container for block-scoped execution.
pub mod module_state;
/// Native account state (DID-keyed nonce tracking).
pub mod native_account;
