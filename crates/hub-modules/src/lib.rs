//! Hub module implementations — ACP, Bulletin, and Hub.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use alloy_primitives as _;

mod borsh_did;
/// Shared key encoding helpers (length prefix, sanitization).
pub mod key_encoding;
/// Shared module state container.
pub mod module_state;
/// Shared types used across modules (Timestamp, Duration).
pub mod types;

/// Access Control Policy module (precompile `0x0810`).
pub mod acp;
/// Bulletin module (precompile `0x0811`).
pub mod bulletin;
/// Hub module (precompile `0x0812`).
pub mod hub;
/// Native account state (DID-keyed nonce tracking).
pub mod native_account;

pub use module_state::{ModuleState, SharedModuleState};
