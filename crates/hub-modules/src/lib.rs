//! Hub module implementations — ACP, Bulletin, and Hub.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use alloy_primitives as _;

/// Access Control Policy module (precompile `0x0810`).
pub mod acp;
/// Bulletin module (precompile `0x0811`).
pub mod bulletin;
/// Hub module (precompile `0x0812`).
pub mod hub;
