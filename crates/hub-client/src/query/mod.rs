//! Read-only query methods for hub precompile modules.

/// ACP queries (precompile `0x0810`).
pub(crate) mod acp;
/// Bulletin queries (precompile `0x0811`).
pub(crate) mod bulletin;
/// Hub queries (precompile `0x0812`).
pub(crate) mod hub;
