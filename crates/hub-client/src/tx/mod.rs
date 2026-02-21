//! State-changing transaction methods for hub precompile modules.

/// ACP write methods (precompile `0x0810`).
pub(crate) mod acp;
/// Bulletin write methods (precompile `0x0811`).
pub(crate) mod bulletin;
/// Hub write methods (precompile `0x0812`).
pub(crate) mod hub;
