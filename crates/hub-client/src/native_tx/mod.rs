//! State-changing native BLS transaction methods for hub precompile modules.

/// ACP native write methods (precompile `0x0810`).
pub(crate) mod acp;
/// Bulletin native write methods (precompile `0x0811`).
pub(crate) mod bulletin;
/// Hub native write methods (precompile `0x0812`).
pub(crate) mod hub;
