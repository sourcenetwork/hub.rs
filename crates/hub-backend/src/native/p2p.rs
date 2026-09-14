//! Peer transport specialized for ordered native module records.

pub use crate::p2p::{MAX_FETCH_OPS, MAX_MESSAGE_BYTES, MAX_RESPONSE_BYTES};

/// Native operation codec.
pub type WireOperation = crate::p2p::WireOperation<super::NativeDb>;
/// Native serving handle.
pub type WireDatabase = crate::p2p::WireDatabase<super::NativeDb>;
/// Native resolver mailbox.
pub type WireMailbox = crate::p2p::WireMailbox<super::NativeDb>;
/// Native synchronization source.
pub type Resolver = crate::p2p::Resolver<super::NativeDb>;

#[cfg(test)]
mod tests;
