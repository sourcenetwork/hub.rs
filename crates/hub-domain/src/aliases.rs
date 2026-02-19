//! Aliases for

/// Consensus digest type alias.
pub type ConsensusDigest = commonware_cryptography::sha256::Digest;

/// Public key type alias.
pub type PublicKey = commonware_cryptography::ed25519::PublicKey;

/// Consensus context carried by each block.
pub type ConsensusContext =
    commonware_consensus::simplex::types::Context<ConsensusDigest, PublicKey>;

/// The finalization event type alias.
pub type FinalizationEvent = (u32, ConsensusDigest);
