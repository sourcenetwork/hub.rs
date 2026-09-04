//! Consensus scheme and input types shared by the node assembly.

use commonware_consensus::simplex::scheme::bls12381_threshold::vrf;
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519};
use hub_domain::PublicKey;

/// BLS12-381 threshold signing with a VRF seed, keyed by ed25519 peer identity.
pub type ConsensusScheme = vrf::Scheme<PublicKey, MinSig>;

/// Per-proposal input forwarded by the reshare wrapper: the DKG payload to include.
pub type ReshareInput = commonware_glue::dkg::reshare::Input<(), MinSig, ed25519::PrivateKey>;
