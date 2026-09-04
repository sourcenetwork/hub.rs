//! Round-robin leader election with VRF seed delivery to the application.

use alloy_primitives::B256;
use commonware_codec::Encode as _;
use commonware_consensus::{
    simplex::{
        elector::{Config, Elector, RoundRobin, RoundRobinElector, Terms},
        scheme::bls12381_threshold::vrf::Certificate,
    },
    types::{Participant, Round},
};
use commonware_cryptography::{Hasher as _, Sha256, bls12381::primitives::variant::MinSig};
use commonware_utils::ordered::Set;
use hub_app::{ConsensusScheme, VrfSeedCache};
use hub_domain::PublicKey;

/// Elector configuration that preserves round-robin leaders and captures the
/// canonical threshold VRF seed from the certificate unlocking each round.
#[derive(Clone, Debug)]
pub(crate) struct VrfElectorConfig {
    seeds: VrfSeedCache,
}

impl VrfElectorConfig {
    pub(crate) const fn new(seeds: VrfSeedCache) -> Self {
        Self { seeds }
    }
}

impl Config<ConsensusScheme> for VrfElectorConfig {
    type Elector = VrfElector;

    fn build(self, participants: &Set<PublicKey>) -> Self::Elector {
        let inner = <RoundRobin<Sha256> as Config<ConsensusScheme>>::build(
            RoundRobin::default(),
            participants,
        );
        VrfElector {
            seeds: self.seeds,
            inner,
        }
    }
}

/// Initialized elector used by each Simplex epoch.
#[derive(Clone, Debug)]
pub(crate) struct VrfElector {
    seeds: VrfSeedCache,
    inner: RoundRobinElector<ConsensusScheme>,
}

impl Elector<ConsensusScheme> for VrfElector {
    fn terms(&self) -> Terms {
        self.inner.terms()
    }

    fn elect(&self, round: Round, certificate: Option<&Certificate<MinSig>>) -> Participant {
        if let Some(signature) = certificate.and_then(Certificate::get) {
            // EVM exposes a 32-byte PREVRANDAO while the MinSig seed is a
            // canonical 48-byte G1 point. Hashing the encoding preserves all
            // of its entropy and gives every validator the same B256.
            let encoded = signature.seed_signature.encode();
            let digest = Sha256::hash(&[encoded.as_ref()]);
            self.seeds.insert(round, B256::from(digest.0));
        }
        self.inner.elect(round, certificate)
    }
}
