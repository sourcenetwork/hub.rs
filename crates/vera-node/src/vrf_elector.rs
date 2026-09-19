//! Bounded leader terms, with VRF delivery for legacy rotating deployments.

use alloy_primitives::B256;
use commonware_codec::Encode as _;
use commonware_consensus::{
    simplex::{
        elector::{Config, Elector, RoundRobin, RoundRobinElector, Terms},
        scheme::bls12381_threshold::vrf::Certificate,
    },
    types::{Participant, Round, TermLength, ViewDelta},
};
use commonware_cryptography::{Hasher as _, Sha256, bls12381::primitives::variant::MinSig};
use commonware_utils::ordered::Set;
use std::{num::NonZeroU32, time::Duration};
use vera_app::{ConsensusScheme, VrfSeedCache};
use vera_domain::{PublicKey, SimplexParameters};

/// Genesis selects rotating leaders or bounded stable-leader terms.
/// Only rotating deployments consume per-view VRF seeds.
#[derive(Clone, Debug)]
pub(crate) struct VrfElectorConfig {
    seeds: VrfSeedCache,
    pipeline: Option<SimplexParameters>,
}

impl VrfElectorConfig {
    pub(crate) const fn new(seeds: VrfSeedCache, pipeline: Option<SimplexParameters>) -> Self {
        Self { seeds, pipeline }
    }
}

impl Config<ConsensusScheme> for VrfElectorConfig {
    type Elector = VrfElector;

    fn build(self, participants: &Set<PublicKey>) -> Self::Elector {
        let mut election = RoundRobin::<Sha256>::default();
        if let Some(parameters) = self.pipeline {
            parameters
                .validate()
                .expect("validated genesis Simplex parameters");
            election = election.with_term(
                TermLength::new(
                    NonZeroU32::new(
                        u32::try_from(parameters.term_length).expect("bounded term length"),
                    )
                    .unwrap(),
                ),
                Duration::from_millis(parameters.stall_timeout_ms),
                ViewDelta::new(parameters.optimistic_views),
            );
        }
        let inner = <RoundRobin<Sha256> as Config<ConsensusScheme>>::build(election, participants);
        VrfElector {
            seeds: self.seeds,
            pipeline: self.pipeline,
            inner,
        }
    }
}

/// Initialized elector used by each Simplex epoch.
#[derive(Clone, Debug)]
pub(crate) struct VrfElector {
    seeds: VrfSeedCache,
    pipeline: Option<SimplexParameters>,
    inner: RoundRobinElector<ConsensusScheme>,
}

impl Elector<ConsensusScheme> for VrfElector {
    fn terms(&self) -> Terms {
        self.inner.terms()
    }

    fn elect(&self, round: Round, certificate: Option<&Certificate<MinSig>>) -> Participant {
        if self.pipeline.is_none()
            && let Some(signature) = certificate.and_then(Certificate::get)
        {
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::types::{Epoch, View};
    use commonware_cryptography::{Signer as _, ed25519};

    #[test]
    fn pipelined_terms_rotate_and_bound_optimistic_work() {
        let participants = Set::from_iter_dedup(
            (0..4).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key()),
        );
        let parameters = SimplexParameters::default();
        let elector =
            VrfElectorConfig::new(VrfSeedCache::default(), Some(parameters)).build(&participants);
        assert_eq!(
            elector.terms().optimistic_views().get(),
            parameters.optimistic_views
        );
        for epoch in 0..3 {
            let round = |view| Round::new(Epoch::new(epoch), View::new(view));
            let first = elector.elect(round(1), None);
            for view in 2..=parameters.term_length {
                assert_eq!(elector.elect(round(view), None), first);
            }
            assert_ne!(
                elector.elect(round(parameters.term_length + 1), None),
                first
            );
        }
        let legacy = VrfElectorConfig::new(VrfSeedCache::default(), None).build(&participants);
        assert_eq!(legacy.terms(), Terms::rotating());
    }
}
