//! Certificate provider whose per-epoch schemes are registered as ceremonies complete.

use std::{collections::HashMap, sync::Arc};

use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig,
    certificate::{Provider, Scoped},
    ed25519,
};
use commonware_glue::dkg::{Registrar as RegistrarTrait, types::SchemeInfo};
use hub_app::ConsensusScheme;
use parking_lot::Mutex;

type Scheme = ConsensusScheme;

/// Certificate provider whose per-epoch schemes are registered as ceremonies complete.
#[derive(Clone, Debug, Default)]
pub struct DynamicProvider {
    schemes: Arc<Mutex<HashMap<Epoch, Arc<Scheme>>>>,
}

impl DynamicProvider {
    /// Register the certificate scheme for `epoch`.
    pub fn register(&self, epoch: Epoch, scheme: Scheme) {
        self.schemes.lock().insert(epoch, Arc::new(scheme));
    }
}

impl Provider for DynamicProvider {
    type Scope = Epoch;
    type Scheme = Scheme;

    fn scoped(&self, scope: Self::Scope) -> Option<Scoped<Self::Scheme>> {
        self.schemes.lock().get(&scope).cloned().map(Scoped::scheme)
    }

    fn scheme(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>> {
        self.schemes.lock().get(&scope).cloned()
    }
}

/// Adapter that registers reshare outputs with the [`DynamicProvider`].
#[derive(Clone, Debug)]
pub struct Registrar {
    provider: DynamicProvider,
}

impl Registrar {
    /// Wrap `provider` for registration by the reshare actor.
    pub const fn new(provider: DynamicProvider) -> Self {
        Self { provider }
    }
}

impl RegistrarTrait for Registrar {
    type Variant = MinSig;
    type PublicKey = ed25519::PublicKey;

    async fn register(&self, epoch: Epoch, info: SchemeInfo<Self::Variant, Self::PublicKey>) {
        let scheme = match info {
            SchemeInfo::Verifier {
                participants,
                sharing,
            } => Scheme::verifier(crate::NAMESPACE, participants, sharing),
            SchemeInfo::Signer {
                participants,
                sharing,
                share,
            } => Scheme::signer(crate::NAMESPACE, participants, sharing, share)
                .expect("registered share must match participant set"),
        };
        self.provider.register(epoch, scheme);
    }
}
