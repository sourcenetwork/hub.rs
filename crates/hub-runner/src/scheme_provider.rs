//! Epoch-aware scheme provider for ed25519 multisig consensus.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use commonware_consensus::types::Epoch;

use crate::Ed25519Scheme;

/// Provides ed25519 signing schemes scoped by epoch.
///
/// Supports dynamic registration and removal of schemes as the validator set
/// changes across epochs.
#[derive(Clone, Debug)]
pub struct EpochSchemeProvider {
    schemes: Arc<RwLock<HashMap<Epoch, Arc<Ed25519Scheme>>>>,
}

impl Default for EpochSchemeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl EpochSchemeProvider {
    /// Create an empty provider with no registered schemes.
    pub fn new() -> Self {
        Self {
            schemes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a scheme for the given epoch.
    pub fn register(&self, epoch: Epoch, scheme: Ed25519Scheme) {
        self.schemes
            .write()
            .expect("lock")
            .insert(epoch, Arc::new(scheme));
    }

    /// Remove the scheme for the given epoch.
    pub fn remove(&self, epoch: &Epoch) {
        self.schemes.write().expect("lock").remove(epoch);
    }
}

impl commonware_cryptography::certificate::Provider for EpochSchemeProvider {
    type Scope = Epoch;
    type Scheme = Ed25519Scheme;

    fn scoped(&self, epoch: Epoch) -> Option<Arc<Self::Scheme>> {
        self.schemes.read().expect("lock").get(&epoch).cloned()
    }

    fn all(&self) -> Option<Arc<Self::Scheme>> {
        None
    }
}
