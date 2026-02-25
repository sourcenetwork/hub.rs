//! Epoch lifecycle manager for Simplex consensus.
//!
//! Manages the ed25519 scheme provider, validator set oracle, and per-epoch
//! engine handles. When the commonware Muxer API supports SubSender→Engine
//! interop, this module will also manage epoch-scoped channel routing.

use std::collections::BTreeMap;

use commonware_consensus::types::Epoch;
use commonware_cryptography::ed25519;
use commonware_p2p::Manager;
use commonware_runtime::Handle;
use commonware_utils::ordered::Set;
use tracing::info;

use crate::scheme::{Ed25519Scheme, SIMPLEX_NAMESPACE};
use crate::scheme_provider::EpochSchemeProvider;

/// Manages Simplex engine lifecycle across epochs.
///
/// Handles scheme registration, validator set oracle tracking, and engine
/// handle management. The caller creates and starts engines; this struct
/// tracks their lifecycle.
pub struct EpochManager {
    scheme_provider: EpochSchemeProvider,
    my_private_key: ed25519::PrivateKey,
    active_epochs: BTreeMap<Epoch, Handle<()>>,
}

impl std::fmt::Debug for EpochManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochManager")
            .field(
                "active_epochs",
                &self.active_epochs.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl EpochManager {
    /// Create a new epoch manager.
    pub const fn new(
        scheme_provider: EpochSchemeProvider,
        my_private_key: ed25519::PrivateKey,
    ) -> Self {
        Self {
            scheme_provider,
            my_private_key,
            active_epochs: BTreeMap::new(),
        }
    }

    /// Enter a new epoch: build the scheme, register it, and track validators.
    ///
    /// Returns the scheme for the caller to use when creating the engine.
    pub async fn enter<O: Manager<PublicKey = ed25519::PublicKey>>(
        &mut self,
        epoch: Epoch,
        participants: Set<ed25519::PublicKey>,
        oracle: &mut O,
    ) -> Ed25519Scheme {
        let scheme = Ed25519Scheme::signer(
            SIMPLEX_NAMESPACE,
            participants.clone(),
            self.my_private_key.clone(),
        )
        .expect("private key is a participant");

        self.scheme_provider.register(epoch, scheme.clone());
        oracle.track(epoch.get(), participants.clone()).await;

        info!(
            %epoch,
            validators = participants.len(),
            "entered epoch"
        );

        scheme
    }

    /// Store the engine handle for an active epoch.
    pub fn track_engine(&mut self, epoch: Epoch, handle: Handle<()>) {
        self.active_epochs.insert(epoch, handle);
    }

    /// Exit an epoch: abort the engine and remove the scheme.
    pub fn exit(&mut self, epoch: &Epoch) {
        if let Some(handle) = self.active_epochs.remove(epoch) {
            handle.abort();
        }
        self.scheme_provider.remove(epoch);
        info!(%epoch, "exited epoch");
    }

    /// Returns the next epoch number (one above the highest active epoch).
    pub fn next_epoch(&self) -> Epoch {
        let next_raw = self.active_epochs.keys().last().map_or(1, |e| e.get() + 1);
        Epoch::new(next_raw)
    }

    /// Access the underlying scheme provider.
    pub const fn scheme_provider(&self) -> &EpochSchemeProvider {
        &self.scheme_provider
    }
}
