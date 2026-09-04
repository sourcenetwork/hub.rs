//! Committee selection for DKG epochs.

use commonware_consensus::types::Epoch;
use commonware_glue::dkg::ParticipantsProvider;
use commonware_utils::{ordered::Set, sequence::Unit};
use hub_domain::PublicKey;

/// The genesis validator set for every epoch.
///
/// Registry-backed membership replaces this in the next stack PR.
#[derive(Clone, Debug)]
pub struct StaticParticipants {
    players: Set<PublicKey>,
}

impl StaticParticipants {
    /// Use `players` for every epoch.
    pub const fn new(players: Set<PublicKey>) -> Self {
        Self { players }
    }
}

impl ParticipantsProvider for StaticParticipants {
    type PublicKey = PublicKey;
    type Directory = Unit;

    async fn participants(&mut self, _epoch: Epoch) -> Set<Self::PublicKey> {
        self.players.clone()
    }

    async fn directory(&mut self, _epoch: Epoch, _players: Set<Self::PublicKey>) -> Unit {
        Unit
    }
}
