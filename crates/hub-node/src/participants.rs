//! Committee selection from execution-derived epoch rosters.

use alloy_primitives::{Address, keccak256};
use commonware_codec::ReadExt as _;
use commonware_consensus::types::Epoch;
use commonware_cryptography::ed25519;
use commonware_glue::dkg::ParticipantsProvider;
use commonware_utils::{ordered::Set, sequence::Unit};
use hub_domain::PublicKey;
use hub_executor::SharedModuleState;

/// Derive a stable validator EVM address from its ed25519 consensus key.
#[must_use]
pub fn validator_address(public_key: &PublicKey) -> Address {
    let encoded = commonware_codec::Encode::encode(public_key);
    let digest = keccak256(encoded);
    Address::from_slice(&digest[12..])
}

/// Future committees selected by finalized execution, independent of lookup time.
#[derive(Clone, Debug)]
pub struct RegistryParticipants {
    modules: SharedModuleState,
    genesis_players: Set<PublicKey>,
}

impl RegistryParticipants {
    /// Genesis supplies the lookahead until the first epoch boundary is finalized.
    #[must_use]
    pub const fn new(modules: SharedModuleState, genesis_players: Set<PublicKey>) -> Self {
        Self {
            modules,
            genesis_players,
        }
    }
}

impl ParticipantsProvider for RegistryParticipants {
    type PublicKey = PublicKey;
    type Directory = Unit;

    async fn participants(&mut self, epoch: Epoch) -> Set<Self::PublicKey> {
        if epoch.get() <= 2 {
            return self.genesis_players.clone();
        }
        let modules = self.modules.read().expect("module state lock poisoned");
        let bytes = modules
            .hub
            .consensus_roster(epoch.get())
            .expect("future consensus roster must have been finalized in the previous epoch");
        assert!(
            !bytes.is_empty()
                && bytes.len().is_multiple_of(32)
                && bytes.len() / 32 <= hub_domain::MAX_DKG_PARTICIPANTS.get() as usize,
            "invalid consensus roster size"
        );
        let keys: Vec<_> = bytes
            .chunks_exact(32)
            .map(|mut bytes| {
                ed25519::PublicKey::read(&mut bytes).expect("invalid consensus identity")
            })
            .collect();
        assert!(
            keys.windows(2).all(|pair| pair[0] < pair[1]),
            "unordered consensus roster"
        );
        Set::from_iter_dedup(keys)
    }

    async fn directory(&mut self, _epoch: Epoch, _players: Set<Self::PublicKey>) -> Unit {
        Unit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hub_modules::{hub::HubModule, kv_store::InMemoryKvStore};
    use std::sync::{Arc, RwLock};

    fn key(encoded: &str) -> PublicKey {
        PublicKey::read(&mut hex::decode(encoded).unwrap().as_slice()).unwrap()
    }

    #[tokio::test]
    async fn roster_selection_survives_later_rosters_and_store_recovery() {
        let first = key("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let second = key("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let genesis = Set::from_iter_dedup([first.clone()]);
        let modules = Arc::new(RwLock::new(hub_modules::ModuleState::default()));
        let mut provider = RegistryParticipants::new(modules.clone(), genesis.clone());
        assert_eq!(provider.participants(Epoch::new(2)).await, genesis);
        let raw = |key: &PublicKey| -> [u8; 32] {
            commonware_codec::Encode::encode(key)
                .as_ref()
                .try_into()
                .unwrap()
        };
        modules
            .write()
            .unwrap()
            .hub
            .record_consensus_roster(3, &[raw(&first)])
            .unwrap();
        let selected = provider.participants(Epoch::new(3)).await;
        assert!(
            modules
                .write()
                .unwrap()
                .hub
                .record_consensus_roster(3, &[raw(&second)])
                .is_err()
        );
        modules
            .write()
            .unwrap()
            .hub
            .record_consensus_roster(4, &[raw(&second)])
            .unwrap();
        assert_eq!(provider.participants(Epoch::new(3)).await, selected);
        let stored = modules.read().unwrap().hub.store().serialize();
        let recovered = hub_modules::ModuleState {
            hub: HubModule::from_store(InMemoryKvStore::deserialize(&stored).unwrap()),
            ..Default::default()
        };
        let mut restarted = RegistryParticipants::new(Arc::new(RwLock::new(recovered)), genesis);
        assert_eq!(restarted.participants(Epoch::new(3)).await, selected);
        assert_eq!(
            restarted.participants(Epoch::new(4)).await,
            Set::from_iter_dedup([second])
        );
        assert!(
            modules
                .write()
                .unwrap()
                .hub
                .record_consensus_roster(3, &[raw(&first)])
                .is_ok()
        );
        assert!(
            modules
                .write()
                .unwrap()
                .hub
                .record_consensus_roster(3, &[])
                .is_err()
        );
    }

    #[tokio::test]
    #[should_panic(expected = "future consensus roster must have been finalized")]
    async fn missing_roster_does_not_fall_back_to_genesis() {
        let genesis = Set::from_iter_dedup([key(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )]);
        let mut provider = RegistryParticipants::new(
            Arc::new(RwLock::new(hub_modules::ModuleState::default())),
            genesis,
        );
        provider.participants(Epoch::new(3)).await;
    }
}
