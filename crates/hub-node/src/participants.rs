//! Committee selection for DKG epochs.

use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock},
};

use alloy_primitives::{Address, U256, keccak256};
use commonware_codec::ReadExt as _;
use commonware_consensus::types::Epoch;
use commonware_cryptography::ed25519;
use commonware_glue::dkg::ParticipantsProvider;
use commonware_utils::{ordered::Set, sequence::Unit};
use hub_domain::PublicKey;
use hub_executor::VALIDATOR_REGISTRY_ADDRESS;
use hub_traits::StateDbRead as _;

use crate::CommittedState;

const SLOT_VALIDATOR_COUNT: U256 = U256::from_limbs([1, 0, 0, 0]);
const SLOT_VALIDATORS_ARRAY_BASE: U256 = U256::from_limbs([2, 0, 0, 0]);
const SLOT_VALIDATORS_MAPPING_BASE: U256 = U256::from_limbs([3, 0, 0, 0]);

fn mapping_slot(key: Address) -> U256 {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(key.as_slice());
    buf[32..64].copy_from_slice(&SLOT_VALIDATORS_MAPPING_BASE.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(buf).0)
}

fn array_element_slot(index: u64) -> U256 {
    let hash = keccak256(SLOT_VALIDATORS_ARRAY_BASE.to_be_bytes::<32>());
    U256::from_be_bytes(hash.0).wrapping_add(U256::from(index))
}

fn stored_address(value: U256) -> Address {
    let bytes = value.to_be_bytes::<32>();
    Address::from_slice(&bytes[12..])
}

/// Derive a stable validator EVM address from its ed25519 consensus key.
#[must_use]
pub fn validator_address(public_key: &PublicKey) -> Address {
    let encoded = commonware_codec::Encode::encode(public_key);
    let digest = keccak256(encoded);
    Address::from_slice(&digest[12..])
}

/// Epoch-stable DKG membership read from committed ValidatorRegistry state.
#[derive(Clone, Debug, Default)]
pub struct RegistryParticipants {
    state: Arc<OnceLock<CommittedState>>,
    epochs: BTreeMap<Epoch, Set<PublicKey>>,
}

impl RegistryParticipants {
    /// Create a provider whose committed state will be attached after startup.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the live committed state initialized by the stateful actor.
    pub fn attach_state(&self, state: CommittedState) {
        assert!(
            self.state.set(state).is_ok(),
            "registry participant state attached more than once"
        );
    }

    async fn load(&self) -> Set<PublicKey> {
        let state = self
            .state
            .get()
            .expect("registry participant state must be attached before an epoch boundary");
        let count = state
            .storage(&VALIDATOR_REGISTRY_ADDRESS, &SLOT_VALIDATOR_COUNT)
            .await
            .expect("validator count must be readable")
            .as_limbs()[0];
        let mut players = Vec::with_capacity(count as usize);
        for index in 0..count {
            let address = state
                .storage(&VALIDATOR_REGISTRY_ADDRESS, &array_element_slot(index))
                .await
                .expect("validator address must be readable");
            let entry = mapping_slot(stored_address(address));
            let packed = state
                .storage(&VALIDATOR_REGISTRY_ADDRESS, &entry)
                .await
                .expect("validator entry must be readable");
            if packed.is_zero() || packed.to_be_bytes::<32>()[20] == 0 {
                continue;
            }
            let key = state
                .storage(
                    &VALIDATOR_REGISTRY_ADDRESS,
                    &entry.wrapping_add(U256::from(1)),
                )
                .await
                .expect("validator consensus key must be readable")
                .to_be_bytes::<32>();
            players.push(
                ed25519::PublicKey::read(&mut key.as_slice())
                    .expect("validator consensus key must be a valid ed25519 public key"),
            );
        }
        Set::from_iter_dedup(players)
    }
}

impl ParticipantsProvider for RegistryParticipants {
    type PublicKey = PublicKey;
    type Directory = Unit;

    async fn participants(&mut self, epoch: Epoch) -> Set<Self::PublicKey> {
        if let Some(players) = self.epochs.get(&epoch) {
            return players.clone();
        }
        let players = self.load().await;
        assert!(
            !players.is_empty(),
            "validator registry returned no active participants for epoch {epoch}"
        );
        self.epochs.insert(epoch, players.clone());
        players
    }

    async fn directory(&mut self, _epoch: Epoch, _players: Set<Self::PublicKey>) -> Unit {
        Unit
    }
}
