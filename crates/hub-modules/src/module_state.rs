//! Shared module state container for block-scoped execution.

use std::sync::{Arc, RwLock};

use alloy_primitives::{B256, keccak256};

use crate::{
    acp::AcpModule, bulletin::BulletinModule, hub::HubModule, kv_store::InMemoryKvStore,
    native_account::NativeNonceStore,
};

const MODULE_ROOT_NAMESPACE: &[u8] = b"_HUB_MODULE_ROOT";

/// All four mutable module instances for a single block execution.
#[derive(Clone, Debug, Default)]
pub struct ModuleState {
    /// Access Control Policy module.
    pub acp: AcpModule,
    /// Bulletin module.
    pub bulletin: BulletinModule,
    /// Hub module.
    pub hub: HubModule,
    /// Native account nonce store.
    pub nonces: NativeNonceStore,
}

impl ModuleState {
    /// Compute a deterministic state root from all module stores.
    ///
    /// The root is `keccak256(namespace || keccak256(acp) || keccak256(bulletin) || keccak256(hub) || keccak256(nonces))`.
    pub fn state_root(&self) -> B256 {
        let acp_bytes = self.acp.store().serialize();
        let bulletin_bytes = self.bulletin.store().serialize();
        let hub_bytes = self.hub.store().serialize();
        let nonce_bytes = self.nonces.store().serialize();

        let mut buf = Vec::with_capacity(MODULE_ROOT_NAMESPACE.len() + 128);
        buf.extend_from_slice(MODULE_ROOT_NAMESPACE);
        buf.extend_from_slice(keccak256(&acp_bytes).as_slice());
        buf.extend_from_slice(keccak256(&bulletin_bytes).as_slice());
        buf.extend_from_slice(keccak256(&hub_bytes).as_slice());
        buf.extend_from_slice(keccak256(&nonce_bytes).as_slice());
        keccak256(buf)
    }

    /// Serialize each module's store for persistence.
    pub fn serialize_stores(&self) -> [Vec<u8>; 4] {
        [
            self.acp.store().serialize(),
            self.bulletin.store().serialize(),
            self.hub.store().serialize(),
            self.nonces.store().serialize(),
        ]
    }

    /// Reconstruct from deserialized stores.
    pub fn from_stores(stores: [InMemoryKvStore; 4]) -> Self {
        let [acp_store, bulletin_store, hub_store, nonce_store] = stores;
        Self {
            acp: AcpModule::from_store(acp_store),
            bulletin: BulletinModule::from_store(bulletin_store),
            hub: HubModule::from_store(hub_store),
            nonces: NativeNonceStore::from_store(nonce_store),
        }
    }
}

/// Thread-safe shared module state for use across block executions.
pub type SharedModuleState = Arc<RwLock<ModuleState>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_root_is_deterministic() {
        let s1 = ModuleState::default();
        let s2 = ModuleState::default();
        assert_eq!(s1.state_root(), s2.state_root());
        assert_ne!(s1.state_root(), B256::ZERO);
    }

    #[test]
    fn state_root_changes_with_data() {
        let s1 = ModuleState::default();
        let root_empty = s1.state_root();

        let mut s2 = ModuleState::default();
        s2.nonces
            .check_and_increment("did:key:z6MkAlice", 0)
            .unwrap();
        let root_with_nonce = s2.state_root();

        assert_ne!(root_empty, root_with_nonce);
    }

    #[test]
    fn serialize_and_from_stores_roundtrip() {
        let mut state = ModuleState::default();
        state
            .nonces
            .check_and_increment("did:key:z6MkAlice", 0)
            .unwrap();

        let stores = state.serialize_stores();
        let deserialized = [
            InMemoryKvStore::deserialize(&stores[0]).unwrap(),
            InMemoryKvStore::deserialize(&stores[1]).unwrap(),
            InMemoryKvStore::deserialize(&stores[2]).unwrap(),
            InMemoryKvStore::deserialize(&stores[3]).unwrap(),
        ];
        let restored = ModuleState::from_stores(deserialized);

        assert_eq!(state.state_root(), restored.state_root());
        assert_eq!(restored.nonces.get_nonce("did:key:z6MkAlice"), 1);
    }
}
