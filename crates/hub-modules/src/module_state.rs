//! Bundled module state shared between executor and RPC layer.

use std::sync::{Arc, RwLock};

use crate::acp::AcpModule;
use crate::bulletin::BulletinModule;
use crate::hub::HubModule;
use crate::native_account::NativeNonceStore;

/// All hub module state, bundled for sharing between the executor
/// (mutation during block execution) and the RPC layer (read-only
/// for `eth_call` queries).
#[derive(Clone, Debug)]
pub struct ModuleState {
    /// Access control policies (Zanzibar relation tuples).
    pub acp: AcpModule,
    /// Bulletin board (namespaces, posts, collaborators).
    pub bulletin: BulletinModule,
    /// Hub identity (JWS tokens, chain config).
    pub hub: HubModule,
    /// BLS native account nonce tracking.
    pub nonces: NativeNonceStore,
}

impl Default for ModuleState {
    fn default() -> Self {
        Self {
            acp: AcpModule::new(),
            bulletin: BulletinModule::new(),
            hub: HubModule::new(),
            nonces: NativeNonceStore::default(),
        }
    }
}

/// Thread-safe handle to shared module state.
pub type SharedModuleState = Arc<RwLock<ModuleState>>;
