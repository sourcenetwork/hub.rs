//! Shared module state container for cross-component access.

use std::sync::{Arc, RwLock};

use crate::acp::AcpModule;
use crate::bulletin::BulletinModule;
use crate::hub::HubModule;
use crate::native_account::NativeNonceStore;

/// All hub module instances bundled together for shared access.
#[derive(Clone, Debug, Default)]
pub struct ModuleState {
    /// ACP module instance.
    pub acp: AcpModule,
    /// Bulletin module instance.
    pub bulletin: BulletinModule,
    /// Hub module instance.
    pub hub: HubModule,
    /// Native nonce store for BLS transactions.
    pub nonces: NativeNonceStore,
}

/// Thread-safe shared reference to module state.
pub type SharedModuleState = Arc<RwLock<ModuleState>>;
