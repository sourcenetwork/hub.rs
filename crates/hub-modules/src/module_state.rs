//! Shared module state container for block-scoped execution.

use std::sync::{Arc, RwLock};

use crate::{
    acp::AcpModule, bulletin::BulletinModule, hub::HubModule, native_account::NativeNonceStore,
};

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

/// Thread-safe shared module state for use across block executions.
pub type SharedModuleState = Arc<RwLock<ModuleState>>;
