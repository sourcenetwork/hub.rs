//! Glue-managed QMDB databases for EVM state: accounts, storage, and code.
//!
//! The three databases form a [`DatabaseSet`] through commonware-glue's tuple
//! implementation; [`HubStateSet`] wraps that tuple so the combined EVM state
//! root has one definition.

use alloy_primitives::B256;
use commonware_codec::RangeCfg;
use commonware_cryptography::Sha256;
use commonware_glue::stateful::db::ManagedDb;
use commonware_glue::stateful::db::{Barrier, DatabaseSet, Reader, Shared};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, tokio};
use commonware_storage::{
    merkle::mmr,
    qmdb::any::{VariableConfig, unordered::variable},
    translator::EightCap,
};
use hub_qmdb::StateRoot;

use crate::{
    backend::store_config,
    types::{AccountKey, AccountValue, CodeKey, StorageKey, StorageValue},
};

/// Runtime context the state set runs on.
pub type Ctx = tokio::Context;

/// Account partition: 20-byte address keys, fixed 80-byte account records.
pub type AccountsDb =
    variable::Db<mmr::Family, Ctx, AccountKey, AccountValue, Sha256, EightCap, Sequential>;
/// Storage partition: 60-byte (address, generation, slot) keys, 32-byte values.
pub type StorageDb =
    variable::Db<mmr::Family, Ctx, StorageKey, StorageValue, Sha256, EightCap, Sequential>;
/// Code partition: 32-byte code-hash keys, variable-length bytecode.
pub type CodeDb = variable::Db<mmr::Family, Ctx, CodeKey, Vec<u8>, Sha256, EightCap, Sequential>;

/// The tuple that carries glue's blanket [`DatabaseSet`] implementation.
pub type HubDatabases = (Shared<AccountsDb>, Shared<StorageDb>, Shared<CodeDb>);
/// Read-only handles over committed state, in accounts, storage, code order.
pub type HubReaders = (Reader<AccountsDb>, Reader<StorageDb>, Reader<CodeDb>);
/// Pending batches forked from committed or pending state.
pub type HubUnmerkleized = (
    <AccountsDb as ManagedDb<Ctx>>::Unmerkleized,
    <StorageDb as ManagedDb<Ctx>>::Unmerkleized,
    <CodeDb as ManagedDb<Ctx>>::Unmerkleized,
);
/// Merkleized batches ready to apply on finalization.
pub type HubMerkleized = (
    <AccountsDb as ManagedDb<Ctx>>::Merkleized,
    <StorageDb as ManagedDb<Ctx>>::Merkleized,
    <CodeDb as ManagedDb<Ctx>>::Merkleized,
);
/// Per-database sync targets, in accounts, storage, code order.
pub type HubSyncTargets = (
    <AccountsDb as ManagedDb<Ctx>>::SyncTarget,
    <StorageDb as ManagedDb<Ctx>>::SyncTarget,
    <CodeDb as ManagedDb<Ctx>>::SyncTarget,
);
/// Per-database configuration, in accounts, storage, code order.
pub type HubConfig = (
    VariableConfig<EightCap, ((), ()), Sequential>,
    VariableConfig<EightCap, ((), ()), Sequential>,
    VariableConfig<EightCap, ((), (RangeCfg<usize>, ())), Sequential>,
);

/// Build the three partition configs under `prefix`, sharing `page_cache`.
pub fn state_set_config(prefix: &str, page_cache: CacheRef) -> HubConfig {
    (
        store_config(prefix, "accounts", page_cache.clone(), ((), ())),
        store_config(prefix, "storage", page_cache.clone(), ((), ())),
        store_config(prefix, "code", page_cache, ((), (RangeCfg::new(0..), ()))),
    )
}

/// The EVM state backend as a glue [`DatabaseSet`].
#[derive(Clone)]
pub struct HubStateSet(HubDatabases);

impl std::fmt::Debug for HubStateSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubStateSet").finish_non_exhaustive()
    }
}

impl HubStateSet {
    /// Borrow the underlying database tuple.
    pub const fn databases(&self) -> &HubDatabases {
        &self.0
    }
}

impl DatabaseSet<Ctx> for HubStateSet {
    type Unmerkleized = HubUnmerkleized;
    type Merkleized = HubMerkleized;
    type Readers = HubReaders;
    type Config = HubConfig;
    type SyncTargets = HubSyncTargets;

    async fn init(context: Ctx, config: Self::Config) -> Self {
        Self(<HubDatabases as DatabaseSet<Ctx>>::init(context, config).await)
    }

    fn initial_sync_targets() -> Self::SyncTargets {
        <HubDatabases as DatabaseSet<Ctx>>::initial_sync_targets()
    }

    async fn new_batches(&self) -> Self::Unmerkleized {
        self.0.new_batches().await
    }

    fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized {
        <HubDatabases as DatabaseSet<Ctx>>::fork_batches(parent)
    }

    fn matches_sync_targets(batches: &Self::Merkleized, targets: &Self::SyncTargets) -> bool {
        <HubDatabases as DatabaseSet<Ctx>>::matches_sync_targets(batches, targets)
    }

    fn readers(&self) -> Self::Readers {
        self.0.readers()
    }

    async fn apply(&self, batches: Self::Merkleized) {
        self.0.apply(batches).await;
    }

    async fn finalize(&self) -> Barrier {
        self.0.finalize().await
    }

    async fn prune(&self, targets: &Self::SyncTargets) {
        self.0.prune(targets).await;
    }

    async fn committed_targets(&self) -> Self::SyncTargets {
        self.0.committed_targets().await
    }

    async fn rewind_to_targets(&self, targets: Self::SyncTargets) {
        self.0.rewind_to_targets(targets).await;
    }
}

/// Combined EVM state root over merkleized batches.
pub fn combined_root(merkleized: &HubMerkleized) -> B256 {
    let (accounts, storage, code) = merkleized.roots();
    StateRoot::compute(accounts, storage, code)
}

/// Roots of the three merkleized batches as 32-byte values.
pub trait MerkleizedTriple {
    /// Return the accounts, storage, and code roots.
    fn roots(&self) -> (B256, B256, B256);
}

impl<A, S, C> MerkleizedTriple for (A, S, C)
where
    A: commonware_glue::stateful::db::Merkleized,
    S: commonware_glue::stateful::db::Merkleized,
    C: commonware_glue::stateful::db::Merkleized,
{
    fn roots(&self) -> (B256, B256, B256) {
        (
            B256::from_slice(self.0.root().as_ref()),
            B256::from_slice(self.1.root().as_ref()),
            B256::from_slice(self.2.root().as_ref()),
        )
    }
}
