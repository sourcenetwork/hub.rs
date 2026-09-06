use alloy_primitives::B256;
use commonware_cryptography::sha256::Digest;
use commonware_glue::stateful::db::{
    AttachableResolver, BatchContext, DatabaseSet, ManagedDb, Merkleized, Shared, StateSyncDb,
    SyncEngineConfig, Unmerkleized,
};
use commonware_runtime::Handle;
use commonware_utils::channel::mpsc;
use hub_backend::{
    AccountsDb, CodeDb, Ctx, HubConfig, HubMerkleized, HubSyncTargets, HubUnmerkleized, StorageDb,
};
use hub_executor::{ExecutionError, HubExecutor, ModuleSnapshot};
use hub_modules::ModuleState;

/// Execution partitions and native modules under one recovery lifecycle.
pub type VeraStateSet = (
    Shared<AccountsDb>,
    Shared<StorageDb>,
    Shared<CodeDb>,
    Shared<ModuleDb>,
);
/// Pending execution and module views from the same parent revision.
pub type VeraUnmerkleized = <VeraStateSet as DatabaseSet<Ctx>>::Unmerkleized;
/// Sealed execution and module changes for a single revision.
pub type VeraMerkleized = <VeraStateSet as DatabaseSet<Ctx>>::Merkleized;
/// Per-partition targets, including the native module revision.
pub type VeraSyncTargets = <VeraStateSet as DatabaseSet<Ctx>>::SyncTargets;

/// Native revision identified by its application height and authenticated root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleTarget {
    /// Application height.
    pub height: u64,
    /// Combined ACP, bulletin, identity and native sequence root.
    pub root: B256,
}

/// Immutable native module branch carried alongside execution batches.
#[derive(Clone, Debug)]
pub struct ModuleBatch {
    pub(crate) snapshot: ModuleSnapshot,
    target: ModuleTarget,
}

impl ModuleBatch {
    fn new(height: u64, snapshot: ModuleSnapshot) -> Self {
        Self {
            target: ModuleTarget {
                height,
                root: snapshot.state_root(height),
            },
            snapshot,
        }
    }
}

impl Unmerkleized for ModuleBatch {
    type Merkleized = Self;
    type Error = ExecutionError;
    async fn merkleize(self) -> Result<Self, Self::Error> {
        Ok(self)
    }
}

impl Merkleized for ModuleBatch {
    type Digest = Digest;
    type Unmerkleized = Self;
    fn root(&self) -> Digest {
        Digest::from(self.target.root.0)
    }
    fn new_batch(&self) -> Self {
        self.clone()
    }
}

/// Native module persistence participating in Commonware's database lifecycle.
#[derive(Debug)]
pub struct ModuleDb {
    executor: HubExecutor,
    target: ModuleTarget,
}

impl ManagedDb<Ctx> for ModuleDb {
    type Unmerkleized = ModuleBatch;
    type Merkleized = ModuleBatch;
    type Error = ExecutionError;
    type Config = HubExecutor;
    type SyncTarget = ModuleTarget;

    async fn init(_context: Ctx, executor: HubExecutor) -> Result<Self, Self::Error> {
        let height = executor.module_height()?;
        let root = executor.snapshot()?.state_root(height);
        Ok(Self {
            executor,
            target: ModuleTarget { height, root },
        })
    }

    fn initial_sync_target() -> ModuleTarget {
        ModuleTarget {
            height: 0,
            root: ModuleState::default().state_root(),
        }
    }

    fn new_batch(database: BatchContext<'_, Self>) -> ModuleBatch {
        let (database, _) = database.into_parts();
        ModuleBatch::new(
            database.target.height,
            database
                .executor
                .snapshot()
                .expect("capture native module state"),
        )
    }

    fn matches_sync_target(batch: &ModuleBatch, target: &ModuleTarget) -> bool {
        batch.target == *target
    }

    async fn apply(mut self, batch: ModuleBatch) -> Result<Self, Self::Error> {
        self.executor
            .commit_snapshot(batch.target.height, batch.snapshot)?;
        self.target = batch.target;
        Ok(self)
    }

    async fn finalize(self) -> Result<(Self, Handle<()>), Self::Error> {
        // Module commits synchronously persist their WAL before apply returns.
        Ok((self, Handle::ready(Ok(()))))
    }

    fn sync_target(&self) -> ModuleTarget {
        self.target
    }

    async fn rewind_to_target(mut self, target: ModuleTarget) -> Result<Self, Self::Error> {
        if self.target != target {
            self.executor.recover_modules(target.height, target.root)?;
            self.target = target;
        }
        Ok(self)
    }
}

/// Reject snapshot synchronization until a native module peer source is configured.
#[derive(Clone, Debug)]
pub struct DisabledModuleSync;

impl AttachableResolver<ModuleDb> for DisabledModuleSync {
    async fn attach_database(&self, _db: Shared<ModuleDb>) {}
}

impl StateSyncDb<Ctx, DisabledModuleSync> for ModuleDb {
    type SyncError = ExecutionError;
    async fn sync_db(
        _context: Ctx,
        _config: HubExecutor,
        _source: DisabledModuleSync,
        _target: ModuleTarget,
        _tip_updates: mpsc::Receiver<ModuleTarget>,
        _finish: Option<mpsc::Receiver<()>>,
        _reached_target: Option<mpsc::Sender<ModuleTarget>>,
        _sync_config: SyncEngineConfig,
    ) -> Result<Self, Self::SyncError> {
        Err(ExecutionError::ModuleTree(
            "native module peer synchronization is not configured".into(),
        ))
    }
}

/// Add native persistence to the execution partition configuration.
pub fn vera_state_config(
    config: HubConfig,
    executor: HubExecutor,
) -> <VeraStateSet as DatabaseSet<Ctx>>::Config {
    (config.0, config.1, config.2, executor)
}

pub(crate) fn split_batches(batches: VeraUnmerkleized) -> (HubUnmerkleized, ModuleSnapshot) {
    ((batches.0, batches.1, batches.2), batches.3.snapshot)
}

pub(crate) fn seal_batches(
    batches: HubMerkleized,
    height: u64,
    modules: ModuleSnapshot,
) -> VeraMerkleized {
    (
        batches.0,
        batches.1,
        batches.2,
        ModuleBatch::new(height, modules),
    )
}

pub(crate) const fn module_targets(
    targets: HubSyncTargets,
    height: u64,
    root: B256,
) -> VeraSyncTargets {
    (
        targets.0,
        targets.1,
        targets.2,
        ModuleTarget { height, root },
    )
}
