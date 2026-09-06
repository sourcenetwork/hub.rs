//! Ordered module persistence with query-state publication after database transitions.

use commonware_cryptography::sha256::Digest;
use commonware_glue::stateful::db::{
    Anchor, Barrier, DatabaseSet, Shared, StateSyncSet, SyncEngineConfig, TipUpdate,
};
use commonware_storage::qmdb::sync::Target;
use commonware_utils::channel::ring;
use commonware_utils::non_empty_range;
use hub_backend::{
    AccountsDb, CodeDb, Ctx, HubConfig, StorageDb,
    native::{self, NativeConfig, NativeDb, NativeStateSet},
};
use hub_domain::Tx;
use hub_executor::{BlockContext, ExecutionOutcome, HubExecutor, ModuleSnapshot};

use crate::{AppError, execute_block};

/// Execution and ordered native partitions, coordinated by Commonware as one set.
pub type OrderedDatabases = (
    Shared<AccountsDb>,
    Shared<StorageDb>,
    Shared<CodeDb>,
    Shared<NativeDb>,
    Shared<NativeDb>,
    Shared<NativeDb>,
    Shared<NativeDb>,
);
type Pending = <OrderedDatabases as DatabaseSet<Ctx>>::Unmerkleized;
type Sealed = <OrderedDatabases as DatabaseSet<Ctx>>::Merkleized;
type Config = <OrderedDatabases as DatabaseSet<Ctx>>::Config;
/// Seven operation-log targets selected by one authenticated revision.
pub type OrderedTargets = <OrderedDatabases as DatabaseSet<Ctx>>::SyncTargets;

/// Storage configuration and the trusted startup recovery selection.
pub struct OrderedConfig {
    databases: Config,
    executor: HubExecutor,
    recovery: Option<OrderedTargets>,
}

impl std::fmt::Debug for OrderedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderedConfig")
            .field("recovery", &self.recovery)
            .finish_non_exhaustive()
    }
}

impl OrderedConfig {
    /// Recover existing journals to targets authenticated by the caller before publication.
    /// Sync uses the targets supplied to `StateSyncSet::sync` instead of this startup selection.
    #[must_use]
    pub const fn recover_to(mut self, targets: OrderedTargets) -> Self {
        self.recovery = Some(targets);
        self
    }
}

/// Pending storage and logical module state from the same parent.
pub struct OrderedPending {
    databases: Pending,
    modules: ModuleSnapshot,
}

/// Sealed storage and the corresponding logical module state.
#[derive(Clone)]
pub struct OrderedSealed {
    databases: Sealed,
    modules: ModuleSnapshot,
    height: u64,
}

/// Ordered storage lifecycle for native execution, independent of application callbacks.
///
/// Database mutations must not overlap, as required by `DatabaseSet`. Queries over
/// logical modules keep the previous snapshot until all partition mutations finish.
/// This set is not yet used by the node's application or query-proof protocol.
#[derive(Clone)]
pub struct OrderedState {
    databases: OrderedDatabases,
    executor: HubExecutor,
}

impl std::fmt::Debug for OrderedPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderedPending").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for OrderedSealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderedSealed")
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for OrderedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderedState")
            .field("deployment", &self.executor.chain_id())
            .finish_non_exhaustive()
    }
}

impl OrderedSealed {
    /// Operation-log targets authenticated by the revision that selects these batches.
    pub fn sync_targets(&self) -> <OrderedState as DatabaseSet<Ctx>>::SyncTargets {
        let db = &self.databases;
        let execution = crate::sync_targets(&crate::db_targets_from_merkleized(&(
            db.0.clone(),
            db.1.clone(),
            db.2.clone(),
        )));
        let native =
            |batch: &<NativeDb as commonware_glue::stateful::db::ManagedDb<Ctx>>::Merkleized| {
                Target::new(
                    batch.ops_root(),
                    non_empty_range!(batch.sync_boundary(), batch.bounds().tip.size),
                )
            };
        (
            execution.0,
            execution.1,
            execution.2,
            native(&db.3),
            native(&db.4),
            native(&db.5),
            native(&db.6),
        )
    }
}

#[cfg(test)]
mod tests;

/// Configure execution and native journals alongside an executor without JMT trees.
pub fn ordered_config(
    execution: HubConfig,
    native: NativeConfig,
    executor: HubExecutor,
) -> OrderedConfig {
    OrderedConfig {
        databases: (
            execution.0,
            execution.1,
            execution.2,
            native.0,
            native.1,
            native.2,
            native.3,
        ),
        executor,
        recovery: None,
    }
}

impl OrderedState {
    /// Open fresh storage, or rewind existing journals before publishing query state.
    ///
    /// Unanchored existing state is rejected. A failed partition rewind is fatal,
    /// matching Commonware's `DatabaseSet` recovery contract.
    pub async fn open(context: Ctx, config: OrderedConfig) -> Result<Self, AppError> {
        if config.executor.module_trees().is_some() {
            return Err(AppError::Execution(
                "ordered storage cannot attach JMT trees".into(),
            ));
        }
        let databases = Box::pin(OrderedDatabases::init(context, config.databases)).await;
        match config.recovery {
            Some(targets) => {
                databases.rewind_to_targets(targets.clone()).await;
                if databases.committed_targets().await != targets {
                    return Err(AppError::RootMismatch("ordered recovery targets"));
                }
            }
            None if databases.committed_targets().await
                != OrderedDatabases::initial_sync_targets() =>
            {
                return Err(AppError::Execution(
                    "existing ordered state requires an authenticated recovery target".into(),
                ));
            }
            None => {}
        }
        Self::restore(databases, config.executor).await
    }

    async fn restore(databases: OrderedDatabases, executor: HubExecutor) -> Result<Self, AppError> {
        let set = Self {
            databases,
            executor,
        };
        set.reload().await?;
        Ok(set)
    }

    async fn reload(&self) -> Result<(), AppError> {
        let db = &self.databases;
        let native: NativeStateSet = (db.3.clone(), db.4.clone(), db.5.clone(), db.6.clone());
        let modules = native::load_modules(&native).await?;
        self.executor.set_base_modules(modules);
        Ok(())
    }

    /// Execute and seal a branch without changing applied storage or query maps.
    pub async fn execute(
        &self,
        parent: OrderedPending,
        context: &BlockContext,
        txs: &[Tx],
    ) -> Result<(OrderedSealed, ExecutionOutcome), AppError> {
        let (accounts, storage, code, acp, bulletin, hub, nonces) = parent.databases;
        // Ordered storage supplies the module commitment after execution.
        let execution_context = context.clone().with_receipt_only();
        let mut executed = execute_block(
            &self.executor,
            (accounts, storage, code),
            &execution_context,
            txs,
            parent.modules.clone(),
        )
        .await?;
        let native = native::prepare(
            (acp, bulletin, hub, nonces),
            executed.modules.changes_from(&parent.modules),
        )
        .await?;
        executed.outcome.module_state_root = native::state_root(&native);
        if context
            .expected_module_state_root
            .is_some_and(|root| root != executed.outcome.module_state_root)
        {
            return Err(AppError::RootMismatch("ordered module state"));
        }
        let execution = executed.merkleized;
        Ok((
            OrderedSealed {
                databases: (
                    execution.0,
                    execution.1,
                    execution.2,
                    native.0,
                    native.1,
                    native.2,
                    native.3,
                ),
                modules: executed.modules,
                height: context.header.number,
            },
            executed.outcome,
        ))
    }
}

impl DatabaseSet<Ctx> for OrderedState {
    type Unmerkleized = OrderedPending;
    type Merkleized = OrderedSealed;
    type Readers = <OrderedDatabases as DatabaseSet<Ctx>>::Readers;
    type Config = OrderedConfig;
    type SyncTargets = OrderedTargets;

    async fn init(context: Ctx, config: Self::Config) -> Self {
        Self::open(context, config)
            .await
            .expect("recover ordered module state")
    }

    fn initial_sync_targets() -> Self::SyncTargets {
        OrderedDatabases::initial_sync_targets()
    }

    async fn new_batches(&self) -> OrderedPending {
        OrderedPending {
            databases: self.databases.new_batches().await,
            modules: self
                .executor
                .snapshot()
                .expect("capture ordered module state"),
        }
    }

    fn fork_batches(parent: &OrderedSealed) -> OrderedPending {
        OrderedPending {
            databases: OrderedDatabases::fork_batches(&parent.databases),
            modules: parent.modules.clone(),
        }
    }

    fn matches_sync_targets(batches: &OrderedSealed, targets: &Self::SyncTargets) -> bool {
        OrderedDatabases::matches_sync_targets(&batches.databases, targets)
    }

    fn readers(&self) -> Self::Readers {
        self.databases.readers()
    }

    async fn apply(&self, batches: OrderedSealed) {
        self.databases.apply(batches.databases).await;
        self.executor
            .commit_snapshot(batches.height, batches.modules)
            .expect("publish applied module state");
    }

    async fn finalize(&self) -> Barrier {
        self.databases.finalize().await
    }

    async fn prune(&self, targets: &Self::SyncTargets) {
        self.databases.prune(targets).await;
    }

    async fn committed_targets(&self) -> Self::SyncTargets {
        self.databases.committed_targets().await
    }

    async fn rewind_to_targets(&self, targets: Self::SyncTargets) {
        self.databases.rewind_to_targets(targets).await;
        self.reload().await.expect("reload rewound module state");
    }
}

impl<R: Send + 'static> StateSyncSet<Ctx, R, Digest> for OrderedState
where
    OrderedDatabases: StateSyncSet<Ctx, R, Digest, Error = String>,
{
    type Error = String;

    async fn sync(
        context: Ctx,
        config: Self::Config,
        sources: R,
        anchor: Anchor<Digest>,
        targets: Self::SyncTargets,
        tip_updates: ring::Receiver<TipUpdate<Digest, Self::SyncTargets>>,
        sync_config: SyncEngineConfig,
    ) -> Result<(Self, Anchor<Digest>), String> {
        if config.executor.module_trees().is_some() {
            return Err("ordered storage cannot attach JMT trees".into());
        }
        let (databases, anchor) = Box::pin(OrderedDatabases::sync(
            context,
            config.databases,
            sources,
            anchor,
            targets,
            tip_updates,
            sync_config,
        ))
        .await?;
        let state = Self::restore(databases, config.executor)
            .await
            .map_err(|e| e.to_string())?;
        Ok((state, anchor))
    }
}
