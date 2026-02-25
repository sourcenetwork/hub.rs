use std::sync::{Arc, RwLock};
use std::time::Duration;

use alloy_consensus::Header;
use alloy_primitives::{Address, B256};
use anyhow::Context as _;
use commonware_consensus::{
    Reporters,
    application::marshaled::Marshaled,
    simplex::{self, elector::RoundRobin, types::Finalization},
    types::{Epoch, FixedEpocher, ViewDelta},
};
use commonware_cryptography::{Sha256, certificate::Scheme as _, ed25519};
use commonware_parallel::Sequential;
use commonware_runtime::{Metrics as _, Spawner, buffer::paged::CacheRef, tokio};
use commonware_utils::{NZUsize, acknowledgement::Exact};
use futures::StreamExt;
use hub_domain::{
    Block, BlockCfg, BootstrapConfig, ConsensusDigest, LedgerEvent, PublicKey, TxCfg,
};
use hub_executor::{BlockContext, ModuleState, RevmExecutor, SharedModuleState};
use hub_indexer::BlockIndex;
use hub_jsonrpc::IndexedStateProvider;
use hub_ledger::{LedgerService, LedgerView};
use hub_marshal::{ArchiveInitializer, BroadcastInitializer, PeerInitializer};
use hub_reporters::{
    BlockContextProvider, FinalizedReporter, NodeStateReporter, PrevrandaoReporter,
    ValidatorSetUpdate, active_participant_set,
};
use hub_service::{NodeRunContext, NodeRunner};
use hub_simplex::{DEFAULT_MAILBOX_SIZE as MAILBOX_SIZE, DefaultPool};
use hub_transport::NetworkTransport;
use tracing::{debug, error, info, trace, warn};

use crate::{
    RevmApplication, RunnerError, epoch_manager::EpochManager, scheme::Ed25519Scheme,
    scheme_provider::EpochSchemeProvider,
};

const BLOCK_CODEC_MAX_TXS: usize = 64;
const BLOCK_CODEC_MAX_TX_BYTES: usize = 1024;
const PARTITION_PREFIX: &str = "hubd";

type Peer = ed25519::PublicKey;
type CertArchive = Finalization<Ed25519Scheme, ConsensusDigest>;
type MarshalMailbox = commonware_consensus::marshal::Mailbox<Ed25519Scheme, Block>;
type NodeStateRptr = NodeStateReporter<Ed25519Scheme>;

fn default_page_cache() -> CacheRef {
    DefaultPool::init()
}

const fn block_codec_cfg() -> BlockCfg {
    BlockCfg {
        max_txs: BLOCK_CODEC_MAX_TXS,
        tx: TxCfg {
            max_tx_bytes: BLOCK_CODEC_MAX_TX_BYTES,
        },
    }
}

#[derive(Clone, Debug)]
struct RevmContextProvider {
    gas_limit: u64,
    participant_addresses: Vec<(PublicKey, Address)>,
}

impl RevmContextProvider {
    fn beneficiary_for(&self, leader: &PublicKey) -> Address {
        self.participant_addresses
            .iter()
            .find(|(pk, _)| pk == leader)
            .map(|(_, addr)| *addr)
            .unwrap_or(Address::ZERO)
    }
}

impl BlockContextProvider for RevmContextProvider {
    fn context(&self, block: &Block) -> BlockContext {
        let header = Header {
            number: block.height,
            timestamp: block.timestamp,
            gas_limit: self.gas_limit,
            beneficiary: self.beneficiary_for(&block.context.leader),
            base_fee_per_gas: Some(0),
            ..Default::default()
        };
        BlockContext::new(header, B256::ZERO, block.prevrandao).with_verification()
    }
}

fn spawn_ledger_observers<S: Spawner>(service: LedgerService, spawner: S) {
    let mut receiver = service.subscribe();
    spawner.shared(true).spawn(move |_| async move {
        while let Some(event) = receiver.next().await {
            match event {
                LedgerEvent::TransactionSubmitted(id) => {
                    trace!(tx=?id, "mempool accepted transaction");
                }
                LedgerEvent::SeedUpdated(digest, seed) => {
                    debug!(digest=?digest, seed=?seed, "seed cache refreshed");
                }
                LedgerEvent::SnapshotPersisted(digest) => {
                    trace!(?digest, "snapshot persisted");
                }
            }
        }
    });
}

/// Production validator node runner.
#[derive(Clone, Debug)]
pub struct ProductionRunner {
    /// Ed25519 multisig signing scheme.
    pub scheme: Ed25519Scheme,
    /// Chain ID.
    pub chain_id: u64,
    /// Gas limit per block.
    pub gas_limit: u64,
    /// Bootstrap configuration.
    pub bootstrap: BootstrapConfig,
    /// Epoch length (views per epoch). `u64::MAX` = single infinite epoch.
    pub epoch_length: u64,
    /// Storage partition prefix.
    pub partition_prefix: String,
    /// Optional RPC configuration (state, bind address).
    pub rpc_config: Option<(hub_jsonrpc::NodeState, std::net::SocketAddr)>,
}

impl ProductionRunner {
    /// Create a new production runner.
    pub fn new(
        scheme: Ed25519Scheme,
        chain_id: u64,
        gas_limit: u64,
        bootstrap: BootstrapConfig,
    ) -> Self {
        Self {
            scheme,
            chain_id,
            gas_limit,
            bootstrap,
            epoch_length: u64::MAX,
            partition_prefix: PARTITION_PREFIX.to_string(),
            rpc_config: None,
        }
    }

    /// Configure RPC server.
    #[must_use]
    pub fn with_rpc(mut self, state: hub_jsonrpc::NodeState, addr: std::net::SocketAddr) -> Self {
        self.rpc_config = Some((state, addr));
        self
    }
}

impl ProductionRunner {
    /// Run the validator as a standalone process.
    pub fn run_standalone(self, config: hub_config::NodeConfig) -> Result<(), RunnerError> {
        use commonware_runtime::Runner;
        use hub_transport::NetworkConfigExt;

        let runtime_cfg =
            tokio::Config::default().with_storage_directory(config.data_dir.join("commonware"));
        let executor = tokio::Runner::new(runtime_cfg);
        executor.start(|context| async move {
            let validator_key = config
                .validator_key()
                .map_err(|e| anyhow::anyhow!("failed to load validator key: {}", e))?;

            let transport = config
                .network
                .build_local_transport(validator_key, context.clone())
                .map_err(|e| anyhow::anyhow!("failed to build transport: {}", e))?;

            let ctx =
                hub_service::NodeRunContext::new(context, std::sync::Arc::new(config), transport);

            let _ledger = self.run(ctx).await?;

            futures::future::pending::<()>().await;
            Ok::<(), RunnerError>(())
        })
    }
}

impl NodeRunner for ProductionRunner {
    type Transport = NetworkTransport<Peer, tokio::Context>;
    type Handle = LedgerService;
    type Error = RunnerError;

    async fn run(&self, ctx: NodeRunContext<Self::Transport>) -> Result<Self::Handle, Self::Error> {
        let (context, config, mut transport) = ctx.into_parts();

        info!(chain_id = self.chain_id, "Starting production validator");

        let validator_key = config
            .validator_key()
            .map_err(|e| anyhow::anyhow!("failed to load validator key: {}", e))?;
        let my_pk = commonware_cryptography::Signer::public_key(&validator_key);

        let validators = self.scheme.participants().clone();

        let scheme_provider = EpochSchemeProvider::new();
        let mut epoch_manager = EpochManager::new(scheme_provider.clone(), validator_key);
        let _epoch_scheme = epoch_manager
            .enter(Epoch::zero(), validators, &mut transport.oracle)
            .await;

        let page_cache = default_page_cache();
        let block_cfg = block_codec_cfg();

        let state = LedgerView::init(
            context.with_label("state"),
            page_cache.clone(),
            format!("{}-qmdb", self.partition_prefix),
            self.bootstrap.genesis_alloc.clone(),
            self.bootstrap.genesis_storage.clone(),
            self.bootstrap.genesis_code.clone(),
            self.chain_id,
        )
        .await
        .context("init qmdb")?;

        let ledger = LedgerService::new(state.clone());
        spawn_ledger_observers(ledger.clone(), context.clone());

        let block_index = Arc::new(BlockIndex::new());

        // Create broadcast channels for WebSocket subscriptions.
        let (heads_tx, _) = ::tokio::sync::broadcast::channel::<hub_jsonrpc::RpcBlock>(64);
        let (logs_tx, _) = ::tokio::sync::broadcast::channel::<Vec<hub_jsonrpc::RpcLog>>(256);

        let participant_addrs: Vec<(PublicKey, Address)> = self
            .scheme
            .participants()
            .iter()
            .zip(self.bootstrap.participant_addresses.iter())
            .map(|(pk, addr)| (pk.clone(), *addr))
            .collect();

        let modules: SharedModuleState = Arc::new(RwLock::new(ModuleState::default()));
        let executor = RevmExecutor::new(self.chain_id);
        let context_provider = RevmContextProvider {
            gas_limit: self.gas_limit,
            participant_addresses: participant_addrs.clone(),
        };
        let (validator_set_tx, validator_set_rx) =
            ::tokio::sync::mpsc::unbounded_channel::<ValidatorSetUpdate>();

        let finalized_reporter = {
            let reporter =
                FinalizedReporter::new(ledger.clone(), context.clone(), executor, context_provider)
                    .with_block_index(block_index.clone())
                    .with_subscriptions(heads_tx.clone(), logs_tx.clone())
                    .with_validator_set_updates(validator_set_tx, self.chain_id, self.gas_limit);
            if let Some((state, _)) = &self.rpc_config {
                reporter.with_node_state(state.clone())
            } else {
                reporter
            }
        };

        let resolver = PeerInitializer::init::<_, _, _, Block, _, _, _>(
            &context.with_label("resolver"),
            my_pk.clone(),
            transport.oracle.clone(),
            transport.oracle.clone(),
            transport.marshal.backfill,
        );

        let (broadcast_engine, buffer) = BroadcastInitializer::init::<_, Peer, Block>(
            context.with_label("broadcast"),
            my_pk.clone(),
            block_cfg,
        );
        broadcast_engine.start(transport.marshal.blocks);

        let partition_prefix = &self.partition_prefix;
        let cert_cfg = <Ed25519Scheme as commonware_cryptography::certificate::Scheme>::certificate_codec_config_unbounded();
        let finalizations_by_height = ArchiveInitializer::init::<_, ConsensusDigest, CertArchive>(
            context.with_label("finalizations_by_height"),
            format!("{partition_prefix}-finalizations-by-height"),
            cert_cfg,
        )
        .await
        .context("init finalizations archive")?;

        let finalized_blocks = ArchiveInitializer::init::<_, ConsensusDigest, Block>(
            context.with_label("finalized_blocks"),
            format!("{partition_prefix}-finalized-blocks"),
            block_cfg,
        )
        .await
        .context("init blocks archive")?;

        let (actor, marshal_mailbox, _last_processed_height) =
            hub_marshal::ActorInitializer::init::<_, Block, _, _, _, Exact>(
                context.clone(),
                finalizations_by_height,
                finalized_blocks,
                scheme_provider,
                page_cache.clone(),
                block_cfg,
            )
            .await;
        actor.start(finalized_reporter, buffer, resolver);

        let epoch_length =
            std::num::NonZeroU64::new(self.epoch_length).expect("epoch length must be non-zero");
        let epocher = FixedEpocher::new(epoch_length);
        let executor = RevmExecutor::new(self.chain_id);
        let mut app = RevmApplication::<Ed25519Scheme, _>::new(
            ledger.clone(),
            executor,
            block_cfg.max_txs,
            self.gas_limit,
        )
        .with_participant_addresses(participant_addrs);
        if let Some((state, _)) = &self.rpc_config {
            app = app.with_node_state(state.clone());
        }
        let marshaled = Marshaled::new(
            context.with_label("marshaled"),
            app,
            marshal_mailbox.clone(),
            epocher,
        );

        let seed_reporter = PrevrandaoReporter::<Ed25519Scheme>::new(ledger.clone());
        let node_state_reporter = self
            .rpc_config
            .as_ref()
            .map(|(state, _)| NodeStateReporter::<Ed25519Scheme>::new(state.clone()));
        let inner_reporters: Reporters<_, MarshalMailbox, Option<NodeStateRptr>> =
            Reporters::from((marshal_mailbox.clone(), node_state_reporter));
        let reporter = Reporters::from((seed_reporter, inner_reporters));

        for tx in &self.bootstrap.bootstrap_txs {
            ledger.submit_tx_trusted(tx.clone()).await;
        }

        let engine = simplex::Engine::new(
            context.with_label("engine"),
            simplex::Config {
                scheme: self.scheme.clone(),
                elector: RoundRobin::<Sha256>::default(),
                blocker: transport.oracle.clone(),
                automaton: marshaled.clone(),
                relay: marshaled,
                reporter,
                strategy: Sequential,
                partition: self.partition_prefix.clone(),
                mailbox_size: MAILBOX_SIZE,
                epoch: Epoch::zero(),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                leader_timeout: Duration::from_millis(500),
                notarization_timeout: Duration::from_secs(1),
                nullify_retry: Duration::from_secs(2),
                fetch_timeout: Duration::from_millis(500),
                activity_timeout: ViewDelta::new(20),
                skip_timeout: ViewDelta::new(10),
                fetch_concurrent: 8,
                page_cache,
            },
        );
        let engine_handle = engine.start(
            transport.simplex.votes,
            transport.simplex.certs,
            transport.simplex.resolver,
        );
        epoch_manager.track_engine(Epoch::zero(), engine_handle);

        // Spawn validator set update consumer that drives epoch transitions.
        {
            let consumer_pk = my_pk.clone();
            let mut consumer_oracle = transport.oracle.clone();
            let mut consumer_rx = validator_set_rx;
            context.clone().shared(true).spawn(move |_| async move {
                let mut epoch_manager = epoch_manager;
                while let Some(update) = consumer_rx.recv().await {
                    let Some(new_participants) = active_participant_set(&update.validators) else {
                        warn!(
                            height = update.height,
                            "validator set update has no active validators with valid keys"
                        );
                        continue;
                    };
                    if new_participants.position(&consumer_pk).is_none() {
                        info!(
                            height = update.height,
                            "validator set update excludes this node; skipping epoch entry"
                        );
                        continue;
                    }
                    let next_epoch = epoch_manager.next_epoch();
                    let _scheme = epoch_manager
                        .enter(next_epoch, new_participants, &mut consumer_oracle)
                        .await;
                }
            });
        }

        // Start RPC server with IndexedStateProvider if configured.
        // FinalizedReporter writes indexed blocks; IndexedStateProvider reads them for RPC.
        if let Some((node_state, addr)) = &self.rpc_config {
            let qmdb_state = ledger.qmdb_state().await;
            let hub_index = block_index.clone();
            let hub_modules = modules.clone();
            let provider = IndexedStateProvider::new(
                block_index,
                qmdb_state,
                self.chain_id,
                self.gas_limit,
                modules.clone(),
            );
            let rpc = hub_jsonrpc::RpcServer::with_state_provider(
                node_state.clone(),
                *addr,
                self.chain_id,
                provider,
            )
            .with_subscriptions(heads_tx, logs_tx)
            .with_hub_index_and_modules(hub_index, hub_modules);
            let rpc_handle = rpc.start();
            context.clone().shared(true).spawn(move |_| async move {
                rpc_handle.stopped().await;
                error!("RPC server stopped unexpectedly");
            });
        }

        info!("Validator started successfully");
        Ok(ledger)
    }
}
