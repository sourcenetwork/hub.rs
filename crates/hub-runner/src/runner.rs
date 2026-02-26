//! HubRunner — production validator node runner for hub.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::epoch_manager::EpochManager;
use crate::scheme_provider::EpochSchemeProvider;
use crate::tx_forward::TxForwarder;
use crate::{Ed25519Scheme, RevmApplication, RunnerError};
use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes};
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
use hub_backend as _;
use hub_domain::{
    Block, BlockCfg, BootstrapConfig, ConsensusDigest, LedgerEvent, PublicKey, Tx, TxCfg,
};
use hub_executor::{BlockContext, HubExecutor, ModuleState, ModuleTrees, SharedModuleState};
use hub_indexer::BlockIndex;
use hub_jsonrpc::IndexedStateProvider;
use hub_ledger::{LedgerService, LedgerView};
use hub_marshal::{ArchiveInitializer, BroadcastInitializer, PeerInitializer};
use hub_modules::kv_store::InMemoryKvStore;
use hub_reporters::{
    BlockContextProvider, FinalizedReporter, NodeStateReporter, PrevrandaoReporter,
    ValidatorSetUpdate, ViewTracker, active_participant_set,
};
use hub_service::{NodeRunContext, NodeRunner};
use hub_simplex::{DEFAULT_MAILBOX_SIZE as MAILBOX_SIZE, DefaultPool};
use hub_state::ModuleStateTree;
use hub_transport::NetworkTransport;
use tracing::{debug, error, info, trace, warn};

const BLOCK_CODEC_MAX_TXS: usize = 64;
const BLOCK_CODEC_MAX_TX_BYTES: usize = 65_536;
const PARTITION_PREFIX: &str = "hubd";

type Peer = ed25519::PublicKey;
type CertArchive = Finalization<Ed25519Scheme, ConsensusDigest>;
type MarshalMailbox = commonware_consensus::marshal::Mailbox<Ed25519Scheme, Block>;
type NodeStateRptr = NodeStateReporter<Ed25519Scheme>;
type ViewTrackerRptr = ViewTracker<Ed25519Scheme>;

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
struct HubContextProvider {
    gas_limit: u64,
    participant_addresses: Vec<(PublicKey, Address)>,
}

impl HubContextProvider {
    fn beneficiary_for(&self, leader: &PublicKey) -> Address {
        self.participant_addresses
            .iter()
            .find(|(pk, _)| pk == leader)
            .map(|(_, addr)| *addr)
            .unwrap_or(Address::ZERO)
    }
}

impl BlockContextProvider for HubContextProvider {
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

/// Consensus timing parameters for the Simplex engine.
#[derive(Clone, Debug)]
pub struct ConsensusParams {
    /// Leader proposal timeout.
    pub leader_timeout: Duration,
    /// Notarization timeout.
    pub notarization_timeout: Duration,
    /// Nullification retry interval.
    pub nullify_retry: Duration,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            leader_timeout: Duration::from_millis(500),
            notarization_timeout: Duration::from_secs(1),
            nullify_retry: Duration::from_secs(2),
        }
    }
}

/// Production validator node runner for hub.
#[derive(Clone, Debug)]
pub struct HubRunner {
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
    /// Optional RPC configuration (state, bind address).
    pub rpc_config: Option<(hub_jsonrpc::NodeState, std::net::SocketAddr)>,
    /// Consensus timing parameters.
    pub consensus: ConsensusParams,
}

impl HubRunner {
    /// Create a new hub runner.
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
            rpc_config: None,
            consensus: ConsensusParams::default(),
        }
    }

    /// Configure epoch length (views per epoch).
    #[must_use]
    pub const fn with_epoch_length(mut self, epoch_length: u64) -> Self {
        self.epoch_length = epoch_length;
        self
    }

    /// Configure consensus timing parameters.
    #[must_use]
    pub const fn with_consensus(mut self, params: ConsensusParams) -> Self {
        self.consensus = params;
        self
    }

    /// Configure RPC server.
    #[must_use]
    pub fn with_rpc(mut self, state: hub_jsonrpc::NodeState, addr: std::net::SocketAddr) -> Self {
        self.rpc_config = Some((state, addr));
        self
    }

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

impl NodeRunner for HubRunner {
    type Transport = NetworkTransport<Peer, tokio::Context>;
    type Handle = LedgerService;
    type Error = RunnerError;

    async fn run(&self, ctx: NodeRunContext<Self::Transport>) -> Result<Self::Handle, Self::Error> {
        let (context, config, mut transport) = ctx.into_parts();

        info!(chain_id = self.chain_id, "Starting hub validator");

        let validator_key = config
            .validator_key()
            .map_err(|e| anyhow::anyhow!("failed to load validator key: {}", e))?;
        let my_pk = commonware_cryptography::Signer::public_key(&validator_key);

        let validators = self.scheme.participants().clone();

        let scheme_provider = EpochSchemeProvider::new();
        let mut epoch_manager = EpochManager::new(scheme_provider.clone(), validator_key);
        let _epoch_scheme = epoch_manager
            .enter(Epoch::zero(), validators.clone(), &mut transport.oracle)
            .await;

        let (mempool_sender, mempool_receiver) = transport.mempool.txs;

        let page_cache = default_page_cache();
        let block_cfg = block_codec_cfg();

        let state = LedgerView::init(
            context.with_label("state"),
            page_cache.clone(),
            format!("{}-qmdb", PARTITION_PREFIX),
            self.bootstrap.genesis_alloc.clone(),
            self.bootstrap.genesis_storage.clone(),
            self.bootstrap.genesis_code.clone(),
            self.chain_id,
        )
        .await
        .context("init qmdb")?;

        let ledger = LedgerService::new(state.clone());
        spawn_ledger_observers(ledger.clone(), context.clone());

        let (_, direct_mempool, _) = ledger.proposal_components().await;

        let participants: Vec<Peer> = validators.iter().cloned().collect();
        let view_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let schedule = crate::tx_forward::LeaderSchedule::new(participants, view_counter.clone());
        let forwarder =
            TxForwarder::new(direct_mempool.clone(), schedule.clone()).with_ledger(state.clone());
        let gossip_notify = forwarder.notifier();
        forwarder.spawn_receiver(context.clone(), mempool_receiver);
        forwarder.spawn_gossip_loop(context.clone(), mempool_sender.clone());
        info!("Gulfstream targeted tx forwarding enabled");

        let block_index = Arc::new(BlockIndex::new());
        let (heads_tx, _) = ::tokio::sync::broadcast::channel::<hub_jsonrpc::RpcBlock>(64);
        let (logs_tx, _) = ::tokio::sync::broadcast::channel::<Vec<hub_jsonrpc::RpcLog>>(256);

        // Open per-module JMT state trees and load persisted state.
        let data_dir = &config.data_dir;
        let module_names = ["acp", "bulletin", "hub", "nonces"];
        let mut module_stores: [InMemoryKvStore; 4] = Default::default();
        let mut trees: Vec<Arc<Mutex<ModuleStateTree>>> = Vec::with_capacity(4);
        for (i, name) in module_names.iter().enumerate() {
            let path = data_dir.join("state").join(name);
            let tree = ModuleStateTree::open(&path)
                .with_context(|| format!("open module state tree: {name}"))?;
            let pairs = tree
                .load_all()
                .with_context(|| format!("load module state: {name}"))?;
            module_stores[i] = InMemoryKvStore::from_pairs(pairs);
            trees.push(Arc::new(Mutex::new(tree)));
        }
        let module_trees: ModuleTrees = [
            trees[0].clone(),
            trees[1].clone(),
            trees[2].clone(),
            trees[3].clone(),
        ];
        let last_committed_height = trees[3].lock().expect("lock").canonical_height();
        tracing::info!(
            last_committed_height,
            "FinalizedReporter skip height from module state trees"
        );
        let persisted_modules = ModuleState::from_stores(module_stores);

        let participant_addrs: Vec<(PublicKey, Address)> = self
            .scheme
            .participants()
            .iter()
            .zip(self.bootstrap.participant_addresses.iter())
            .map(|(pk, addr)| (pk.clone(), *addr))
            .collect();

        let module_trees_for_rpc = module_trees.clone();
        let executor = HubExecutor::new(self.chain_id).with_module_trees(module_trees);
        let modules: SharedModuleState = executor.modules().clone();
        executor.set_base_modules(persisted_modules);

        // Attach module state to the ledger so finalized native nonces
        // survive validator resets.
        state.set_modules(modules.clone()).await;

        let context_provider = HubContextProvider {
            gas_limit: self.gas_limit,
            participant_addresses: participant_addrs.clone(),
        };
        let (validator_set_tx, validator_set_rx) =
            ::tokio::sync::mpsc::unbounded_channel::<ValidatorSetUpdate>();

        let finalized_reporter = {
            let reporter = FinalizedReporter::new(
                ledger.clone(),
                context.clone(),
                executor.clone(),
                context_provider,
            )
            .with_block_index(block_index.clone())
            .with_subscriptions(heads_tx.clone(), logs_tx.clone())
            .with_last_committed_height(last_committed_height)
            .with_validator_set_updates(
                validator_set_tx,
                self.chain_id,
                self.gas_limit,
            );
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

        let cert_cfg = <Ed25519Scheme as commonware_cryptography::certificate::Scheme>::certificate_codec_config_unbounded();
        let finalizations_by_height = ArchiveInitializer::init::<_, ConsensusDigest, CertArchive>(
            context.with_label("finalizations_by_height"),
            format!("{}-finalizations-by-height", PARTITION_PREFIX),
            cert_cfg,
        )
        .await
        .context("init finalizations archive")?;

        let finalized_blocks = ArchiveInitializer::init::<_, ConsensusDigest, Block>(
            context.with_label("finalized_blocks"),
            format!("{}-finalized-blocks", PARTITION_PREFIX),
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
        let view_tracker = ViewTracker::<Ed25519Scheme>::new(view_counter);
        let node_state_reporter = self
            .rpc_config
            .as_ref()
            .map(|(state, _)| NodeStateReporter::<Ed25519Scheme>::new(state.clone()));
        let inner_reporters: Reporters<_, MarshalMailbox, Option<NodeStateRptr>> =
            Reporters::from((marshal_mailbox.clone(), node_state_reporter));
        let with_view: Reporters<_, ViewTrackerRptr, _> =
            Reporters::from((view_tracker, inner_reporters));
        let reporter = Reporters::from((seed_reporter, with_view));

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
                partition: PARTITION_PREFIX.to_string(),
                mailbox_size: MAILBOX_SIZE,
                epoch: Epoch::zero(),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                leader_timeout: self.consensus.leader_timeout,
                notarization_timeout: self.consensus.notarization_timeout,
                nullify_retry: self.consensus.nullify_retry,
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

            let (tx_broadcast_sender, mut tx_broadcast_receiver) =
                ::tokio::sync::mpsc::unbounded_channel::<Bytes>();
            context.clone().shared(true).spawn({
                let mut fwd_sender = mempool_sender;
                let fwd_schedule = Some(schedule);
                move |_| async move {
                    while let Some(tx_bytes) = tx_broadcast_receiver.recv().await {
                        TxForwarder::forward_tx(&mut fwd_sender, &fwd_schedule, &tx_bytes).await;
                    }
                }
            });
            let submit_ledger = ledger.clone();
            let tx_submit: hub_jsonrpc::TxSubmitCallback = Arc::new(move |data: Bytes| {
                let ledger = submit_ledger.clone();
                let fwd_sender = tx_broadcast_sender.clone();
                let notify = gossip_notify.clone();
                Box::pin(async move {
                    let tx = Tx::new(data.clone());
                    let inserted = ledger.submit_tx(tx).await?;
                    if inserted {
                        if fwd_sender.send(data).is_err() {
                            tracing::warn!(
                                "tx forwarding channel closed; tx in local mempool only"
                            );
                        }
                        notify.notify_one();
                    }
                    Ok(inserted)
                })
            });

            let rpc = hub_jsonrpc::RpcServer::with_state_provider(
                node_state.clone(),
                *addr,
                self.chain_id,
                provider,
            )
            .with_tx_submit(tx_submit)
            .with_subscriptions(heads_tx, logs_tx)
            .with_hub_index_and_modules(hub_index, hub_modules)
            .with_hub_module_trees(module_trees_for_rpc);
            let rpc_handle = rpc.start();
            context.clone().shared(true).spawn(move |_| async move {
                rpc_handle.stopped().await;
                error!("RPC server stopped unexpectedly");
            });
        }

        info!("Hub validator started successfully");
        Ok(ledger)
    }
}
