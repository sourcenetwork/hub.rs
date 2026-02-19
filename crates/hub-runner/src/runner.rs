//! HubRunner — production validator node runner for hub.

use std::sync::Arc;
use std::time::Duration;

use crate::tx_forward::TxForwarder;
use crate::{RevmApplication, RunnerError, ThresholdScheme};
use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes};
use anyhow::Context as _;
use commonware_consensus::{
    Reporters,
    application::marshaled::Marshaled,
    simplex::{self, elector::RoundRobin, types::Finalization},
    types::{Epoch, FixedEpocher, ViewDelta},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinSig, ed25519};
use commonware_p2p::Manager;
use commonware_parallel::Sequential;
use commonware_runtime::{Metrics as _, Spawner, buffer::paged::CacheRef, tokio};
use commonware_utils::{NZU64, NZUsize, acknowledgement::Exact};
use futures::StreamExt;
use hub_domain::{Block, BlockCfg, BootstrapConfig, ConsensusDigest, LedgerEvent, Tx, TxCfg};
use hub_executor::BlockContext;
use hub_executor::HubExecutor;
use hub_indexer::BlockIndex;
use hub_jsonrpc::IndexedStateProvider;
use hub_ledger::{LedgerService, LedgerView};
use hub_marshal::{ArchiveInitializer, BroadcastInitializer, PeerInitializer};
use hub_reporters::{
    BlockContextProvider, FinalizedReporter, NodeStateReporter, SeedReporter, ViewTracker,
};
use hub_service::{NodeRunContext, NodeRunner};
use hub_simplex::{DEFAULT_MAILBOX_SIZE as MAILBOX_SIZE, DefaultPool};
use hub_transport::NetworkTransport;
use tracing::{debug, error, info, trace};

const BLOCK_CODEC_MAX_TXS: usize = 64;
const BLOCK_CODEC_MAX_TX_BYTES: usize = 65_536;
const EPOCH_LENGTH: u64 = u64::MAX;
const PARTITION_PREFIX: &str = "hubd";

type Peer = ed25519::PublicKey;
type CertArchive = Finalization<ThresholdScheme, ConsensusDigest>;
type MarshalMailbox = commonware_consensus::marshal::Mailbox<ThresholdScheme, Block>;
type NodeStateRptr = NodeStateReporter<ThresholdScheme>;
type ViewTrackerRptr = ViewTracker<ThresholdScheme>;

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

#[derive(Clone)]
struct ConstantSchemeProvider(Arc<ThresholdScheme>);

impl commonware_cryptography::certificate::Provider for ConstantSchemeProvider {
    type Scope = Epoch;
    type Scheme = ThresholdScheme;

    fn scoped(&self, _epoch: Epoch) -> Option<Arc<Self::Scheme>> {
        Some(self.0.clone())
    }

    fn all(&self) -> Option<Arc<Self::Scheme>> {
        Some(self.0.clone())
    }
}

impl From<ThresholdScheme> for ConstantSchemeProvider {
    fn from(scheme: ThresholdScheme) -> Self {
        Self(Arc::new(scheme))
    }
}

#[derive(Clone, Debug)]
struct HubContextProvider {
    gas_limit: u64,
}

impl BlockContextProvider for HubContextProvider {
    fn context(&self, block: &Block) -> BlockContext {
        let header = Header {
            number: block.height,
            timestamp: block.timestamp,
            gas_limit: self.gas_limit,
            beneficiary: Address::ZERO,
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
    /// Threshold signing scheme.
    pub scheme: ThresholdScheme,
    /// Chain ID.
    pub chain_id: u64,
    /// Gas limit per block.
    pub gas_limit: u64,
    /// Bootstrap configuration.
    pub bootstrap: BootstrapConfig,
    /// Optional RPC configuration (state, bind address).
    pub rpc_config: Option<(hub_jsonrpc::NodeState, std::net::SocketAddr)>,
    /// Consensus timing parameters.
    pub consensus: ConsensusParams,
    /// BLS12-381 group public key from DKG ceremony.
    pub group_public_key: Vec<u8>,
}

impl HubRunner {
    /// Create a new hub runner.
    pub fn new(
        scheme: ThresholdScheme,
        chain_id: u64,
        gas_limit: u64,
        bootstrap: BootstrapConfig,
        group_public_key: Vec<u8>,
    ) -> Self {
        Self {
            scheme,
            chain_id,
            gas_limit,
            bootstrap,
            rpc_config: None,
            consensus: ConsensusParams::default(),
            group_public_key,
        }
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

        let executor = tokio::Runner::default();
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

        let validators = self.scheme.participants().clone();
        transport.oracle.track(0, validators.clone()).await;
        info!(
            count = validators.len(),
            "Registered validators with oracle"
        );

        let (mempool_sender, mempool_receiver) = transport.mempool.txs;

        let page_cache = default_page_cache();
        let block_cfg = block_codec_cfg();

        let state = LedgerView::init(
            context.with_label("state"),
            page_cache.clone(),
            format!("{}-qmdb", PARTITION_PREFIX),
            self.bootstrap.genesis_alloc.clone(),
        )
        .await
        .context("init qmdb")?;

        let ledger = LedgerService::new(state.clone());
        spawn_ledger_observers(ledger.clone(), context.clone());

        let (_, direct_mempool, _) = ledger.proposal_components().await;

        let participants: Vec<Peer> = validators.iter().cloned().collect();
        let view_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let schedule = crate::tx_forward::LeaderSchedule::new(participants, view_counter.clone());
        let forwarder = TxForwarder::new(direct_mempool.clone(), schedule.clone());
        let gossip_notify = forwarder.notifier();
        forwarder.spawn_receiver(context.clone(), mempool_receiver);
        forwarder.spawn_gossip_loop(context.clone(), mempool_sender.clone());
        info!("Gulfstream targeted tx forwarding enabled");

        let block_index = Arc::new(BlockIndex::new());

        let validator_key = config
            .validator_key()
            .map_err(|e| anyhow::anyhow!("failed to load validator key: {}", e))?;
        let my_pk = commonware_cryptography::Signer::public_key(&validator_key);

        let executor = HubExecutor::new(self.chain_id);
        let context_provider = HubContextProvider {
            gas_limit: self.gas_limit,
        };
        let finalized_reporter = FinalizedReporter::new(
            ledger.clone(),
            context.clone(),
            executor.clone(),
            context_provider,
        )
        .with_block_index(block_index.clone());

        let scheme_provider = ConstantSchemeProvider::from(self.scheme.clone());

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

        <ThresholdScheme as commonware_cryptography::certificate::Scheme>::certificate_codec_config_unbounded();
        let finalizations_by_height = ArchiveInitializer::init::<_, ConsensusDigest, CertArchive>(
            context.with_label("finalizations_by_height"),
            format!("{}-finalizations-by-height", PARTITION_PREFIX),
            (),
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

        let epocher = FixedEpocher::new(NZU64!(EPOCH_LENGTH));
        let mut app = RevmApplication::<ThresholdScheme, _>::new(
            ledger.clone(),
            executor,
            block_cfg.max_txs,
            self.gas_limit,
        );
        if let Some((state, _)) = &self.rpc_config {
            app = app.with_node_state(state.clone());
        }
        let marshaled = Marshaled::new(
            context.with_label("marshaled"),
            app,
            marshal_mailbox.clone(),
            epocher,
        );

        let seed_reporter = SeedReporter::<MinSig>::new(ledger.clone());
        let view_tracker = ViewTracker::<ThresholdScheme>::new(view_counter);
        let node_state_reporter = self
            .rpc_config
            .as_ref()
            .map(|(state, _)| NodeStateReporter::<ThresholdScheme>::new(state.clone()));
        let inner_reporters: Reporters<_, MarshalMailbox, Option<NodeStateRptr>> =
            Reporters::from((marshal_mailbox.clone(), node_state_reporter));
        let with_view: Reporters<_, ViewTrackerRptr, _> =
            Reporters::from((view_tracker, inner_reporters));
        let reporter = Reporters::from((seed_reporter, with_view));

        for tx in &self.bootstrap.bootstrap_txs {
            let _ = ledger.submit_tx(tx.clone()).await;
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
        engine.start(
            transport.simplex.votes,
            transport.simplex.certs,
            transport.simplex.resolver,
        );

        if let Some((node_state, addr)) = &self.rpc_config {
            let qmdb_state = ledger.qmdb_state().await;
            let provider = IndexedStateProvider::new(block_index, qmdb_state);

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
            let tx_submit: hub_jsonrpc::TxSubmitCallback = Arc::new(move |data: Bytes| {
                use hub_consensus::Mempool as _;
                let tx = Tx::new(data.clone());
                let inserted = direct_mempool.insert(tx);
                if inserted {
                    if tx_broadcast_sender.send(data).is_err() {
                        tracing::warn!("tx forwarding channel closed; tx in local mempool only");
                    }
                    gossip_notify.notify_one();
                }
                inserted
            });

            let rpc = hub_jsonrpc::RpcServer::with_state_provider(
                node_state.clone(),
                *addr,
                self.chain_id,
                provider,
            )
            .with_tx_submit(tx_submit);
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
