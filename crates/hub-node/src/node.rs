//! Validator assembly: start every commonware actor around the hub application
//! and run until one of them stops.

use std::{
    marker::PhantomData,
    sync::{Arc, OnceLock},
    time::Duration,
};

use commonware_broadcast::buffered;
use commonware_codec::Encode as _;
use commonware_consensus::{
    Reporters,
    marshal::{
        self, Identifier, core::Actor as MarshalActor, resolver::p2p as marshal_resolver,
        standard::Deferred,
    },
    simplex::{
        SkipBudget,
        config::{ForwardPolicy, SkipPolicy},
    },
    types::{Epoch, FixedEpocher, Height, ViewDelta},
};
use commonware_cryptography::{Digestible as _, Signer as _};
use commonware_glue::{
    dkg::{
        SecretStore as _,
        fence::Fence,
        orchestrator, probe, reshare,
        state_sync::{Config as StateSyncConfig, Plan as StateSyncPlan, StateSync},
        types::Payload,
    },
    stateful::{
        Config as StatefulConfig, Stateful, SyncPlan,
        db::{Shared, SyncEngineConfig, p2p as state_p2p},
    },
};
use commonware_p2p::{Ingress, Provider as _, authenticated::discovery};
use commonware_parallel::Sequential;
use commonware_runtime::{Handle, Spawner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_storage::{archive::prunable, translator::TwoCap};
use commonware_utils::{NZDuration, NZU64, NZUsize, sequence::Unit};
use hub_app::{
    ConsensusScheme, StatefulHubApp,
    ordered_state::{OrderedState, ordered_config},
};
use hub_backend::{
    AccountsDb, CodeDb, StorageDb,
    native::{self, NativeDb},
    p2p::{MAX_FETCH_OPS, Resolver as StateResolver, WireDatabase},
    state_set_config,
};
use hub_consensus::components::InMemoryMempool;
use hub_domain::EpochMaterial;
use hub_executor::{ExecutionConfig, HubExecutor, MempoolValidator};
use hub_indexer::{BlockIndex, LightBlockIndex, StoredEpochMaterial};
use hub_jsonrpc::{IndexedStateProvider, NodeState, RpcServer, TxSubmitCallback};
use tracing::{error, info};

use crate::{
    BACKFILL_CHANNEL, BROADCAST_CHANNEL, CERTIFICATE_CHANNEL, CommittedState, DKG_CHANNEL,
    DKG_PROBE_CHANNEL, DynamicProvider, FileSecretStore, IO_BUFFER_SIZE, MAILBOX_SIZE,
    MAX_BLOCK_TXS, MAX_MESSAGE_SIZE, MAX_PARTICIPANTS, MAX_SUPPORTED_MODE, MAX_TX_BYTES,
    MEMPOOL_CHANNEL, MESSAGE_RATE, NAMESPACE, NodeSettings, P2P_SUFFIX, PAGE_CACHE_SIZE, PAGE_SIZE,
    RESOLVER_CHANNEL, REVEAL, Registrar, RegistryParticipants, SHARING_MODE, TxGossip,
    VOTE_CHANNEL, VrfElectorConfig,
    sink::{FinalizationArtifacts, FinalizationLookup, NodeSink, SinkParts},
    spawn_tx_receiver,
    tx_gossip::SharedValidator,
};

pub(super) const PARTITION_PREFIX: &str = "hub";

/// Run a validator until one of its actors stops.
pub async fn run_node(context: tokio::Context, settings: NodeSettings) -> anyhow::Result<()> {
    let NodeSettings {
        config,
        genesis,
        peers,
        secrets_path,
        rpc_addr,
        leader_timeout,
        certification_timeout,
        timeout_retry,
    } = settings;
    let chain_id = config.chain_id;
    let gas_limit = config.execution.gas_limit;
    let snapshot = config.snapshot.clone().unwrap_or_default();
    anyhow::ensure!(
        snapshot.record_bytes > 0 && snapshot.peer_timeout_ms > 0,
        "snapshot byte limit and peer deadline must be positive"
    );
    let signing_key = config.validator_key()?;
    let local = signing_key.public_key();
    let validator_index = peers
        .participants
        .iter()
        .position(|pk| *pk == local)
        .ok_or_else(|| anyhow::anyhow!("validator key is not in peers.json"))?;
    let blocks_per_epoch = std::num::NonZeroU64::new(genesis.blocks_per_epoch)
        .ok_or_else(|| anyhow::anyhow!("genesis blocks_per_epoch must be non-zero"))?;
    let epoch_info = genesis
        .decode_epoch_info()?
        .ok_or_else(|| anyhow::anyhow!("genesis.json is missing epoch_info"))?;
    let listen: std::net::SocketAddr = config.network.listen_addr.parse()?;
    let dial: std::net::SocketAddr = config
        .network
        .dialable_addr
        .as_deref()
        .map_or(Ok(listen), str::parse)?;
    let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

    // Network.
    let bootstrappers = peers
        .bootstrappers
        .iter()
        .filter(|(pk, _)| *pk != local)
        .map(|(pk, addr)| (pk.clone(), Ingress::Socket(*addr)))
        .collect();
    let max_peers_per_set = NZUsize!(MAX_PARTICIPANTS.get() as usize);
    let mut p2p_config = discovery::Config::local(
        signing_key.clone(),
        &[NAMESPACE, P2P_SUFFIX].concat(),
        listen,
        dial,
        bootstrappers,
        max_peers_per_set,
        MAX_MESSAGE_SIZE,
    );
    p2p_config.mailbox_size = MAILBOX_SIZE;
    let (mut p2p, oracle) = discovery::Network::new(context.child("network"), p2p_config);
    let vote_network = p2p.register(VOTE_CHANNEL, MESSAGE_RATE);
    let certificate_network = p2p.register(CERTIFICATE_CHANNEL, MESSAGE_RATE);
    let resolver_network = p2p.register(RESOLVER_CHANNEL, MESSAGE_RATE);
    let backfill_network = p2p.register(BACKFILL_CHANNEL, MESSAGE_RATE);
    let broadcast_network = p2p.register(BROADCAST_CHANNEL, MESSAGE_RATE);
    let dkg_network = p2p.register(DKG_CHANNEL, MESSAGE_RATE);
    let dkg_probe_network = p2p.register(DKG_PROBE_CHANNEL, MESSAGE_RATE);
    let (mempool_sender, mempool_receiver) = p2p.register(MEMPOOL_CHANNEL, MESSAGE_RATE);
    let history_network = p2p.register(crate::HISTORY_CHANNEL, MESSAGE_RATE);
    let mut state_resolver_handles = Vec::new();
    macro_rules! state_channel {
        ($id:literal, $db:ty) => {{
            let (actor, mailbox) = state_p2p::Actor::new(
                context.child(concat!("state_resolver_", stringify!($id))),
                state_p2p::Config {
                    peer_provider: oracle.clone(),
                    blocker: oracle.clone(),
                    database: None::<Shared<WireDatabase<$db>>>,
                    mailbox_size: NZUsize!(16),
                    me: Some(local.clone()),
                    timeout: Duration::from_secs(2),
                    fetch_retry_timeout: Duration::from_millis(100),
                    max_serve_ops: MAX_FETCH_OPS,
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            state_resolver_handles
                .push(actor.start(p2p.register(crate::QMDB_CHANNELS[$id], MESSAGE_RATE)));
            StateResolver::<$db>::new(mailbox)
        }};
    }
    let state_resolvers = (
        state_channel!(0, AccountsDb),
        state_channel!(1, StorageDb),
        state_channel!(2, CodeDb),
        state_channel!(3, NativeDb),
        state_channel!(4, NativeDb),
        state_channel!(5, NativeDb),
        state_channel!(6, NativeDb),
        (),
    );
    let p2p_handle = p2p.start();

    // Epoch-0 certificate scheme.
    let provider = DynamicProvider::default();
    let mut store = FileSecretStore::load(&secrets_path)?;
    let players = epoch_info.output.players().clone();
    anyhow::ensure!(
        players.len() <= hub_domain::max_epoch_participants(blocks_per_epoch) as usize,
        "genesis participants exceed the configured epoch capacity"
    );
    let sharing = epoch_info.output.public().clone();
    match store.get_share(Epoch::zero()).await {
        Some(share) => provider.register(
            Epoch::zero(),
            ConsensusScheme::signer(NAMESPACE, players.clone(), sharing.clone(), share)
                .ok_or_else(|| anyhow::anyhow!("epoch-0 share does not match genesis"))?,
        ),
        None => provider.register(
            Epoch::zero(),
            ConsensusScheme::verifier(NAMESPACE, players.clone(), sharing.clone()),
        ),
    }

    let executor = HubExecutor::new(chain_id).with_membership_epochs(blocks_per_epoch);
    #[cfg(feature = "fault-injection")]
    let executor = executor.with_crash_marker(config.data_dir.join("module-commit-crash"));
    let modules = executor.modules().clone();
    let genesis_block =
        crate::native_genesis::load_or_create(&context, &config.data_dir, &genesis, &page_cache)
            .await?
            .with_payload(Payload::EpochInfo(epoch_info.clone()));
    let executor = executor.with_genesis_id(genesis_block.id().0.0);

    // Marshal, broadcast, archives.
    let resolver = marshal_resolver::init(
        context.child("marshal_resolver"),
        marshal_resolver::Config {
            public_key: local.clone(),
            peer_provider: oracle.clone(),
            blocker: oracle.clone(),
            mailbox_size: MAILBOX_SIZE,
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
        backfill_network,
    );
    let (broadcast_engine, buffer) = buffered::Engine::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: local.clone(),
            mailbox_size: MAILBOX_SIZE,
            deque_size: 16,
            priority: false,
            codec_config: block_cfg(),
            peer_provider: oracle.clone(),
        },
    );
    let broadcast_handle = broadcast_engine.start(broadcast_network);
    let finalizations_by_height = prunable::Archive::init(
        context.child("finalizations_by_height"),
        archive_config("finalizations", page_cache.clone(), ()),
    )
    .await?;
    let finalized_blocks = prunable::Archive::init(
        context.child("finalized_blocks"),
        archive_config("blocks", page_cache.clone(), block_cfg()),
    )
    .await?;

    let (probe_actor, probe_mailbox) = probe::Actor::new(probe::Config {
        context: context.child("dkg_probe"),
        manager: oracle.clone(),
        bootstrap: probe::Bootstrap {
            epoch: Epoch::zero(),
            participants: epoch_info.participants(),
            directory: Unit,
        },
        verifier: ConsensusScheme::certificate_verifier(NAMESPACE, *sharing.public()),
        genesis: epoch_info.clone(),
        strategy: Sequential,
        blocker: oracle.clone(),
        blocks_per_epoch,
        retry_timeout: NZDuration!(Duration::from_millis(500)),
        mailbox_size: MAILBOX_SIZE,
        block_codec_config: block_cfg(),
    });
    let probe_handle = probe_actor.start(dkg_probe_network);

    let stateful_startup = context.child("stateful_startup");
    let mut plan = SyncPlan::init(&stateful_startup, PARTITION_PREFIX).await;
    let completed_sync_height = plan.sync_height();
    let snapshot_sync = plan.should_state_sync(config.snapshot.is_some());
    let probe_artifact = if snapshot_sync {
        let artifact = probe_mailbox
            .subscribe()
            .await
            .map_err(|e| anyhow::anyhow!("dkg probe stopped before state sync: {e:?}"))?;
        provider.register(
            artifact.info.epoch,
            ConsensusScheme::verifier(
                NAMESPACE,
                artifact.info.output.players().clone(),
                artifact.info.output.public().clone(),
            ),
        );
        plan = plan.with_floor(artifact.floor.clone());
        Some(artifact)
    } else {
        None
    };

    let (marshal_actor, marshal, floor) = MarshalActor::init(
        context.child("marshal"),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            provider: provider.clone(),
            epocher: FixedEpocher::new(blocks_per_epoch),
            start: plan.marshal_start(genesis_block.clone()),
            partition_prefix: PARTITION_PREFIX.to_string(),
            mailbox_size: MAILBOX_SIZE,
            view_retention: ViewDelta::new(10),
            prunable_items_per_section: NZU64!(10),
            page_cache: page_cache.clone(),
            replay_buffer: IO_BUFFER_SIZE,
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            block_codec_config: block_cfg(),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
            strategy: Sequential,
        },
    )
    .await;

    // DKG / reshare.
    let fence_epoch = probe_artifact
        .as_ref()
        .map_or_else(Epoch::zero, |artifact| artifact.info.epoch);
    let state_sync = probe_artifact.map(|artifact| StateSync {
        info: artifact.info,
        floor: plan
            .floor()
            .cloned()
            .expect("state sync startup carries a floor"),
    });
    let state_sync = StateSyncPlan::init(
        context.child("dkg_state_sync_plan"),
        StateSyncConfig {
            partition_prefix: PARTITION_PREFIX.to_string(),
            max_participants: MAX_PARTICIPANTS,
            max_supported_mode: MAX_SUPPORTED_MODE,
        },
        state_sync,
    )
    .await;
    let (fence, gate) = Fence::new(fence_epoch);
    let history = Arc::new(crate::FinalizedHistory::open(
        config.data_dir.join("history"),
        &genesis_block,
    )?);
    let participants_provider = RegistryParticipants::new(
        modules.clone(),
        players.clone(),
        history.clone(),
        blocks_per_epoch,
    );
    let (reshare_actor, reshare_mailbox) = reshare::Actor::new(
        context.child("reshare"),
        reshare::Config {
            signer: signing_key.clone(),
            manager: oracle.clone(),
            blocker: oracle.clone(),
            participants_provider: participants_provider.clone(),
            secret_store: store,
            strategy: Sequential,
            registrar: Registrar::new(provider.clone()),
            marshal: marshal.clone(),
            state_sync: state_sync.clone(),
            fence,
            namespace: NAMESPACE,
            sharing_mode: SHARING_MODE,
            reveal: REVEAL,
            mailbox_size: MAILBOX_SIZE,
            partition_prefix: format!("{PARTITION_PREFIX}-reshare"),
            max_participants: MAX_PARTICIPANTS,
            blocks_per_epoch,
            batch_verifier: PhantomData::<commonware_cryptography::ed25519::Batch>,
        },
    );

    // Mempool, RPC plumbing, and the application.
    let mempool = InMemoryMempool::default();
    let (history_failures, mut history_failure_rx) = ::tokio::sync::mpsc::channel(1);
    let block_index = Arc::new(BlockIndex::new());
    let light_block_index = Arc::new(LightBlockIndex::new());
    let initial_material = EpochMaterial::new(
        epoch_info.output.players().clone(),
        epoch_info.output.public().clone(),
    );
    light_block_index.insert_epoch_material(
        epoch_info.epoch.get(),
        StoredEpochMaterial {
            bytes: initial_material.encode().into(),
        },
    );
    let (history_peer, history_peer_handle) = crate::start_history_peer(
        context.child("history_peer"),
        history.clone(),
        light_block_index.clone(),
        oracle.clone(),
        oracle.clone(),
        local.clone(),
        history_network,
    );
    let history_peer = Arc::new(::tokio::sync::Mutex::new(history_peer));
    let node_state = NodeState::new(
        chain_id,
        validator_index as u32,
        peers.participants.len() as u32,
    );
    if let Some(height) = completed_sync_height {
        node_state.set_snapshot_revision(height.get());
    }
    let (heads_tx, _) = ::tokio::sync::broadcast::channel(64);
    let (logs_tx, _) = ::tokio::sync::broadcast::channel(256);
    let (headers_tx, _) = ::tokio::sync::broadcast::channel(64);

    let validator: SharedValidator = Arc::new(OnceLock::new());
    let finalization_marshal = marshal.clone();
    let finalization_lookup: FinalizationLookup = Arc::new(move |height| {
        let marshal = finalization_marshal.clone();
        Box::pin(async move {
            // Marshal dispatches only after its finalized archive is durable.
            // Ancestors finalized by a descendant need not have a certificate.
            marshal
                .get_finalization(Height::new(height))
                .await
                .map(|finalization| FinalizationArtifacts {
                    epoch: finalization.proposal.round.epoch().get(),
                    certificate: finalization.certificate.encode().to_vec(),
                    finalization: finalization.encode().to_vec(),
                })
        })
    });
    let sink = NodeSink::new(SinkParts {
        history: history.clone(),
        failures: history_failures,
        index: block_index.clone(),
        light_index: light_block_index.clone(),
        heads: heads_tx.clone(),
        logs: logs_tx.clone(),
        headers: headers_tx.clone(),
        node_state: node_state.clone(),
        finalization_lookup: finalization_lookup.clone(),
        chain_id,
        publisher_index: validator_index as u32,
        gas_limit,
        executor: executor.clone(),
        mempool: mempool.clone(),
        validator: validator.clone(),
    });
    let participant_addresses = peers
        .participants
        .iter()
        .cloned()
        .zip(genesis.to_genesis_state()?.participant_addresses)
        .collect();
    let application = StatefulHubApp::<_, OrderedState>::new(
        executor.clone(),
        genesis_block.clone(),
        mempool.clone(),
        sink.clone(),
        MAX_BLOCK_TXS,
        gas_limit,
    )
    .with_participant_addresses(participant_addresses);
    let vrf_elector = VrfElectorConfig::new(application.vrf_seed_cache());

    let snapshot_history = crate::history::SnapshotHistory {
        history: history.clone(),
        genesis: genesis_block.clone(),
        index: block_index.clone(),
        epochs: light_block_index.clone(),
        trusted: *sharing.public(),
        lookup: finalization_lookup.clone(),
        limits: crate::HistoryLimits {
            record_bytes: snapshot.record_bytes,
            logs: snapshot.logs,
        },
        deadline: Duration::from_millis(snapshot.peer_timeout_ms),
        #[cfg(feature = "fault-injection")]
        crash_marker: config.data_dir.join("snapshot-import-crash"),
    };
    let sync_marshal = marshal.clone();
    let mut sync_peers = oracle.clone();
    let sync_local = local.clone();
    let sync_history_peer = history_peer.clone();
    let sync_status = node_state.clone();
    let (stateful_actor, stateful_mailbox) = Stateful::init(
        context.child("stateful"),
        StatefulConfig {
            application,
            db_config: ordered_config(
                state_set_config(PARTITION_PREFIX, page_cache.clone()),
                native::state_config(PARTITION_PREFIX, page_cache.clone()),
                executor.clone(),
            )
            .recover_from_marshal()
            .with_sync_handoff(move |anchor| async move {
                let selected: hub_domain::Block = sync_marshal
                    .get_block(Identifier::Height(anchor.height))
                    .await
                    .ok_or_else(|| "missing synchronized history anchor".to_string())?;
                if selected.digest() != anchor.digest || selected.context.round != anchor.round {
                    return Err("synchronized history anchor mismatch".into());
                }
                let mut updates = sync_peers.subscribe().await;
                let peers = updates
                    .recv()
                    .await
                    .ok_or_else(|| "history peer subscription closed".to_string())?;
                let peers: Vec<_> = peers
                    .all
                    .primary
                    .into_iter()
                    .filter(|peer| *peer != sync_local)
                    .collect();
                let mut client = sync_history_peer.lock().await;
                snapshot_history
                    .recover(&mut client, &peers, &selected)
                    .await
                    .map_err(|e| e.to_string())?;
                sync_status.set_snapshot_revision(anchor.height.get());
                Ok(())
            }),
            provider: mempool.clone(),
            marshal: (marshal.clone(), floor),
            mailbox_size: MAILBOX_SIZE,
            plan,
            resolvers: state_resolvers,
            sync_config: sync_config(),
            prune_config: None,
        },
    );

    let deferred = Deferred::new(
        context.child("deferred"),
        reshare::Application::new(
            stateful_mailbox.clone(),
            reshare_mailbox.clone(),
            blocks_per_epoch,
        ),
        marshal.clone(),
        FixedEpocher::new(blocks_per_epoch),
    );
    let skip_timeout = Duration::from_secs(5)
        .max(certification_timeout.saturating_add(Duration::from_millis(1)))
        .max(timeout_retry.saturating_add(Duration::from_millis(1)));
    let (orchestrator_actor, orchestrator_mailbox) = orchestrator::Actor::new(
        context.child("orchestrator"),
        orchestrator::Config {
            oracle: oracle.clone(),
            manager: oracle.clone(),
            provider: provider.clone(),
            marshal: marshal.clone(),
            application: deferred,
            strategy: Sequential,
            simplex: orchestrator::SimplexConfig {
                elector: vrf_elector,
                mailbox_size: NZUsize!(3),
                replay_buffer: IO_BUFFER_SIZE,
                write_buffer: IO_BUFFER_SIZE,
                page_cache_page_size: PAGE_SIZE,
                page_cache_pages: PAGE_CACHE_SIZE,
                leader_timeout,
                certification_timeout,
                timeout_retry,
                fetch_timeout: Duration::from_secs(2),
                view_retention: ViewDelta::new(10),
                skip: SkipPolicy::Enabled {
                    timeout: skip_timeout,
                    budget: SkipBudget::Participants,
                },
                forward: ForwardPolicy::Disabled,
                track_historical_votes: false,
            },
            gate,
            state_sync,
            blocks_per_epoch,
            muxer_size: 128,
            mailbox_size: MAILBOX_SIZE,
            partition_prefix: format!("{PARTITION_PREFIX}-orchestrator"),
        },
    );
    let orchestrator_handle =
        orchestrator_actor.start(vote_network, certificate_network, resolver_network);

    let reporters = Reporters::from((
        stateful_mailbox.clone(),
        Reporters::from((orchestrator_mailbox, reshare_mailbox)),
    ));
    let marshal_handle = marshal_actor.start(reporters, buffer, resolver);
    probe_mailbox.attach(marshal.clone());
    if !snapshot_sync {
        let processed_height = marshal.get_processed_height().await;
        let recovered_height = processed_height
            .into_iter()
            .chain(completed_sync_height)
            .max()
            .unwrap_or_else(Height::zero);
        let recovered = match marshal
            .get_block(Identifier::Height(recovered_height))
            .await
        {
            Some(block) => block,
            None if processed_height == Some(recovered_height) => marshal
                .get_block(Identifier::Height(recovered_height.next()))
                .await
                .ok_or_else(|| anyhow::anyhow!("missing recovered module anchor"))?,
            None => anyhow::bail!("missing recovered module anchor"),
        };
        history
            .recover(
                &genesis_block,
                &recovered,
                &block_index,
                &light_block_index,
                &finalization_lookup,
            )
            .await?;
    }
    let stateful_handle = stateful_actor.start();

    // Transaction gossip and RPC over the live committed state.
    let databases = stateful_mailbox.subscribe_databases().await;
    let native_databases = databases.native_databases();
    let state_set = databases.execution_databases();
    let committed_state = CommittedState::new(state_set.clone());
    let reshare_handle = reshare_actor.start(dkg_network);
    sink.attach_state(state_set.clone());
    {
        // Hold the module read lock through publication so finalization cannot
        // advance nonces between loading them and enabling admission.
        let recovered_modules = modules.read().expect("module state lock poisoned");
        let mut admission =
            MempoolValidator::new(committed_state.clone(), ExecutionConfig::new(chain_id), 0);
        admission.reset(committed_state.clone(), recovered_modules.nonces.clone());
        let _ = validator.set(::tokio::sync::Mutex::new(admission));
    }
    let gossip = TxGossip::new(mempool.clone(), validator.clone(), chain_id, mempool_sender);
    spawn_tx_receiver(
        context.child("tx_receiver"),
        mempool_receiver,
        mempool.clone(),
        validator.clone(),
        chain_id,
    );
    let tx_submit: TxSubmitCallback = Arc::new(move |bytes| {
        let gossip = gossip.clone();
        Box::pin(async move { gossip.submit(bytes).await })
    });
    let state_provider = IndexedStateProvider::new(
        block_index.clone(),
        committed_state,
        chain_id,
        gas_limit,
        modules.clone(),
    );
    let rpc_handle = RpcServer::with_state_provider(node_state, rpc_addr, chain_id, state_provider)
        .with_max_connections(config.rpc.max_connections.get())
        .with_tx_submit(tx_submit)
        .with_subscriptions(heads_tx, logs_tx)
        .with_headers_subscription(headers_tx)
        .with_hub_index_and_modules(block_index, modules.clone())
        .with_hub_native_modules(native_databases, modules)
        .with_hub_light_block_lookup({
            let epochs = light_block_index.clone();
            Arc::new(move |height| {
                history
                    .light_block(height, &epochs)
                    .map_err(|error| error.to_string())
            })
        })
        .with_hub_light_block_index(light_block_index)
        .start();
    context.child("rpc").spawn(move |_| async move {
        rpc_handle.stopped().await;
        error!("RPC server stopped unexpectedly");
    });
    info!(validator_index, %rpc_addr, "hub validator started");

    state_resolver_handles.extend([
        p2p_handle,
        broadcast_handle,
        probe_handle,
        reshare_handle,
        orchestrator_handle,
        marshal_handle,
        stateful_handle,
        history_peer_handle,
    ]);
    ::tokio::select! {
        failure = history_failure_rx.recv() => Err(failure.unwrap_or_else(|| anyhow::anyhow!("history failure channel closed"))),
        result = Handle::select(state_resolver_handles) => result.map_err(|e| anyhow::anyhow!("validator actor failed: {e:?}")),
    }
}

pub(crate) const fn block_cfg() -> hub_domain::BlockCfg {
    hub_domain::BlockCfg {
        max_txs: MAX_BLOCK_TXS,
        tx: hub_domain::TxCfg {
            max_tx_bytes: MAX_TX_BYTES,
        },
    }
}

const fn sync_config() -> SyncEngineConfig {
    SyncEngineConfig {
        fetch_batch_size: MAX_FETCH_OPS,
        apply_batch_size: NZU64!(64),
        max_outstanding_requests: 8,
        update_channel_size: NZUsize!(256),
        max_retained_roots: 8,
    }
}

fn archive_config<C>(
    name: &str,
    page_cache: CacheRef,
    codec_config: C,
) -> prunable::Config<TwoCap, C> {
    prunable::Config {
        translator: TwoCap,
        metadata_partition: format!("{PARTITION_PREFIX}-{name}-metadata"),
        key_partition: format!("{PARTITION_PREFIX}-{name}-key"),
        key_page_cache: page_cache,
        value_partition: format!("{PARTITION_PREFIX}-{name}-value"),
        compression: None,
        codec_config,
        items_per_section: NZU64!(10),
        key_write_buffer: IO_BUFFER_SIZE,
        value_write_buffer: IO_BUFFER_SIZE,
        replay_buffer: IO_BUFFER_SIZE,
    }
}
