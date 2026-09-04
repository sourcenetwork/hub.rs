//! Validator assembly: start every commonware actor around the hub application
//! and run until one of them stops.

use std::{
    marker::PhantomData,
    path::Path,
    sync::{Arc, OnceLock},
    time::Duration,
};

use commonware_broadcast::buffered;
use commonware_codec::{Decode as _, Encode as _};
use commonware_consensus::{
    Reporters,
    marshal::{
        self, core::Actor as MarshalActor, resolver::p2p as marshal_resolver, standard::Deferred,
    },
    simplex::{
        SkipBudget,
        config::{ForwardPolicy, SkipPolicy},
    },
    types::{Epoch, FixedEpocher, Height, ViewDelta},
};
use commonware_cryptography::Signer as _;
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
        db::{DatabaseSet as _, SyncEngineConfig},
    },
};
use commonware_p2p::{Ingress, authenticated::discovery};
use commonware_parallel::Sequential;
use commonware_runtime::{Handle, Spawner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_storage::{archive::prunable, translator::TwoCap};
use commonware_utils::{NZDuration, NZU64, NZUsize, sequence::Unit};
use hub_app::{ConsensusScheme, StatefulHubApp, apply_genesis, genesis_block};
use hub_backend::{HubStateSet, state_set_config};
use hub_consensus::components::InMemoryMempool;
use hub_domain::{Block, EpochMaterial};
use hub_executor::{ExecutionConfig, HubExecutor, MempoolValidator, ModuleTrees};
use hub_indexer::{BlockIndex, LightBlockIndex, StoredEpochMaterial};
use hub_jsonrpc::{IndexedStateProvider, NodeState, RpcServer, TxSubmitCallback};
use hub_modules::{ModuleState, kv_store::InMemoryKvStore};
use hub_state::ModuleStateTree;
use tracing::{error, info};

use crate::{
    BACKFILL_CHANNEL, BROADCAST_CHANNEL, CERTIFICATE_CHANNEL, CommittedState, DKG_CHANNEL,
    DKG_PROBE_CHANNEL, DynamicProvider, FileSecretStore, IO_BUFFER_SIZE, MAILBOX_SIZE,
    MAX_BLOCK_TXS, MAX_MESSAGE_SIZE, MAX_PARTICIPANTS, MAX_SUPPORTED_MODE, MAX_TX_BYTES,
    MEMPOOL_CHANNEL, MESSAGE_RATE, NAMESPACE, NoSync, NodeSettings, P2P_SUFFIX, PAGE_CACHE_SIZE,
    PAGE_SIZE, RESOLVER_CHANNEL, REVEAL, Registrar, RegistryParticipants, SHARING_MODE, TxGossip,
    VOTE_CHANNEL, VrfElectorConfig,
    sink::{FinalizationArtifacts, FinalizationLookup, NodeSink, SinkParts},
    spawn_tx_receiver,
    tx_gossip::SharedValidator,
};

const PARTITION_PREFIX: &str = "hub";
const MODULE_NAMES: [&str; 4] = ["acp", "bulletin", "hub", "nonces"];

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
    let p2p_handle = p2p.start();

    // Epoch-0 certificate scheme.
    let provider = DynamicProvider::default();
    let mut store = FileSecretStore::load(&secrets_path)?;
    let players = epoch_info.output.players().clone();
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

    // Module state trees and executor.
    let (module_trees, persisted_modules) = open_module_trees(&config.data_dir)?;
    let executor = HubExecutor::new(chain_id).with_module_trees(module_trees.clone());
    executor.set_base_modules(persisted_modules);
    let modules = executor.modules().clone();
    let module_root = modules
        .read()
        .map(|m| m.state_root())
        .map_err(|_| anyhow::anyhow!("module state lock poisoned"))?;

    // Genesis: apply EVM genesis state once, then persist the resulting block.
    let genesis_block = load_or_create_genesis(
        &context,
        &config.data_dir,
        &genesis,
        module_root,
        &page_cache,
    )
    .await?
    .with_payload(Payload::EpochInfo(epoch_info.clone()));

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
    let probe_artifact = if plan.should_state_sync(false) {
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
    let participants_provider = RegistryParticipants::new();
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
    let reshare_handle = reshare_actor.start(dkg_network);

    // Mempool, RPC plumbing, and the application.
    let mempool = InMemoryMempool::default();
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
    let node_state = NodeState::new(
        chain_id,
        validator_index as u32,
        peers.participants.len() as u32,
    );
    let (heads_tx, _) = ::tokio::sync::broadcast::channel(64);
    let (logs_tx, _) = ::tokio::sync::broadcast::channel(256);
    let (headers_tx, _) = ::tokio::sync::broadcast::channel(64);

    let validator: SharedValidator = Arc::new(OnceLock::new());
    let finalization_marshal = marshal.clone();
    let finalization_lookup: FinalizationLookup = Arc::new(move |height| {
        let marshal = finalization_marshal.clone();
        Box::pin(async move {
            // The stateful finalization callback is normally downstream of the
            // marshal write. A short retry also covers scheduler reordering.
            for _ in 0..100 {
                if let Some(finalization) = marshal.get_finalization(Height::new(height)).await {
                    return Some(FinalizationArtifacts {
                        epoch: finalization.proposal.round.epoch().get(),
                        certificate: finalization.certificate.encode().to_vec(),
                        finalization: finalization.encode().to_vec(),
                    });
                }
                ::tokio::time::sleep(Duration::from_millis(10)).await;
            }
            None
        })
    });
    let sink = NodeSink::new(SinkParts {
        index: block_index.clone(),
        light_index: light_block_index.clone(),
        heads: heads_tx.clone(),
        logs: logs_tx.clone(),
        headers: headers_tx.clone(),
        node_state: node_state.clone(),
        finalization_lookup,
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
    let application = StatefulHubApp::new(
        executor,
        genesis_block,
        mempool.clone(),
        sink.clone(),
        MAX_BLOCK_TXS,
        gas_limit,
    )
    .with_participant_addresses(participant_addresses);
    let vrf_elector = VrfElectorConfig::new(application.vrf_seed_cache());

    let (stateful_actor, stateful_mailbox) = Stateful::init(
        context.child("stateful"),
        StatefulConfig {
            application,
            db_config: state_set_config(PARTITION_PREFIX, page_cache.clone()),
            provider: mempool.clone(),
            marshal: (marshal.clone(), floor),
            mailbox_size: MAILBOX_SIZE,
            plan,
            resolvers: (NoSync::new(), NoSync::new(), NoSync::new()),
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
    let stateful_handle = stateful_actor.start();

    // Transaction gossip and RPC over the live committed state.
    let state_set = stateful_mailbox.subscribe_databases().await;
    let committed_state = CommittedState::new(state_set.clone());
    participants_provider.attach_state(committed_state.clone());
    let _ = validator.set(::tokio::sync::Mutex::new(MempoolValidator::new(
        committed_state.clone(),
        ExecutionConfig::new(chain_id),
        0,
    )));
    sink.attach_state(state_set.clone());
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
        .with_tx_submit(tx_submit)
        .with_subscriptions(heads_tx, logs_tx)
        .with_headers_subscription(headers_tx)
        .with_hub_index_and_modules(block_index, modules)
        .with_hub_module_trees(module_trees)
        .with_hub_light_block_index(light_block_index)
        .start();
    context.child("rpc").spawn(move |_| async move {
        rpc_handle.stopped().await;
        error!("RPC server stopped unexpectedly");
    });
    info!(validator_index, %rpc_addr, "hub validator started");

    Handle::select([
        p2p_handle,
        broadcast_handle,
        probe_handle,
        reshare_handle,
        orchestrator_handle,
        marshal_handle,
        stateful_handle,
    ])
    .await
    .map_err(|e| anyhow::anyhow!("validator actor failed: {e:?}"))
}

fn open_module_trees(data_dir: &Path) -> anyhow::Result<(ModuleTrees, ModuleState)> {
    let mut stores: [InMemoryKvStore; 4] = Default::default();
    let mut trees = Vec::with_capacity(4);
    for (store, name) in stores.iter_mut().zip(MODULE_NAMES) {
        let tree = ModuleStateTree::open(data_dir.join("state").join(name))?;
        *store = InMemoryKvStore::from_pairs(tree.load_all()?);
        trees.push(Arc::new(std::sync::Mutex::new(tree)));
    }
    let trees: ModuleTrees = trees
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected four module trees"))?;
    Ok((trees, ModuleState::from_stores(stores)))
}

/// Apply the genesis state on first boot and persist the genesis block so
/// every later boot starts marshal from the identical block.
async fn load_or_create_genesis(
    context: &tokio::Context,
    data_dir: &Path,
    genesis: &hub_genesis::HubGenesis,
    module_root: alloy_primitives::B256,
    page_cache: &CacheRef,
) -> anyhow::Result<Block> {
    let path = data_dir.join("genesis_block.bin");
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        return Ok(Block::decode_cfg(bytes.as_slice(), &block_cfg())?);
    }
    let set = HubStateSet::init(
        context.child("genesis"),
        state_set_config(PARTITION_PREFIX, page_cache.clone()),
    )
    .await;
    let (state_root, db_targets) = apply_genesis(&set, &genesis.to_genesis_state()?).await?;
    drop(set);
    let block = genesis_block(state_root, db_targets, module_root);
    std::fs::create_dir_all(data_dir)?;
    std::fs::write(&path, block.encode())?;
    Ok(block)
}

const fn block_cfg() -> hub_domain::BlockCfg {
    hub_domain::BlockCfg {
        max_txs: MAX_BLOCK_TXS,
        tx: hub_domain::TxCfg {
            max_tx_bytes: MAX_TX_BYTES,
        },
    }
}

const fn sync_config() -> SyncEngineConfig {
    SyncEngineConfig {
        fetch_batch_size: NZU64!(16),
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
