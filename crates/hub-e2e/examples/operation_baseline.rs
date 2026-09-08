//! Four-node certified registration workload; see docs/native-workload.md for arguments.
//! Build hubd in release mode and set HUBD_BINARY to that binary before running.

#[path = "operation_baseline/driver.rs"]
mod driver;
#[path = "operation_baseline/resources.rs"]
mod resources;

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::FixedBytes;
use alloy_sol_types::SolCall;
use hub_client::{ACP_ADDRESS, BlsSigner, HubClient};
use hub_domain::NativeTx;
use hub_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use hub_modules::acp::abi::IAcp;
use tokio::{sync::Semaphore, task::JoinSet, time::Instant};

const CHAIN_ID: u64 = 9001;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert!(
        args.len() <= 7,
        "usage: operation_baseline [count] [arrivals/sec] [max outstanding] [permission reads 0/1] [fast|normal|stress] [RPC connections] [epoch revisions]"
    );
    let parse = |index: usize, default: usize| {
        args.get(index).map_or(default, |value| {
            value.parse::<usize>().expect("positive integer")
        })
    };
    let count = parse(0, 200);
    let rate = parse(1, 20);
    let outstanding = parse(2, 128);
    let permission_reads = parse(3, 1);
    assert!(permission_reads <= 1);
    let preset = match args.get(4).map(String::as_str).unwrap_or("normal") {
        "fast" => ConsensusPreset::Fast,
        "normal" => ConsensusPreset::Normal,
        "stress" => ConsensusPreset::Stress,
        _ => panic!("timing preset must be fast, normal or stress"),
    };
    let rpc_connections = u32::try_from(parse(5, 100))
        .ok()
        .and_then(std::num::NonZeroU32::new)
        .expect("positive RPC connection limit within u32");
    let epoch_length = u64::try_from(parse(6, 20))
        .ok()
        .and_then(std::num::NonZeroU64::new)
        .expect("positive epoch length within u64");
    assert!(
        hub_domain::max_epoch_participants(epoch_length) >= 4,
        "epoch is too short for four participants"
    );
    let timing = preset.params();
    let keys = KeySet::builder().seed(42).build().unwrap();
    let trusted = *keys.epoch_info().output.public().public();
    assert!((1..=10_000).contains(&count) && (1..=10_000).contains(&rate));
    assert!((1..=1024).contains(&outstanding));

    let mut cluster = TestCluster::builder()
        .nodes(4)
        .genesis(GenesisBuilder::devnet().blocks_per_epoch(epoch_length.get()))
        .seed(42)
        .chain_id(CHAIN_ID)
        .preset(preset)
        .rpc_max_connections(rpc_connections)
        .build()
        .await
        .expect("start cluster");
    cluster
        .wait_ready(Duration::from_secs(30))
        .await
        .expect("ready cluster");
    let client = Arc::new(HubClient::new(cluster.node(0).rpc_url()));
    let setup = BlsSigner::new(((count + 1) as u64).into(), CHAIN_ID).unwrap();
    let raw = setup
        .sign_native_tx(
            ACP_ADDRESS,
            IAcp::createPolicyCall {
                policy: b"name: baseline\nresources:\n  - name: file\n    permissions:\n      - name: read\n        expr: owner\n"
                    .to_vec()
                    .into(),
                marshalType: 1,
            }
            .abi_encode()
            .into(),
        )
        .unwrap();
    let setup_receipt = tokio::time::timeout(Duration::from_secs(30), async {
        let hash = client.send_native_tx(&raw).await.unwrap();
        client
            .wait_for_receipt(hash, driver::POLL_INTERVAL, 600)
            .await
            .unwrap()
    })
    .await
    .expect("policy creation timed out");
    assert_eq!(setup_receipt.status, 1);
    let ids = client.get_policy_ids().await.unwrap();
    assert_eq!(ids.len(), 1);
    let policy_id = FixedBytes::<32>::from_slice(&hex::decode(&ids[0]).unwrap());

    let reads = Arc::new(driver::ReadContext {
        trusted,
        policy: ids[0].clone(),
        permissions: permission_reads == 1,
    });

    let signing_start = Instant::now();
    let requests: Vec<_> = (0..count)
        .map(|index| {
            let signer = BlsSigner::new(((index + 1) as u64).into(), CHAIN_ID).unwrap();
            let raw = signer
                .sign_native_tx(
                    ACP_ADDRESS,
                    IAcp::registerObjectCall {
                        policyId: policy_id,
                        resource: "file".into(),
                        objectId: index.to_string(),
                    }
                    .abi_encode()
                    .into(),
                )
                .unwrap();
            driver::Request {
                index,
                hash: NativeTx::decode_wire(&raw).unwrap().tx_id().0,
                owner: signer.did().to_string(),
                raw,
            }
        })
        .collect();
    println!(
        "{}",
        serde_json::json!({
            "kind": "configuration", "workload": "certified_native_registrations",
            "format_version": 2, "permission_reads_per_write": permission_reads,
            "runner_debug_assertions": cfg!(debug_assertions),
            "revisions_per_epoch": epoch_length.get(),
            "max_operations_per_revision": hub_domain::MAX_BLOCK_TXS,
            "max_encoded_operation_bytes_per_revision": hub_domain::MAX_BLOCK_TX_BYTES,
            "max_encoded_revision_bytes": hub_domain::MAX_BLOCK_BYTES,
            "rpc_max_connections": rpc_connections.get(), "nodes": 4, "preset": format!("{preset:?}"),
            "leader_timeout_ms": timing.leader_timeout.as_millis(),
            "notarization_timeout_ms": timing.notarization_timeout.as_millis(),
            "nullify_retry_ms": timing.nullify_retry.as_millis(), "count": count, "arrivals_per_second": rate,
            "max_outstanding": outstanding, "receipt_poll_ms": driver::POLL_INTERVAL.as_millis(),
            "request_timeout_ms": driver::REQUEST_TIMEOUT.as_millis(),
            "signing_seconds": signing_start.elapsed().as_secs_f64(),
            "signed_bytes": requests.iter().map(|r| r.raw.len()).sum::<usize>(),
            "node_data_dirs": (0..4).map(|i| cluster.node(i).data_dir.display().to_string()).collect::<Vec<_>>(),
        })
    );

    resources::storage(&cluster, "before").await;
    let (stop_resources, resource_task) = resources::start(&cluster);
    let limit = Arc::new(Semaphore::new(outstanding));
    let mut tasks = JoinSet::new();
    let started = Instant::now();
    for request in requests {
        let scheduled = started + Duration::from_secs_f64(request.index as f64 / rate as f64);
        tokio::time::sleep_until(scheduled).await;
        let permit = limit.clone().try_acquire_owned().ok();
        tasks.spawn(driver::observe(
            client.clone(),
            request,
            scheduled,
            permit,
            reads.clone(),
        ));
    }
    let mut observations = Vec::with_capacity(count);
    while let Some(result) = tasks.join_next().await {
        observations.push(result.expect("request task panicked"));
    }
    let elapsed = started.elapsed();
    let _ = stop_resources.send(());
    resource_task.await.expect("resource sampler task");
    resources::storage(&cluster, "after").await;
    observations.sort_unstable_by_key(|o| o.request.index);
    for observation in &observations {
        println!("{}", observation.json());
    }
    println!("{}", driver::summary(&observations, elapsed));

    let replica_clients: Vec<_> = (0..cluster.node_count())
        .map(|i| HubClient::new(cluster.node(i).rpc_url()))
        .collect();
    let mut reconciled = 0;
    let mut unresolved = 0;
    for observation in &observations {
        match driver::verify(&replica_clients, policy_id, observation).await {
            driver::Resolution::Verified => reconciled += 1,
            driver::Resolution::Unresolved => unresolved += 1,
        }
    }
    println!(
        "{}",
        serde_json::json!({
            "kind": "verification", "replicas": 4, "verified": reconciled, "unresolved": unresolved,
        })
    );
    cluster
        .wait_ready(Duration::from_secs(10))
        .await
        .expect("cluster health after workload");
    assert_eq!(
        unresolved, 0,
        "unresolved outcomes prevent a complete baseline"
    );

    cluster.kill_node(3);
    let probe = setup
        .sign_native_tx(
            ACP_ADDRESS,
            IAcp::registerObjectCall {
                policyId: policy_id,
                resource: "file".into(),
                objectId: "recovery-probe".into(),
            }
            .abi_encode()
            .into(),
        )
        .unwrap();
    let probe_receipt = tokio::time::timeout(driver::REQUEST_TIMEOUT, async {
        let hash = client.send_native_tx(&probe).await.unwrap();
        client
            .wait_for_receipt(hash, driver::POLL_INTERVAL, 600)
            .await
            .unwrap()
    })
    .await
    .expect("three-node write timed out");
    assert_eq!(probe_receipt.status, 1);
    let restart = Instant::now();
    cluster.restart_node(3).expect("restart replica");
    cluster
        .wait_ready(driver::REQUEST_TIMEOUT)
        .await
        .expect("restarted RPC ready");
    let rpc_ready_ms = restart.elapsed().as_secs_f64() * 1000.0;
    let recovered = HubClient::new(cluster.node(3).rpc_url());
    let recovered_receipt = tokio::time::timeout(
        driver::REQUEST_TIMEOUT,
        recovered.wait_for_receipt(probe_receipt.transaction_hash, driver::POLL_INTERVAL, 600),
    )
    .await
    .expect("recovery deadline")
    .expect("recover probe receipt");
    assert_eq!(recovered_receipt.block_hash, probe_receipt.block_hash);
    assert_eq!(recovered_receipt.status, 1);
    let (registered, owner) = recovered
        .get_object_owner(policy_id, "file", "recovery-probe")
        .await
        .unwrap();
    assert!(registered);
    let owner: serde_json::Value = serde_json::from_slice(&owner).unwrap();
    assert_eq!(owner["metadata"]["owner_did"], setup.did());
    let recovery_ms = restart.elapsed().as_secs_f64() * 1000.0;
    let mut receipt_mismatches = 0;
    let mut state_mismatches = 0;
    for observation in &observations {
        let (receipt_matches, state_matches) =
            driver::check_recovered(&client, &recovered, policy_id, observation).await;
        receipt_mismatches += usize::from(!receipt_matches);
        state_mismatches += usize::from(!state_matches);
    }
    println!(
        "{}",
        serde_json::json!({
            "kind": "recovery", "rpc_ready_ms": rpc_ready_ms,
            "restart_to_probe_observed_ms": recovery_ms, "inspected_operations": count,
            "receipt_mismatches": receipt_mismatches, "state_mismatches": state_mismatches,
            "probe_height": probe_receipt.block_number,
        })
    );
    assert_eq!(
        state_mismatches, 0,
        "restarted replica lost application state"
    );
    assert_eq!(
        receipt_mismatches, 0,
        "restarted replica lost receipt history"
    );
    driver::assert_no_verification_failures(&observations);
}
