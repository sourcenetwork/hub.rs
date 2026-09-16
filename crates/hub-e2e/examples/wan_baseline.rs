//! Sustained-load driver against a deployed (remote) validator network.
//!
//! Drives the same certified-registration workflow as `operation_baseline`
//! (submit native tx, wait for the certified receipt, optionally verify
//! current permission evidence) but targets RPC endpoints of an existing
//! deployment instead of a locally managed cluster. Used for the wide-area
//! release gates: run it from one region against another region's RPC.

use std::{sync::Arc, time::Duration};

use alloy_primitives::FixedBytes;
use alloy_sol_types::SolCall;
use futures::{StreamExt as _, stream};
use hub_client::{ACP_ADDRESS, BlsSigner, HubClient};
use hub_domain::NativeTx;
use hub_modules::acp::abi::IAcp;
use tokio::{sync::Semaphore, task::JoinSet, time::Instant};

// The workload driver is shared with operation_baseline, which also uses the
// update-workflow and recovery helpers this gate does not drive.
#[path = "operation_baseline/driver.rs"]
#[allow(dead_code)]
mod driver;

const DEFAULT_CHAIN_ID: u64 = 9001;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert!(
        args.len() >= 2 && args.len() <= 8,
        "usage: wan_baseline <rpc url> <genesis.json | trusted group key hex> [count] [arrivals/sec] [max outstanding] [permission reads 0/1] [chain id] [extra rpc urls comma-separated]"
    );
    let parse = |index: usize, default: usize| {
        args.get(index).map_or(default, |value| {
            value.parse::<usize>().expect("positive integer")
        })
    };
    let count = parse(2, 5_000).clamp(1, 100_000);
    let rate = parse(3, 20).clamp(1, 10_000);
    let outstanding = parse(4, 128).clamp(1, 1024);
    let permission_reads = parse(5, 1);
    assert!(permission_reads <= 1);
    let chain_id = parse(6, DEFAULT_CHAIN_ID as usize) as u64;
    let trusted: hub_domain::ConsensusPublicKey = std::fs::read(&args[1]).map_or_else(
        |_| {
            let bytes = hex::decode(args[1].trim_start_matches("0x")).expect("trusted key hex");
            bytes
                .as_slice()
                .try_into()
                .expect("trusted group key bytes")
        },
        |bytes| {
            let genesis: hub_genesis::HubGenesis =
                serde_json::from_slice(&bytes).expect("parse genesis.json");
            *genesis
                .decode_epoch_info()
                .expect("decode epoch info")
                .expect("genesis carries epoch info")
                .output
                .public()
                .public()
        },
    );
    let extra = args
        .get(7)
        .map(|list| list.split(',').map(str::to_string).collect::<Vec<_>>())
        .unwrap_or_default();

    let client = Arc::new(HubClient::new(&args[0]));
    let setup = BlsSigner::new(1u64.into(), chain_id).unwrap();
    let raw = setup
        .sign_native_tx(
            ACP_ADDRESS,
            IAcp::createPolicyCall {
                policy: b"name: wan\nresources:\n  - name: file\n    permissions:\n      - name: read\n        expr: owner\n"
                    .to_vec()
                    .into(),
                marshalType: 1,
            }
            .abi_encode()
            .into(),
        )
        .unwrap();
    let setup_started = Instant::now();
    let hash = client
        .send_native_tx(&raw)
        .await
        .expect("submit setup policy");
    client
        .wait_for_receipt(hash, driver::POLL_INTERVAL, 600)
        .await
        .expect("setup policy receipt");
    let ids = client.get_policy_ids().await.expect("policy ids");
    assert_eq!(ids.len(), 1, "network must accept the setup policy");
    let policy_id = FixedBytes::<32>::from_slice(&hex::decode(&ids[0]).unwrap());

    let reads = Arc::new(driver::ReadContext {
        trusted,
        policy: ids[0].clone(),
        permissions: permission_reads == 1,
    });
    let requests: Vec<_> = (0..count)
        .map(|index| {
            let signer = BlsSigner::new(((index + 2) as u64).into(), chain_id).unwrap();
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
                object_id: index.to_string(),
                expected_access: true,
                final_registered: None,
                hash: NativeTx::decode_wire(&raw).unwrap().tx_id().0,
                owner: signer.did().to_string(),
                raw,
            }
        })
        .collect();
    println!(
        "{}",
        serde_json::json!({
            "kind": "configuration",
            "workload": "wan_certified_native_registrations",
            "format_version": 1,
            "rpc": args[0],
            "extra_rpcs": extra,
            "count": count,
            "arrivals_per_second": rate,
            "max_outstanding": outstanding,
            "permission_reads_per_write": permission_reads,
            "chain_id": chain_id,
            "setup_policy_ms": setup_started.elapsed().as_millis(),
            "max_operations_per_revision": hub_domain::MAX_BLOCK_TXS,
        })
    );

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
    observations.sort_unstable_by_key(|observation| observation.request.index);
    for observation in &observations {
        println!("{}", observation.json());
    }
    println!("{}", driver::summary(&observations, elapsed));

    if !extra.is_empty() {
        let replicas: Vec<_> = extra
            .iter()
            .map(HubClient::new)
            .chain([HubClient::new(&args[0])])
            .collect();
        let mut checks = stream::iter(observations.iter())
            .map(|observation| driver::verify(&replicas, policy_id, observation))
            .buffer_unordered(8);
        let mut verified = 0;
        let mut unresolved = 0;
        while let Some(resolution) = checks.next().await {
            match resolution {
                driver::Resolution::Verified => verified += 1,
                driver::Resolution::Unresolved => unresolved += 1,
            }
        }
        println!(
            "{}",
            serde_json::json!({
                "kind": "verification",
                "replicas": replicas.len(),
                "verified": verified,
                "unresolved": unresolved,
            })
        );
    }
}
