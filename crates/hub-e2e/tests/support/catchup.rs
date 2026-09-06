//! Shared empty-replica recovery checks for replay and snapshot startup.

use std::{fs, time::Duration};

use commonware_codec::Encode as _;
use hub_client::{
    AccessRequest, Actor, BlsSigner, HubClient, Object, Operation, PERMISSION_LIMITS,
};
use hub_domain::{ConsensusPublicKey, LightBlock, verify_light_block};
use hub_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use serde_json::json;

const POLL: Duration = Duration::from_millis(100);
const DEADLINE: Duration = Duration::from_secs(90);
const READER: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
const POLICY: &[u8] = b"name: replayed
resources:
  - name: file
    relations:
      - name: reader
    permissions:
      - name: read
        expr: reader
";

async fn certified_height(
    client: &HubClient,
    minimum: u64,
    trusted_key: &ConsensusPublicKey,
) -> LightBlock {
    tokio::time::timeout(DEADLINE, async {
        loop {
            let height: String = client
                .rpc_call_typed("eth_blockNumber", json!([]))
                .await
                .unwrap();
            let height = u64::from_str_radix(height.trim_start_matches("0x"), 16).unwrap();
            if height >= minimum {
                let result = client
                    .rpc_call_typed::<LightBlock>(
                        "hub_getLightBlock",
                        json!([format!("0x{height:x}")]),
                    )
                    .await;
                match result {
                    Ok(light) => {
                        verify_light_block(&light, trusted_key).unwrap();
                        assert_eq!(light.height, height);
                        return light;
                    }
                    Err(hub_client::ClientError::Rpc { message, .. })
                        if message.contains("finalization certificate not found") => {}
                    Err(error) => panic!("light block fetch failed: {error}"),
                }
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .expect("certified revision deadline")
}

async fn current_access(
    client: &HubClient,
    policy: &str,
    request: &AccessRequest,
    minimum: u64,
    trusted_key: &ConsensusPublicKey,
) -> (LightBlock, bool) {
    certified_height(client, minimum, trusted_key).await;
    client
        .verify_current_access(policy, request, minimum, trusted_key, PERMISSION_LIMITS)
        .await
        .unwrap()
}

pub(super) async fn recover_replica(snapshot: bool, interrupt: bool) {
    let deployment = 9041;
    let keys = KeySet::builder().seed(deployment).build().unwrap();
    let trusted_key = *keys.epoch_info().output.public().public();
    let mut cluster = TestCluster::builder()
        .binary(hub_e2e::resolve_binary().unwrap())
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .genesis(GenesisBuilder::devnet().blocks_per_epoch(20))
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();

    cluster.kill_node(3);
    let directory = cluster.node(3).data_dir.clone();
    let archived = directory.with_file_name("node3-before-replay");
    fs::rename(&directory, &archived).unwrap();
    fs::create_dir(&directory).unwrap();
    fs::rename(archived.join("logs"), directory.join("logs")).unwrap();
    for filename in ["config.toml", "genesis.json", "validator.key"] {
        fs::copy(archived.join(filename), directory.join(filename)).unwrap();
    }
    fs::write(
        directory.join("secrets.json"),
        serde_json::to_vec(&json!({
            "shares": {"0": hex::encode(keys.share(3).unwrap().encode())},
            "seeds": {},
            "dealings": {},
        }))
        .unwrap(),
    )
    .unwrap();

    if snapshot {
        let path = directory.join("config.toml");
        let mut config = fs::read_to_string(&path).unwrap();
        config.push_str("\n[snapshot]\n");
        fs::write(path, config).unwrap();
    }

    let origin = HubClient::new(cluster.node(0).rpc_url());
    tokio::time::timeout(DEADLINE, async {
        while origin.chain_id().await.is_err() {
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .expect("origin startup deadline");
    let signer = BlsSigner::new(7u64.into(), deployment).unwrap();
    let mut receipts = vec![
        origin
            .native_create_policy(&signer, POLICY, 1)
            .await
            .unwrap(),
    ];
    let policies = origin.get_policy_ids().await.unwrap();
    assert_eq!(policies.len(), 1);
    let policy = policies[0].parse().unwrap();
    receipts.push(
        origin
            .native_register_object(&signer, policy, "doc", "file")
            .await
            .unwrap(),
    );
    receipts.push(
        origin
            .native_set_relationship(&signer, policy, "file", "doc", "reader", READER)
            .await
            .unwrap(),
    );
    let request = AccessRequest {
        actor: Actor(READER.parse().unwrap()),
        operations: vec![Operation {
            object: Object {
                resource: "file".into(),
                id: "doc".into(),
            },
            permission: "read".into(),
        }],
    };
    let (_, allowed) = current_access(
        &origin,
        &policies[0],
        &request,
        receipts.last().unwrap().block_number,
        &trusted_key,
    )
    .await;
    assert!(allowed);
    receipts.push(
        origin
            .native_delete_relationship(&signer, policy, "file", "doc", "reader", READER)
            .await
            .unwrap(),
    );
    assert!(receipts.iter().all(|receipt| receipt.status == 1));
    let (target, allowed) = current_access(
        &origin,
        &policies[0],
        &request,
        42.max(receipts.last().unwrap().block_number),
        &trusted_key,
    )
    .await;
    assert!(target.epoch >= 2);
    assert!(!allowed);
    eprintln!("cold replica starts at origin height {}", target.height);

    let crash_marker = directory.join("snapshot-import-crash");
    if interrupt {
        fs::write(&crash_marker, []).unwrap();
    }
    cluster.restart_node(3).unwrap();
    if interrupt {
        tokio::time::timeout(DEADLINE, async {
            while cluster.node_mut(3).process.is_running() {
                tokio::time::sleep(POLL).await;
            }
        })
        .await
        .expect("snapshot import crash deadline");
        assert!(
            !crash_marker.exists(),
            "crash must occur after a durable history record"
        );
        assert!(
            HubClient::new(cluster.node(3).rpc_url())
                .chain_id()
                .await
                .is_err()
        );
        let path = directory.join("config.toml");
        let config = fs::read_to_string(&path).unwrap();
        fs::write(path, config.replace("\n[snapshot]\n", "\n")).unwrap();
        cluster.restart_node(3).unwrap();
    }
    cluster.wait_ready(DEADLINE).await.unwrap();
    let replica = HubClient::new(cluster.node(3).rpc_url());
    for receipt in receipts {
        let replayed = tokio::time::timeout(
            DEADLINE,
            replica.wait_for_receipt(receipt.transaction_hash, POLL, 900),
        )
        .await
        .expect("cold replay deadline")
        .unwrap();
        assert_eq!(
            serde_json::to_value(replayed).unwrap(),
            serde_json::to_value(receipt).unwrap()
        );
    }
    let (caught_up, allowed) = current_access(
        &replica,
        &policies[0],
        &request,
        target.height,
        &trusted_key,
    )
    .await;
    assert!(!allowed);
    let restored: LightBlock = replica
        .rpc_call_typed(
            "hub_getLightBlock",
            json!([format!("0x{:x}", target.height)]),
        )
        .await
        .unwrap();
    verify_light_block(&restored, &trusted_key).unwrap();
    assert_eq!(restored, target);
    assert_eq!(replica.get_policy_ids().await.unwrap(), policies);
    assert_eq!(replica.get_native_nonce(signer.did()).await.unwrap(), 4);
    if snapshot {
        let status: serde_json::Value = replica
            .rpc_call_typed("hub_nodeStatus", json!([]))
            .await
            .unwrap();
        let snapshot_revision = status["snapshotRevision"]
            .as_u64()
            .expect("snapshot handoff must run");
        assert!(snapshot_revision > 0);
        cluster.kill_node(3);
        cluster.restart_node(3).unwrap();
        cluster.wait_ready(DEADLINE).await.unwrap();
        assert_eq!(replica.get_native_nonce(signer.did()).await.unwrap(), 4);
        let (_, allowed) = current_access(
            &replica,
            &policies[0],
            &request,
            target.height,
            &trusted_key,
        )
        .await;
        assert!(!allowed);
        let status: serde_json::Value = replica
            .rpc_call_typed("hub_nodeStatus", json!([]))
            .await
            .unwrap();
        assert!(status["snapshotRevision"].as_u64().unwrap() >= snapshot_revision);
    }
    // Allow a complete resharing ceremony after replay, then require this
    // replica's vote: only three of the four participants remain online.
    let ready = certified_height(&replica, (caught_up.epoch + 2) * 20 + 2, &trusted_key).await;
    cluster.kill_node(2);

    let subsequent = replica
        .native_create_policy(
            &signer,
            b"name: after-replay\nresources:\n  - name: file\n",
            1,
        )
        .await
        .unwrap();
    assert_eq!(subsequent.status, 1);
    origin
        .wait_for_receipt(subsequent.transaction_hash, POLL, 900)
        .await
        .unwrap();
    assert_eq!(origin.get_native_nonce(signer.did()).await.unwrap(), 5);
    let (active, allowed) = current_access(
        &replica,
        &policies[0],
        &request,
        (ready.epoch + 1) * 20 + 2,
        &trusted_key,
    )
    .await;
    assert!(active.height >= subsequent.block_number);
    assert!(!allowed);
    eprintln!(
        "recovered replica required for quorum through height {}",
        active.height
    );
}
