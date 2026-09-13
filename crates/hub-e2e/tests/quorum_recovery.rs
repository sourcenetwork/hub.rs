//! A write admitted by a minority completes only after quorum recovers.

use std::time::Duration;

use alloy_sol_types::SolCall;
use hub_client::{BULLETIN_ADDRESS, BlsSigner, HubClient};
use hub_e2e::cluster::{ConsensusPreset, KeySet, TestCluster};
use hub_modules::bulletin::abi::IBulletin;

#[tokio::test]
async fn minority_write_waits_for_quorum_and_survives_replica_recovery() {
    let deployment = 9081;
    let trusted = *KeySet::builder()
        .seed(deployment)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let mut cluster = TestCluster::builder()
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(hub_e2e::readiness_deadline())
        .await
        .unwrap();
    cluster
        .observe(Duration::from_millis(100))
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let clients: Vec<_> = (0..4)
        .map(|i| HubClient::new(cluster.node(i).rpc_url()))
        .collect();
    cluster.kill_node(2);
    cluster.kill_node(3);

    let signer = BlsSigner::new(7u64.into(), deployment).unwrap();
    let wire = signer
        .sign_native_tx(
            BULLETIN_ADDRESS,
            IBulletin::registerNamespaceCall {
                namespace: "quorum/recovery".into(),
            }
            .abi_encode()
            .into(),
        )
        .unwrap();
    let id = clients[0].send_native_tx(&wire).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        for client in &clients[..2] {
            assert!(client.read_receipt(id, &trusted).await.unwrap().is_none());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    cluster.restart_node(2).unwrap();
    let revision = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(proof) = clients[0].read_receipt(id, &trusted).await.unwrap() {
                assert!(proof.verify(id, &trusted).unwrap().success());
                break proof.revision.height;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the surviving replicas must retain and finalize the admitted write");

    cluster.restart_node(3).unwrap();
    cluster
        .wait_ready(hub_e2e::readiness_deadline())
        .await
        .unwrap();
    for client in &clients {
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if let Some(proof) = client.read_receipt(id, &trusted).await.unwrap() {
                    assert!(proof.verify(id, &trusted).unwrap().success());
                    assert_eq!(proof.revision.height, revision);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the recovered replica must serve the same certified outcome");
        let namespaces = client
            .list_bulletin_namespaces(None, 2, revision, &trusted)
            .await
            .unwrap();
        assert!(namespaces.continuation.is_none());
        assert_eq!(namespaces.records.len(), 1);
        let namespace = &namespaces.records[0];
        assert_eq!(namespace.id, "bulletin/quorum/recovery");
        assert_eq!(namespace.owner_did, signer.did());
        assert_eq!(namespace.created_at.block_height, revision);
    }
}
