//! Crash after each module-store commit and recover the durable consensus prefix.
//! Requires hubd built with --features fault-injection.

use std::{collections::BTreeSet, time::Duration};

use alloy_sol_types::SolCall;
use hub_client::{ACP_ADDRESS, BlsSigner, HubClient, TransactionReceipt};
use hub_e2e::cluster::{ConsensusPreset, TestCluster};
use hub_modules::acp::abi::IAcp;

const POLL: Duration = Duration::from_millis(50);
const DEADLINE: Duration = Duration::from_secs(30);

async fn create_policy(client: &HubClient, signer: &BlsSigner, name: &str) -> TransactionReceipt {
    let raw = signer
        .sign_native_tx(
            ACP_ADDRESS,
            IAcp::createPolicyCall {
                policy: format!("name: {name}\nresources:\n  - name: file\n")
                    .into_bytes()
                    .into(),
                marshalType: 1,
            }
            .abi_encode()
            .into(),
        )
        .unwrap();
    tokio::time::timeout(DEADLINE, async {
        let hash = client.send_native_tx(&raw).await.unwrap();
        let receipt = client.wait_for_receipt(hash, POLL, 600).await.unwrap();
        assert_eq!(receipt.status, 1);
        receipt
    })
    .await
    .expect("policy confirmation deadline")
}

async fn assert_replicas(cluster: &TestCluster, signer: &BlsSigner, receipt: &TransactionReceipt) {
    tokio::time::timeout(DEADLINE, async {
        let origin = HubClient::new(cluster.node(0).rpc_url());
        origin
            .wait_for_receipt(receipt.transaction_hash, POLL, 600)
            .await
            .unwrap();
        let expected: BTreeSet<_> = origin.get_policy_ids().await.unwrap().into_iter().collect();
        for index in 0..4 {
            let client = HubClient::new(cluster.node(index).rpc_url());
            let actual = client
                .wait_for_receipt(receipt.transaction_hash, POLL, 600)
                .await
                .unwrap();
            assert_eq!(actual.block_hash, receipt.block_hash);
            assert_eq!(actual.status, 1);
            assert_eq!(
                client.get_native_nonce(signer.did()).await.unwrap(),
                signer.nonce()
            );
            let policies: BTreeSet<_> =
                client.get_policy_ids().await.unwrap().into_iter().collect();
            assert_eq!(policies, expected, "replica {index} policy state differs");
            assert_eq!(policies.len(), signer.nonce() as usize);
        }
    })
    .await
    .expect("replica convergence deadline");
}

#[tokio::test]
async fn recover_after_each_module_commit() {
    let mut cluster = TestCluster::builder()
        .nodes(4)
        .chain_id(9001)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster.wait_ready(DEADLINE).await.unwrap();
    let origin = HubClient::new(cluster.node(0).rpc_url());
    let signer = BlsSigner::new(7u64.into(), 9001).unwrap();
    let baseline = create_policy(&origin, &signer, "baseline").await;
    assert_replicas(&cluster, &signer, &baseline).await;
    let marker = cluster.node(3).data_dir.join("module-commit-crash");
    let witness = marker.with_extension("hit");

    for store in 0..4 {
        if witness.exists() {
            std::fs::remove_file(&witness).unwrap();
        }
        std::fs::write(&marker, store.to_string()).unwrap();
        let receipt = create_policy(&origin, &signer, &format!("crash-{store}")).await;
        tokio::time::timeout(DEADLINE, async {
            while !witness.exists() {
                tokio::time::sleep(POLL).await;
            }
        })
        .await
        .expect("crash point did not fire; build hubd with fault-injection");
        let observed: Vec<u64> = std::fs::read_to_string(&witness)
            .unwrap()
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(observed, vec![receipt.block_number, store]);
        assert!(
            !marker.exists(),
            "crash marker must be consumed before restart"
        );
        cluster.kill_node(3);
        cluster.restart_node(3).unwrap();
        cluster.wait_ready(DEADLINE).await.unwrap();
        assert_replicas(&cluster, &signer, &receipt).await;

        let recovered = HubClient::new(cluster.node(3).rpc_url());
        let probe = create_policy(&recovered, &signer, &format!("after-crash-{store}")).await;
        assert_replicas(&cluster, &signer, &probe).await;
        eprintln!(
            "recovered after module store {store} at height {}",
            receipt.block_number
        );
    }
}
