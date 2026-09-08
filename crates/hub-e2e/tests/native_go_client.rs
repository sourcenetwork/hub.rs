//! Cross-language signing and proof verification against a native cluster.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_sol_types::SolCall as _;
use commonware_codec::Encode as _;
use hub_client::{
    ACP_ADDRESS, BlsSigner, DelegationScope, HUB_ADDRESS, HubClient,
    administration::{AdministrativeCommand, SignedAdministrativeRequest},
};
use hub_domain::{ConsensusPublicKey, NativeTx};
use hub_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use hub_modules::{
    acp::{delegated_operation::DelegatedOperation, types::PolicyMarshalingType},
    hub::{abi::IHub, relay::RelayGrant},
};
use k256::ecdsa::SigningKey;

#[path = "support/administration.rs"]
mod administration_support;

#[tokio::test]
#[ignore = "requires TRUST_NATIVE_TEST_BINARY built with vera_native and its shared library"]
async fn native_go_workers_verify_policy_creation() {
    let binary = std::env::var("TRUST_NATIVE_TEST_BINARY").expect("Go native test binary required");
    let deployment = 9063;
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
        .genesis(GenesisBuilder::devnet().operators(administration_support::operators()))
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster.wait_ready(Duration::from_secs(30)).await.unwrap();
    let client = HubClient::new(cluster.node(0).rpc_url());
    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    let issuer = hub_crypto::secp256k1::did_from_secp256k1_pubkey(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let approved = administration_support::approve(
        &client,
        AdministrativeCommand::SetRelay(RelayGrant {
            issuer: issuer.clone(),
            scopes: vec![DelegationScope::CreatePolicy],
            expires_at: now + 600,
        }),
        0,
    )
    .await;
    let operator = BlsSigner::new(9u64.into(), deployment).unwrap();
    apply(&client, &client, &trusted, &operator, &approved).await;

    let signer = BlsSigner::new(7u64.into(), deployment).unwrap();
    let vector = signer
        .sign_native_tx_with_sequence(ACP_ADDRESS, vec![1, 2, 3].into(), 0)
        .unwrap();
    let definition = "name: shared\nresources:\n  - name: document\n";
    let unicode = "<>&\u{2028}\u{2029}\\u2028\\u2029\n\t\"\\";
    let vectors: Vec<_> = [definition, unicode]
        .into_iter()
        .map(|value| {
            serde_json::json!({
                "definition": value,
                "operation": hex::encode(DelegatedOperation::CreatePolicy(
                    value, &PolicyMarshalingType::ShortYaml,
                ).digest().unwrap()),
            })
        })
        .collect();
    let mut fixture = serde_json::json!({
        "endpoint": cluster.node(0).rpc_url(),
        "trusted_key": hex::encode(trusted.encode()),
        "deployment": deployment,
        "genesis": hex::encode(approved.request.genesis_id),
        "issuer": issuer.clone(),
        "wire": hex::encode(&vector),
        "submission": NativeTx::decode_wire(&vector).unwrap().tx_id().0,
        "worker": signer.did(),
        "vectors": vectors,
    });
    run_client(&binary, &fixture).await;
    let revoked =
        administration_support::approve(&client, AdministrativeCommand::RevokeRelay(issuer), 1)
            .await;
    let replica = HubClient::new(cluster.node(3).rpc_url());
    apply(&client, &replica, &trusted, &operator, &revoked).await;
    cluster.restart_node(3).unwrap();
    cluster.wait_ready(Duration::from_secs(30)).await.unwrap();
    fixture["endpoint"] = serde_json::json!(cluster.node(3).rpc_url());
    fixture["revoked"] = serde_json::json!(true);
    run_client(&binary, &fixture).await;
}

async fn apply(
    client: &HubClient,
    observer: &HubClient,
    trusted: &ConsensusPublicKey,
    operator: &BlsSigner,
    approved: &SignedAdministrativeRequest,
) {
    let wire = operator
        .sign_native_tx(
            HUB_ADDRESS,
            IHub::applyAdministrationCall {
                request: serde_json::to_vec(approved).unwrap().into(),
            }
            .abi_encode()
            .into(),
        )
        .unwrap();
    let submission = client.send_native_tx(&wire).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(proof) = observer.read_receipt(submission, trusted).await.unwrap() {
                assert!(proof.verify(submission, trusted).unwrap().success());
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}

async fn run_client(binary: &str, fixture: &serde_json::Value) {
    let mut command = tokio::process::Command::new(binary);
    command
        .args([
            "-test.run=^TestNativeCluster$",
            "-test.v",
            "-test.timeout=60s",
        ])
        .env("VERA_NATIVE_FIXTURE", fixture.to_string())
        .kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(65), command.status())
        .await
        .expect("Go client must finish within its deadline")
        .expect("launch Go native client test");
    assert!(status.success(), "Go native client failed: {status}");
}
