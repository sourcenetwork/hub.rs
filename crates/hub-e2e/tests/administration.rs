//! Operator quorum, transport independence and rotation recovery.

#[path = "support/administration.rs"]
mod support;

use std::time::Duration;

use hub_client::{
    BlsSigner, ClientError, EvmSigner, HubClient,
    administration::{AdministrativeCommand, OperatorPolicy, approve_administration},
};
use hub_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use hub_modules::acp::types::AcpParams;
use k256::ecdsa::SigningKey;

#[tokio::test]
async fn operator_rotation_and_sequence_survive_replica_restart() {
    let trusted = *KeySet::builder()
        .seed(9099)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let mut cluster = TestCluster::builder()
        .nodes(4)
        .seed(9099)
        .genesis(GenesisBuilder::devnet().operators(support::operators()))
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster.wait_ready(Duration::from_secs(30)).await.unwrap();
    let client = HubClient::new(cluster.node(0).rpc_url());
    let submitter = BlsSigner::new(42u64.into(), 9001).unwrap();
    let parameters = AcpParams {
        policy_command_max_expiration_delta: 3600,
        ..Default::default()
    };
    let approved = support::approve(
        &client,
        AdministrativeCommand::SetAcpParameters(parameters.clone()),
        0,
    )
    .await;
    let mut insufficient = approved.clone();
    insufficient.approvals.pop();
    assert!(matches!(
        client
            .native_apply_administration(&submitter, &insufficient)
            .await,
        Err(ClientError::TxReverted { .. })
    ));
    assert_eq!(
        client
            .read_administration(0, &trusted)
            .await
            .unwrap()
            .value
            .unwrap()
            .sequence,
        0
    );
    client
        .native_apply_administration(&submitter, &approved)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<AcpParams>(&client.get_acp_params().await.unwrap()).unwrap(),
        parameters
    );

    let next = SigningKey::from_bytes(&[3; 32].into()).unwrap();
    let next_policy = OperatorPolicy {
        threshold: 1,
        keys: vec![hex::encode(next.verifying_key().to_sec1_bytes())],
    };
    let rotation = support::approve(
        &client,
        AdministrativeCommand::RotateOperators(next_policy.clone()),
        1,
    )
    .await;
    let evm_submitter = EvmSigner::from_hex(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        9001,
    )
    .unwrap();
    let receipt = client
        .apply_administration(&evm_submitter, &rotation)
        .await
        .unwrap();
    let replica = HubClient::new(cluster.node(3).rpc_url());
    replica
        .wait_for_receipt(receipt.transaction_hash, Duration::from_millis(50), 600)
        .await
        .unwrap();
    cluster.restart_node(3).unwrap();
    cluster.wait_ready(Duration::from_secs(30)).await.unwrap();
    let restored = replica
        .read_administration(receipt.block_number, &trusted)
        .await
        .unwrap()
        .value
        .unwrap();
    assert_eq!(restored.sequence, 2);
    assert_eq!(restored.policy, next_policy);
    assert!(matches!(
        replica
            .native_apply_administration(&submitter, &approved)
            .await,
        Err(ClientError::TxReverted { .. })
    ));

    let mut change = support::approve(
        &client,
        AdministrativeCommand::SetAcpParameters(AcpParams::default()),
        2,
    )
    .await;
    change.approvals.truncate(1);
    assert!(matches!(
        replica
            .native_apply_administration(&submitter, &change)
            .await,
        Err(ClientError::TxReverted { .. })
    ));
    change.approvals = vec![approve_administration(&change.request, 0, &next).unwrap()];
    let mut foreign = change.clone();
    foreign.request.genesis_id = [8; 32];
    foreign.approvals = vec![approve_administration(&foreign.request, 0, &next).unwrap()];
    assert!(matches!(
        replica
            .native_apply_administration(&submitter, &foreign)
            .await,
        Err(ClientError::TxReverted { .. })
    ));
    assert_eq!(
        replica
            .read_administration(receipt.block_number, &trusted)
            .await
            .unwrap()
            .value
            .unwrap()
            .sequence,
        2
    );
    let applied = replica
        .native_apply_administration(&submitter, &change)
        .await
        .unwrap();
    assert_eq!(
        replica
            .read_administration(receipt.block_number, &trusted)
            .await
            .unwrap()
            .value
            .unwrap()
            .sequence,
        3
    );
    assert_eq!(
        serde_json::from_slice::<AcpParams>(&replica.get_acp_params().await.unwrap()).unwrap(),
        AcpParams::default()
    );
    for index in 0..cluster.node_count() {
        HubClient::new(cluster.node(index).rpc_url())
            .wait_for_receipt(applied.transaction_hash, Duration::from_millis(50), 600)
            .await
            .unwrap();
    }
}
