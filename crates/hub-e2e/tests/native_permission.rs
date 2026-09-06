//! Native permission evidence across a running consensus group and later denial.

use std::time::Duration;

use alloy_sol_types::SolCall;
use hub_client::{
    ACP_ADDRESS, AccessRequest, Actor, BlsSigner, ClientError, HubClient, Object, Operation,
    PERMISSION_LIMITS, PermissionProof, PermissionRead, verify_permission_proof,
};
use hub_domain::{ConsensusPublicKey, LightBlock, verify_finalized_block};
use hub_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use hub_e2e::{RECEIPT_POLL_ATTEMPTS, RECEIPT_POLL_INTERVAL};
use hub_modules::acp::abi::IAcp;

const READER: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
const POLICY: &str = "\
name: native-permissions
resources:
  - name: document
    relations:
      - name: reader
        types: [actor]
      - name: blocked
        types: [actor]
    permissions:
      - name: read
        expr: reader - blocked
";

async fn submit(client: &HubClient, signer: &BlsSigner, call: impl SolCall) -> u64 {
    let wire = signer
        .sign_native_tx(ACP_ADDRESS, call.abi_encode().into())
        .unwrap();
    let id = client.send_native_tx(&wire).await.unwrap();
    let receipt = client
        .wait_for_receipt(id, RECEIPT_POLL_INTERVAL, RECEIPT_POLL_ATTEMPTS)
        .await
        .unwrap();
    assert_eq!(receipt.status, 1);
    receipt.block_number
}

async fn revision(client: &HubClient, height: u64, trusted: &ConsensusPublicKey) -> LightBlock {
    let light = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match client
                .rpc_call_typed::<LightBlock>("hub_getLightBlock", serde_json::json!([height]))
                .await
            {
                Ok(light) => return light,
                Err(ClientError::Rpc { message, .. })
                    if message.contains("finalization certificate not found") =>
                {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => panic!("finalized revision: {error}"),
            }
        }
    })
    .await
    .expect("certificate deadline");
    let block = verify_finalized_block(&light, trusted).unwrap();
    assert!(block.native_targets.is_some());
    light
}

async fn current_evidence(
    client: &HubClient,
    policy: &str,
    request: &AccessRequest,
    minimum: u64,
    trusted: &ConsensusPublicKey,
) -> (LightBlock, PermissionProof) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut attempts = 0;
        loop {
            attempts += 1;
            let height = client.block_number().await.unwrap();
            assert!(height >= minimum);
            let light = revision(client, height, trusted).await;
            match client
                .rpc_call_typed::<PermissionProof>(
                    "hub_getPermissionProof",
                    serde_json::json!([policy, request, height]),
                )
                .await
            {
                Ok(proof) => {
                    eprintln!("current permission evidence: {attempts} attempts");
                    return (light, proof);
                }
                Err(ClientError::Rpc {
                    code: -32002,
                    message,
                }) if message == "invalid permission evidence: selected module root changed" => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("permission evidence: {error}"),
            }
        }
    })
    .await
    .expect("current permission evidence deadline")
}

fn evaluate(
    light: &LightBlock,
    policy: &str,
    request: &AccessRequest,
    proof: &PermissionProof,
    trusted: &ConsensusPublicKey,
) -> bool {
    let block = verify_finalized_block(light, trusted).unwrap();
    verify_permission_proof(
        block.module_state_root,
        block.height,
        policy,
        request,
        proof,
        PERMISSION_LIMITS,
    )
    .unwrap()
}

#[tokio::test]
async fn native_permission_reads_follow_finalized_grants_and_denials() {
    let deployment = 9047;
    let trusted = *KeySet::builder()
        .seed(deployment)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let cluster = TestCluster::builder()
        .binary(hub_e2e::resolve_binary().unwrap())
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .genesis(GenesisBuilder::devnet())
        .preset(ConsensusPreset::Fast)
        .build()
        .await
        .unwrap();
    cluster.wait_ready(Duration::from_secs(30)).await.unwrap();
    let observed = cluster.observe(Duration::from_millis(100));
    observed
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let client = HubClient::new(cluster.node(0).rpc_url());
    let owner = BlsSigner::new(1u64.into(), deployment).unwrap();
    submit(
        &client,
        &owner,
        IAcp::createPolicyCall {
            policy: POLICY.as_bytes().to_vec().into(),
            marshalType: 1,
        },
    )
    .await;
    let policy = client.get_policy_ids().await.unwrap().remove(0);
    let granted = submit(
        &client,
        &owner,
        IAcp::batchCallsCall {
            calls: vec![
                IAcp::registerObjectCall {
                    policyId: policy.parse().unwrap(),
                    resource: "document".into(),
                    objectId: "report".into(),
                }
                .abi_encode()
                .into(),
                IAcp::setRelationshipCall {
                    policyId: policy.parse().unwrap(),
                    resource: "document".into(),
                    objectId: "report".into(),
                    relation: "reader".into(),
                    actor: READER.into(),
                }
                .abi_encode()
                .into(),
            ],
        },
    )
    .await;
    let request = AccessRequest {
        actor: Actor(READER.parse().unwrap()),
        operations: vec![Operation {
            object: Object {
                resource: "document".into(),
                id: "report".into(),
            },
            permission: "read".into(),
        }],
    };
    let (allowed_revision, proof) =
        current_evidence(&client, &policy, &request, granted, &trusted).await;
    assert!(evaluate(
        &allowed_revision,
        &policy,
        &request,
        &proof,
        &trusted
    ));
    assert!(proof.roots.is_some());
    assert!(proof.reads.iter().all(|read| matches!(
        read,
        PermissionRead::CurrentPoint { .. } | PermissionRead::CurrentPrefix { .. }
    )));
    let denied = submit(
        &client,
        &owner,
        IAcp::setRelationshipCall {
            policyId: policy.parse().unwrap(),
            resource: "document".into(),
            objectId: "report".into(),
            relation: "blocked".into(),
            actor: READER.into(),
        },
    )
    .await;
    observed
        .wait_for_height(denied + 2, Duration::from_secs(30))
        .await
        .unwrap();
    assert!(matches!(
        client
            .verify_access_at(
                &policy,
                &request,
                &allowed_revision,
                &trusted,
                PERMISSION_LIMITS
            )
            .await,
        Err(ClientError::Rpc { code: -32002, .. })
    ));
    for index in 0..cluster.node_count() {
        let replica = HubClient::new(cluster.node(index).rpc_url());
        let (denied_revision, denied_proof) =
            current_evidence(&replica, &policy, &request, denied, &trusted).await;
        assert!(
            !evaluate(&denied_revision, &policy, &request, &denied_proof, &trusted),
            "node {index} must deny the blocked reader"
        );
        let block = verify_finalized_block(&denied_revision, &trusted).unwrap();
        assert!(
            verify_permission_proof(
                block.module_state_root,
                denied,
                &policy,
                &request,
                &proof,
                PERMISSION_LIMITS,
            )
            .is_err(),
            "the old grant must not verify at the new root"
        );
        let mut owner_request = request.clone();
        owner_request.actor = Actor(owner.did().parse().unwrap());
        let (owner_revision, owner_proof) =
            current_evidence(&replica, &policy, &owner_request, denied, &trusted).await;
        assert!(evaluate(
            &owner_revision,
            &policy,
            &owner_request,
            &owner_proof,
            &trusted
        ));
    }
}
