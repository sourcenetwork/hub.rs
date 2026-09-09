//! Direct actor signatures bind native commands and preserve identity across workers.

use alloy_sol_types::SolCall;
use hub_client::{ACP_ADDRESS, BlsSigner, HubClient, ModuleId, RECORD_PROOF_BYTES};
use hub_crypto::{
    jwt::{DelegationScope, JwtClaims},
    operation::{OperationClaim, OperationId},
};
use hub_domain::ConsensusPublicKey;
use hub_e2e::cluster::{ConsensusPreset, KeySet, TestCluster};
use hub_modules::acp::{
    abi::IAcp,
    delegated_operation::DelegatedOperation,
    types::{Object, PolicyCmd},
};
use k256::ecdsa::SigningKey;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

async fn submit(
    client: &HubClient,
    signer: &BlsSigner,
    trusted: &ConsensusPublicKey,
    call: impl SolCall,
    success: bool,
) -> u64 {
    let wire = signer
        .sign_native_tx(ACP_ADDRESS, call.abi_encode().into())
        .unwrap();
    let id = client.send_native_tx(&wire).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(response) = client.read_receipt(id, trusted).await.unwrap() {
                assert_eq!(response.verify(id, trusted).unwrap().success(), success);
                return response.revision.height;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn actor_signed_command_rejects_substitution_and_deduplicates_across_workers() {
    let deployment = 9085;
    let keys = KeySet::builder().seed(deployment).build().unwrap();
    let trusted = *keys.epoch_info().output.public().public();
    let cluster = TestCluster::builder()
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster.wait_ready(Duration::from_secs(30)).await.unwrap();
    cluster
        .observe(Duration::from_millis(100))
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let client = HubClient::new(cluster.node(0).rpc_url());
    let worker = BlsSigner::new(7u64.into(), deployment).unwrap();
    let other = BlsSigner::new(8u64.into(), deployment).unwrap();
    let key = SigningKey::from_bytes((&[42u8; 32]).into()).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = hub_client::create_scoped_bearer_token(
        &key,
        worker.did(),
        deployment,
        now,
        now + 120,
        DelegationScope::CreatePolicy,
    )
    .unwrap();
    let created = submit(
        &client,
        &worker,
        &trusted,
        IAcp::bearerCreatePolicyCall {
            bearerToken: token.clone(),
            policy: b"name: signed_operation\nresources:\n  - name: file\n"
                .to_vec()
                .into(),
            marshalType: 1,
        },
        true,
    )
    .await;
    let policy = client
        .read_policy_page(None, 1, created, &trusted)
        .await
        .unwrap()
        .records
        .remove(0);
    let actor = hub_crypto::jwt::verify_bearer_token(&token).unwrap().iss;
    let genesis = client
        .read_finalized_revision(1, &trusted)
        .await
        .unwrap()
        .parent_hash
        .parse::<alloy_primitives::B256>()
        .unwrap()
        .0;
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let command = PolicyCmd::RegisterObject(object.clone());
    let digest = DelegatedOperation::PolicyCommand(&policy.policy.id, &command)
        .digest()
        .unwrap();
    let mut id = [1; 32];
    id[..8].copy_from_slice(&(now + 120).to_be_bytes());
    let mut claims = JwtClaims {
        iss: actor.clone(),
        sub: worker.did().into(),
        exp: now + 120,
        aud: format!("vera:{deployment}"),
        scope: DelegationScope::PolicyCommands,
        iat: now,
        nbf: now,
        relay: None,
        request: Some(OperationClaim {
            id: OperationId(id),
            digest,
            genesis_id: genesis,
        }),
    };
    let signed = hub_client::create_operation_token(&key, &claims).unwrap();
    let call = |token: String, command: &PolicyCmd| IAcp::bearerPolicyCmdCall {
        policyId: policy.policy.id.parse().unwrap(),
        bearerToken: token,
        cmd: serde_json::to_vec(command).unwrap().into(),
    };
    let substituted = PolicyCmd::RegisterObject(Object {
        resource: "file".into(),
        id: "other".into(),
    });
    submit(
        &client,
        &worker,
        &trusted,
        call(signed.clone(), &substituted),
        false,
    )
    .await;
    submit(
        &client,
        &other,
        &trusted,
        call(signed.clone(), &command),
        false,
    )
    .await;
    let registered = submit(&client, &worker, &trusted, call(signed, &command), true).await;
    claims.sub = other.did().into();
    let retry = hub_client::create_operation_token(&key, &claims).unwrap();
    let retried = submit(&client, &other, &trusted, call(retry, &command), true).await;
    let prefix = hub_client::object_owner_prefix(&policy.policy.id, &object).unwrap();
    let owner = client
        .read_current_prefix(
            ModuleId::Acp,
            &prefix,
            retried,
            &trusted,
            RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    assert_eq!(
        owner
            .verify_object_owner(&policy.policy.id, &object, retried, &trusted)
            .unwrap()
            .unwrap()
            .0
            .as_str(),
        actor
    );
    let records = owner
        .verify(
            ModuleId::Acp,
            &prefix,
            retried,
            &trusted,
            RECORD_PROOF_BYTES,
        )
        .unwrap();
    assert_eq!(records.entries.len(), 1);
    let record: hub_modules::acp::types::RelationshipRecord =
        serde_json::from_slice(&records.entries[0].value).unwrap();
    assert_eq!(record.metadata.creation_ts.block_height, registered);
    assert_eq!(record.metadata.tx_signer, worker.did());
}
