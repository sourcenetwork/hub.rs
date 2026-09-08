//! Registration priority and ownership transfer through certified native execution.

use alloy_primitives::{B256, Bytes};
use alloy_sol_types::{SolCall as _, SolEvent as _};
use hub_client::{ACP_ADDRESS, Actor, BlsSigner, HubClient, ModuleId, Object, RECORD_PROOF_BYTES};
use hub_domain::{ConsensusPublicKey, ExecutionReceipt, NativeTx};
use hub_e2e::cluster::{ConsensusPreset, KeySet, TestCluster};
use hub_modules::acp::{
    abi::IAcp,
    types::{GenerateCommitmentResult, RelationshipRecord},
};
use std::time::Duration;

async fn submit(
    client: &HubClient,
    signer: &BlsSigner,
    trusted: &ConsensusPublicKey,
    call: Vec<u8>,
) -> (u64, ExecutionReceipt) {
    let wire = signer
        .sign_native_tx(ACP_ADDRESS, Bytes::from(call))
        .unwrap();
    let id = NativeTx::decode_wire(&wire).unwrap().tx_id().0;
    assert_eq!(client.send_native_tx(&wire).await.unwrap(), id);
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Ok(Some(response)) = client.read_receipt(id, trusted).await {
                return (
                    response.revision.height,
                    response.verify(id, trusted).unwrap().clone(),
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("certified registration receipt deadline")
}

#[tokio::test]
async fn native_registration_preserves_commitment_priority_and_owner_proofs() {
    let deployment = 9083;
    let keys = KeySet::builder().seed(deployment).build().unwrap();
    let trusted = *keys.epoch_info().output.public().public();
    let cluster = TestCluster::builder()
        .binary(hub_e2e::resolve_binary().unwrap())
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster.wait_ready(Duration::from_secs(30)).await.unwrap();
    let client = HubClient::new(cluster.node(0).rpc_url());
    let first = BlsSigner::new(7u64.into(), deployment).unwrap();
    let second = BlsSigner::new(8u64.into(), deployment).unwrap();
    client.native_create_policy(&first, b"name: registrations\nresources:\n  - name: file\n    permissions:\n      - name: read\n        expr: owner\n", 1).await.unwrap();
    let policy = client.get_policy_ids().await.unwrap().pop().unwrap();
    let policy_id: B256 = policy.parse().unwrap();
    let call = IAcp::generateCommitmentCall {
        policyId: policy_id,
        resources: vec!["file".into()],
        objectIds: vec!["report".into()],
        actor: second.did().into(),
    };
    let result = client
        .eth_call(ACP_ADDRESS, call.abi_encode().into())
        .await
        .unwrap();
    let generated: GenerateCommitmentResult =
        serde_json::from_slice(&IAcp::generateCommitmentCall::abi_decode_returns(&result).unwrap())
            .unwrap();
    let commit = || {
        IAcp::commitRegistrationsCall {
            policyId: policy_id,
            commitment: generated.commitment.clone().into(),
        }
        .abi_encode()
    };
    let (early_height, early) = submit(&client, &second, &trusted, commit()).await;
    assert!(early.success());
    let early = IAcp::RegistrationsCommitted::decode_log(&early.logs()[0]).unwrap();
    assert_eq!(early.data.policyId, policy_id);
    assert_eq!(early.data.commitment.as_slice(), generated.commitment);
    let registered = client
        .native_register_object(&first, policy_id, "report", "file")
        .await
        .unwrap();
    assert!(registered.block_number > early_height);
    let (_, late) = submit(&client, &second, &trusted, commit()).await;
    assert!(late.success());
    let late = IAcp::RegistrationsCommitted::decode_log(&late.logs()[0]).unwrap();
    let reveal = |id| {
        IAcp::revealRegistrationCall {
            commitmentId: id,
            proof: serde_json::to_vec(&generated.proofs[0]).unwrap().into(),
        }
        .abi_encode()
    };
    let (_, rejected) = submit(&client, &second, &trusted, reveal(late.data.commitmentId)).await;
    assert!(!rejected.success());
    let (amended_height, amended) =
        submit(&client, &second, &trusted, reveal(early.data.commitmentId)).await;
    assert!(amended.success());
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let prefix = hub_client::object_owner_prefix(&policy, &object).unwrap();
    let ownership = client
        .read_current_prefix(
            ModuleId::Acp,
            &prefix,
            amended_height,
            &trusted,
            RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    assert_eq!(
        ownership
            .verify_object_owner(&policy, &object, amended_height, &trusted)
            .unwrap(),
        Some(Actor(second.did().parse().unwrap()))
    );
    let records = ownership
        .verify(
            ModuleId::Acp,
            &prefix,
            amended_height,
            &trusted,
            RECORD_PROOF_BYTES,
        )
        .unwrap();
    assert_eq!(records.entries.len(), 1);
    let record: RelationshipRecord = serde_json::from_slice(&records.entries[0].value).unwrap();
    assert_eq!(record.metadata.creation_ts.block_height, early_height);
    let archive = || {
        IAcp::archiveObjectCall {
            policyId: policy_id,
            objectId: "report".into(),
            resource: "file".into(),
        }
        .abi_encode()
    };
    assert!(
        !submit(&client, &first, &trusted, archive())
            .await
            .1
            .success()
    );
    assert!(
        submit(&client, &second, &trusted, archive())
            .await
            .1
            .success()
    );
}
