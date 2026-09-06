use super::{broadcast_evm_tx, parse_policy_id};
use alloy_sol_types::SolCall;
use hub_client::{
    ACP_ADDRESS, AccessRequest, Actor, EvmSigner, HubClient, Object, Operation, PERMISSION_LIMITS,
    PermissionProof, PermissionRead, verify_permission_proof,
};
use hub_domain::{ConsensusPublicKey, LightBlock, verify_light_block};
use hub_e2e::cluster::TestCluster;
use hub_modules::acp::abi::IAcp;

pub(super) const READER_DID: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

pub(super) async fn check_permissions(
    cluster: &TestCluster,
    client: &HubClient,
    signer: &EvmSigner,
    policy: &str,
    revision: &LightBlock,
    trusted: &ConsensusPublicKey,
) {
    let request = AccessRequest {
        actor: Actor(READER_DID.parse().unwrap()),
        operations: vec![Operation {
            object: Object {
                resource: "document".into(),
                id: "doc1".into(),
            },
            permission: "read".into(),
        }],
    };
    assert!(
        client
            .verify_access_at(policy, &request, revision, trusted, PERMISSION_LIMITS)
            .await
            .unwrap()
    );
    let (_, root) = verify_light_block(revision, trusted).unwrap();
    let proof: PermissionProof = client
        .rpc_call_typed(
            "hub_getPermissionProof",
            serde_json::json!([policy, request, revision.height]),
        )
        .await
        .unwrap();
    assert!(
        verify_permission_proof(
            root,
            revision.height,
            policy,
            &request,
            &proof,
            PERMISSION_LIMITS
        )
        .unwrap()
    );
    for index in 0..proof.reads.len() {
        let mut missing = proof.clone();
        missing.reads.remove(index);
        assert!(
            verify_permission_proof(
                root,
                revision.height,
                policy,
                &request,
                &missing,
                PERMISSION_LIMITS
            )
            .is_err()
        );
    }
    let mut wrong_request = request.clone();
    wrong_request.actor = Actor(
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap(),
    );
    assert!(!matches!(
        verify_permission_proof(
            root,
            revision.height,
            policy,
            &wrong_request,
            &proof,
            PERMISSION_LIMITS
        ),
        Ok(true)
    ));
    let mut duplicate = proof.clone();
    duplicate.reads.push(proof.reads[0].clone());
    assert!(
        verify_permission_proof(
            root,
            revision.height,
            policy,
            &request,
            &duplicate,
            PERMISSION_LIMITS
        )
        .is_err()
    );
    let mut limits = PERMISSION_LIMITS;
    limits.proof_bytes = 1;
    assert!(
        verify_permission_proof(root, revision.height, policy, &request, &proof, limits).is_err()
    );
    limits = PERMISSION_LIMITS;
    limits.reads.reads = 1;
    assert!(
        verify_permission_proof(root, revision.height, policy, &request, &proof, limits).is_err()
    );

    let edge = IAcp::setRelationshipSubjectCall {
        policyId: parse_policy_id(policy),
        resource: "document".into(),
        objectId: "doc1".into(),
        relation: "blocked".into(),
        subjectKind: 3,
        subjectResource: "document".into(),
        subjectObjectId: "suspensions".into(),
        subjectRelation: "blocked".into(),
    }
    .abi_encode();
    assert_eq!(
        broadcast_evm_tx(cluster, client, signer, ACP_ADDRESS, edge)
            .await
            .status,
        1
    );
    let block = IAcp::setRelationshipCall {
        policyId: parse_policy_id(policy),
        resource: "document".into(),
        objectId: "suspensions".into(),
        relation: "blocked".into(),
        actor: READER_DID.into(),
    }
    .abi_encode();
    let receipt = broadcast_evm_tx(cluster, client, signer, ACP_ADDRESS, block).await;
    assert_eq!(receipt.status, 1);
    let denied_revision = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match client
                .rpc_call_typed::<LightBlock>(
                    "hub_getLightBlock",
                    serde_json::json!([receipt.block_number]),
                )
                .await
            {
                Ok(revision) => break revision,
                Err(hub_client::ClientError::Rpc { message, .. })
                    if message.contains("finalization certificate not found") =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(error) => panic!("finalized revision: {error}"),
            }
        }
    })
    .await
    .expect("certificate must become available for the included operation");
    assert!(
        !client
            .verify_access_at(
                policy,
                &request,
                &denied_revision,
                trusted,
                PERMISSION_LIMITS
            )
            .await
            .unwrap()
    );
    let mut owner_request = request.clone();
    owner_request.actor = Actor(signer.did().parse().unwrap());
    assert!(
        client
            .verify_access_at(
                policy,
                &owner_request,
                &denied_revision,
                trusted,
                PERMISSION_LIMITS
            )
            .await
            .unwrap()
    );
    let (_, denied_root) = verify_light_block(&denied_revision, trusted).unwrap();
    assert!(
        verify_permission_proof(
            denied_root,
            denied_revision.height,
            policy,
            &request,
            &proof,
            PERMISSION_LIMITS
        )
        .is_err()
    );
    let mut denied: PermissionProof = client
        .rpc_call_typed(
            "hub_getPermissionProof",
            serde_json::json!([policy, request, denied_revision.height]),
        )
        .await
        .unwrap();
    assert!(
        !verify_permission_proof(
            denied_root,
            denied_revision.height,
            policy,
            &request,
            &denied,
            PERMISSION_LIMITS
        )
        .unwrap()
    );
    let blocked_prefix = format!("relationship/{policy}//rel/document/doc1/blocked/");
    let relation = denied
        .reads
        .iter_mut()
        .find_map(|read| match read {
            PermissionRead::Prefix { prefix, proof }
                if prefix.as_ref() == blocked_prefix.as_bytes() =>
            {
                Some(proof)
            }
            _ => None,
        })
        .expect("cross-object exclusion must prove the complete blocked relation");
    assert_eq!(relation.records.len(), 1);
    relation.records.clear();
    assert!(
        verify_permission_proof(
            denied_root,
            denied_revision.height,
            policy,
            &request,
            &denied,
            PERMISSION_LIMITS
        )
        .is_err()
    );
}
