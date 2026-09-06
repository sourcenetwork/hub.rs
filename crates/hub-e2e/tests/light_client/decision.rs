use super::{broadcast_evm_tx, parse_policy_id};
use alloy_sol_types::SolCall;
use hub_client::{ACP_ADDRESS, EvmSigner, HubClient};
use hub_domain::{
    ConsensusPublicKey, LightBlock, ModuleStateProof, verify_light_block, verify_module_state_proof,
};
use hub_e2e::cluster::TestCluster;
use hub_modules::{
    acp::{
        abi::IAcp,
        decision::DecisionRequest,
        types::{AccessRequest, Actor, Object, Operation},
    },
    types::Timestamp,
};

pub(super) async fn check_decisions(
    cluster: &TestCluster,
    client: &HubClient,
    signer: &EvmSigner,
    policy: &str,
    trusted: &ConsensusPublicKey,
) {
    let mut ids = vec![];
    for _ in 0..2 {
        let expected = DecisionRequest {
            deployment_id: signer.chain_id(),
            policy_id: policy.into(),
            creator: signer.did(),
            creator_sequence: client.get_nonce(signer.address()).await.unwrap(),
            request: AccessRequest {
                actor: Actor(signer.did().parse().unwrap()),
                operations: vec![Operation {
                    object: Object {
                        resource: "document".into(),
                        id: "doc1".into(),
                    },
                    permission: "read".into(),
                }],
            },
        };
        let receipt = broadcast_evm_tx(
            cluster,
            client,
            signer,
            ACP_ADDRESS,
            IAcp::checkAccessCall {
                policyId: parse_policy_id(policy),
                resources: vec!["document".into()],
                objectIds: vec!["doc1".into()],
                permissions: vec!["read".into()],
                actor: signer.did(),
            }
            .abi_encode(),
        )
        .await;
        assert_eq!(receipt.status, 1);
        let id = expected.id().unwrap();
        let revision: LightBlock =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    match client
                        .rpc_call_typed(
                            "hub_getLightBlock",
                            serde_json::json!([receipt.block_number]),
                        )
                        .await
                    {
                        Ok(light) => break light,
                        Err(hub_client::ClientError::Rpc { message, .. })
                            if message.contains("finalization certificate not found") =>
                        {
                            tokio::time::sleep(std::time::Duration::from_millis(25)).await
                        }
                        Err(error) => panic!("decision certificate: {error}"),
                    }
                }
            })
            .await
            .unwrap();
        assert_eq!(revision.height, receipt.block_number);
        let (_, root) = verify_light_block(&revision, trusted).unwrap();
        let key = format!("0x{}", hex::encode(format!("access_decision/{id}")));
        let proof: ModuleStateProof = client
            .rpc_call_typed(
                "hub_getStateProof",
                serde_json::json!(["acp", key, revision.height]),
            )
            .await
            .unwrap();
        assert_eq!(proof.module, hub_domain::ModuleId::Acp);
        assert_eq!(proof.key, key);
        assert_eq!(proof.height, revision.height);
        verify_module_state_proof(root, &proof).unwrap();
        let value = proof.value.unwrap();
        let value = hex::decode(value.strip_prefix("0x").unwrap_or(&value)).unwrap();
        let decision = expected
            .verify_record(
                &value,
                &Timestamp {
                    seconds: revision.timestamp,
                    block_height: revision.height,
                },
            )
            .unwrap();
        assert_eq!(decision.issued_height, receipt.block_number);
        assert!(decision.creation_time.seconds <= revision.timestamp);
        ids.push(id);
    }
    assert_ne!(ids[0], ids[1]);
}
