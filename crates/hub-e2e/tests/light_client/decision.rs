use super::{broadcast_evm_tx, parse_policy_id};
use alloy_sol_types::SolCall;
use hub_client::{ACP_ADDRESS, EvmSigner, HubClient, ModuleId, RECORD_PROOF_BYTES};
use hub_domain::ConsensusPublicKey;
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
        let key = hub_modules::acp::keys::access_decision_key(&id);
        let response = client
            .read_current_record(
                ModuleId::Acp,
                &key,
                receipt.block_number,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await
            .unwrap();
        let revision = response.revision;
        let value = response.record.value.unwrap();
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
