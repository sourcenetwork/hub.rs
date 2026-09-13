use super::*;
use crate::types::Timestamp;
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn public(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_sec1_bytes())
}
fn context() -> BlockExecCtx {
    BlockExecCtx {
        genesis_id: [1; 32],
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: 100,
            block_height: 2,
        },
    }
}
fn sign(
    node: &SigningKey,
    signer: &SigningKey,
    sequence: u64,
    command: NodeCommand,
) -> SignedNodeRequest {
    let request = NodeRequest {
        deployment_root: context().genesis_id,
        deployment_id: 9001,
        node_key: public(node),
        sequence,
        expires_at: 200,
        command,
    };
    let signature: Signature = signer
        .sign_prehash(&request.signing_digest().unwrap())
        .unwrap();
    SignedNodeRequest {
        request,
        signer_key: public(signer),
        signature: hex::encode(signature.to_bytes()),
    }
}
fn registration(controller: &SigningKey) -> NodeCommand {
    NodeCommand::Register(NodeInfo {
        peer_id: "peer1".into(),
        controller_key: public(controller),
        allowed_policy_ids: vec![],
        allowed_ring_ids: vec![],
    })
}
fn rejected(module: &mut HubModule, request: &SignedNodeRequest) {
    let before = module.store().serialize();
    assert!(module.apply_node_request(&context(), request).is_err());
    assert_eq!(module.store().serialize(), before);
}

#[test]
fn node_controller_transfer_revokes_old_authority_and_preserves_sequence() {
    let (node, controller, next) = (key(1), key(2), key(3));
    let mut module = HubModule::new();
    rejected(
        &mut module,
        &sign(&node, &controller, 0, registration(&controller)),
    );
    let create = sign(&node, &node, 0, registration(&controller));
    assert_eq!(
        module
            .apply_node_request(&context(), &create)
            .unwrap()
            .sequence,
        1
    );
    rejected(&mut module, &create);
    rejected(
        &mut module,
        &sign(&node, &node, 1, NodeCommand::SetPeer("wrong".into())),
    );
    let transfer = sign(
        &node,
        &controller,
        1,
        NodeCommand::TransferController(public(&next)),
    );
    module.apply_node_request(&context(), &transfer).unwrap();
    let mut module = HubModule::from_store(module.store().clone());
    rejected(
        &mut module,
        &sign(&node, &controller, 2, NodeCommand::SetPeer("wrong".into())),
    );
    let allow = NodeCommand::Allow(NodeTarget::Policy("policy".into()));
    module
        .apply_node_request(&context(), &sign(&node, &next, 2, allow.clone()))
        .unwrap();
    rejected(&mut module, &sign(&node, &next, 3, allow));
    let state = module
        .apply_node_request(
            &context(),
            &sign(
                &node,
                &next,
                3,
                NodeCommand::Allow(NodeTarget::Ring("ring".into())),
            ),
        )
        .unwrap();
    assert!(state.info.allows_ring("policy", "other"));
    assert!(state.info.allows_ring("other", "ring"));
    let state = module
        .apply_node_request(
            &context(),
            &sign(
                &node,
                &next,
                4,
                NodeCommand::Disallow(NodeTarget::Policy("policy".into())),
            ),
        )
        .unwrap();
    assert!(!state.info.allows_ring("policy", "other"));
    assert!(state.info.allows_ring("policy", "ring"));
    assert_eq!(state.sequence, 5);
}

#[test]
fn node_requests_bind_context_sequence_payload_and_signature() {
    let node = key(1);
    let mut module = HubModule::new();
    module
        .apply_node_request(&context(), &sign(&node, &node, 0, registration(&node)))
        .unwrap();
    let valid = sign(&node, &node, 1, NodeCommand::SetPeer("peer2".into()));
    for mutation in 0..7 {
        let mut changed = valid.clone();
        match mutation {
            0 => changed.request.deployment_root[0] ^= 1,
            1 => changed.request.deployment_id += 1,
            2 => changed.request.expires_at = 99,
            3 => changed.request.sequence += 1,
            4 => changed.request.command = NodeCommand::SetPeer("peer3".into()),
            5 => changed.signature = "00".repeat(64),
            _ => changed.request.node_key = public(&key(2)),
        }
        rejected(&mut module, &changed);
    }
    assert_eq!(
        module
            .apply_node_request(&context(), &valid)
            .unwrap()
            .info
            .peer_id,
        "peer2"
    );
    rejected(&mut module, &valid);
}

#[test]
fn node_record_and_request_limits_fail_without_mutation() {
    let node = key(1);
    let mut module = HubModule::new();
    let NodeCommand::Register(base) = registration(&node) else {
        unreachable!()
    };
    for mutation in 0..5 {
        let mut info = base.clone();
        match mutation {
            0 => info.peer_id = "x".repeat(257),
            1 => info.controller_key = "00".repeat(33),
            2 => info.allowed_policy_ids = vec!["same".into(); 2],
            3 => {
                info.allowed_ring_ids = (0..=MAX_NODE_TARGETS)
                    .map(|i| format!("ring{i:03}"))
                    .collect()
            }
            _ => info.allowed_policy_ids = vec!["white space".into()],
        }
        rejected(
            &mut module,
            &sign(&node, &node, 0, NodeCommand::Register(info)),
        );
    }
    let created = module
        .apply_node_request(&context(), &sign(&node, &node, 0, registration(&node)))
        .unwrap();
    let mut exhausted = created;
    exhausted.sequence = u64::MAX;
    module.store.put(
        &node_key(&public(&node)).unwrap(),
        serde_json::to_vec(&exhausted).unwrap(),
    );
    rejected(
        &mut module,
        &sign(&node, &node, u64::MAX, NodeCommand::SetPeer("peer2".into())),
    );
    module
        .store
        .put(&node_key(&public(&node)).unwrap(), b"{}".to_vec());
    assert!(module.threshold_node(&public(&node)).is_err());
    module.store.put(
        &node_key(&public(&node)).unwrap(),
        vec![b' '; MAX_NODE_BYTES + 1],
    );
    assert!(
        module
            .threshold_node(&public(&node))
            .unwrap_err()
            .to_string()
            .contains("exceeds byte limit")
    );
}
