use super::*;
use crate::{
    acp::types::PolicyMarshalingType,
    hub::nodes::{NodeCommand, NodeInfo, NodeRequest, SignedNodeRequest},
    types::Timestamp,
};
use acp::Relationship;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hub_crypto::{
    jwt::{DelegationScope, JwtClaims},
    operation::{OperationClaim, OperationId},
};
use k256::ecdsa::{
    Signature, SigningKey,
    signature::{Signer as _, hazmat::PrehashSigner as _},
};

const POLICY: &str = "name: rings\nresources:\n  - name: ring_policy\n    relations:\n      - name: creator\n    permissions:\n      - name: create_ring\n        expr: creator\n  - name: ring\n";
fn secret(n: u8) -> SigningKey {
    SigningKey::from_slice(&[n; 32]).unwrap()
}
fn public(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_sec1_bytes())
}
fn actor() -> Did {
    Did::new(
        hub_crypto::secp256k1::did_from_secp256k1_pubkey(
            secret(1).verifying_key().to_sec1_bytes().as_ref(),
        )
        .unwrap(),
    )
    .unwrap()
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
fn submission() -> TxExecCtx {
    TxExecCtx {
        signer: "did:key:worker".into(),
        sequence: 0,
        tx_hash: vec![8; 32],
    }
}
fn token(command: &RingCommand, entropy: u8) -> String {
    let mut id = [entropy; 32];
    id[..8].copy_from_slice(&200u64.to_be_bytes());
    let claims = JwtClaims {
        iss: actor().to_string(),
        sub: submission().signer,
        exp: 200,
        aud: "vera:9001".into(),
        scope: DelegationScope::ManageRings,
        iat: 100,
        nbf: 100,
        relay: None,
        request: Some(OperationClaim {
            id: OperationId(id),
            digest: DelegatedOperation::RingCommand(command).digest().unwrap(),
            genesis_id: context().genesis_id,
        }),
    };
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: Signature = secret(1).sign(message.as_bytes());
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}
fn fixture(policy: &str) -> (HubModule, AcpModule, RingConfig) {
    let mut hub = HubModule::new();
    let mut acp = AcpModule::new();
    let policy_id = acp
        .create_policy(&actor(), policy, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    acp.direct_policy_cmd(
        &actor(),
        &policy_id,
        PolicyCmd::RegisterObject(Object {
            resource: "ring_policy".into(),
            id: policy_id.clone(),
        }),
    )
    .unwrap();
    acp.direct_policy_cmd(
        &actor(),
        &policy_id,
        PolicyCmd::SetRelationship(Relationship::with_entity(
            "ring_policy",
            &policy_id,
            "creator",
            actor(),
        )),
    )
    .unwrap();
    let mut peers = Vec::new();
    for key in [secret(2), secret(3)] {
        let request = NodeRequest {
            deployment_root: context().genesis_id,
            deployment_id: 9001,
            node_key: public(&key),
            sequence: 0,
            expires_at: 200,
            command: NodeCommand::Register(NodeInfo {
                peer_id: public(&key),
                controller_key: public(&key),
                allowed_policy_ids: vec![policy_id.clone()],
                allowed_ring_ids: vec![],
            }),
        };
        let signature: Signature = key
            .sign_prehash(&request.signing_digest().unwrap())
            .unwrap();
        hub.apply_node_request(
            &context(),
            &SignedNodeRequest {
                request,
                signer_key: public(&key),
                signature: hex::encode(signature.to_bytes()),
            },
        )
        .unwrap();
        peers.push(public(&key));
    }
    peers.sort();
    (
        hub,
        acp,
        RingConfig {
            policy_id,
            peer_node_keys: peers,
            threshold: 2,
            pss_interval: 86400,
            current_version: 0,
            nonce: [9; 32],
            trusted_auth_relay_dids: None,
            reporting: ReportingConfig::default(),
        },
    )
}
fn participant(
    ring: &str,
    key: &SigningKey,
    command: RingParticipantCommand,
) -> SignedRingParticipantRequest {
    let request = RingParticipantRequest {
        deployment_root: context().genesis_id,
        deployment_id: 9001,
        ring_id: ring.into(),
        node_key: public(key),
        command,
        expires_at: 200,
    };
    let signature: Signature = key
        .sign_prehash(&request.signing_digest().unwrap())
        .unwrap();
    SignedRingParticipantRequest {
        request,
        signature: hex::encode(signature.to_bytes()),
    }
}
fn confirm(ring: &str, n: u8, key: &str) -> SignedRingParticipantRequest {
    participant(
        ring,
        &secret(n),
        RingParticipantCommand::Confirm(key.into()),
    )
}
fn apply(
    hub: &mut HubModule,
    acp: &mut AcpModule,
    command: &RingCommand,
    entropy: u8,
) -> Result<RingRecord> {
    hub.apply_ring_command(
        acp,
        &context(),
        &submission(),
        &token(command, entropy),
        command,
    )
}

#[test]
fn ring_creation_is_atomic_and_confirmations_require_unanimity() {
    let (mut hub, mut acp, config) = fixture(POLICY);
    let create = RingCommand::Create(config.clone());
    let record = apply(&mut hub, &mut acp, &create, 1).unwrap();
    assert!(
        acp.query_object_owner(
            &config.policy_id,
            &Object {
                resource: "ring".into(),
                id: record.id.clone()
            }
        )
        .unwrap()
        .0
    );
    assert_eq!(apply(&mut hub, &mut acp, &create, 1).unwrap(), record);
    assert!(apply(&mut hub, &mut acp, &create, 2).is_err());
    let first = confirm(&record.id, 2, "aabb");
    let pending = hub
        .apply_ring_participant_request(&context(), &first)
        .unwrap();
    assert!(matches!(pending.state, RingState::Pending { .. }));
    let before = hub.store().serialize();
    assert!(
        hub.apply_ring_participant_request(&context(), &confirm(&record.id, 2, "ccdd"))
            .is_err()
    );
    assert_eq!(hub.store().serialize(), before);
    let mut restored = HubModule::from_store(hub.store().clone());
    let active = restored
        .apply_ring_participant_request(&context(), &confirm(&record.id, 3, "aabb"))
        .unwrap();
    assert_eq!(
        active.state,
        RingState::Active {
            public_key: "aabb".into()
        }
    );
    assert!(
        restored
            .apply_ring_participant_request(
                &context(),
                &participant(&record.id, &secret(2), RingParticipantCommand::Cancel)
            )
            .is_err()
    );
    assert!(
        apply(
            &mut restored,
            &mut acp,
            &RingCommand::Cancel { ring_id: record.id },
            3
        )
        .is_err()
    );

    let (mut hub, mut acp, config) = fixture(&POLICY.replace("  - name: ring\n", ""));
    let before = (hub.store().serialize(), acp.store().serialize());
    assert!(apply(&mut hub, &mut acp, &RingCommand::Create(config), 1).is_err());
    assert_eq!((hub.store().serialize(), acp.store().serialize()), before);
    let (mut hub, acp, config) = fixture(POLICY);
    let mut store = acp.store().clone();
    store.put(b"operation-bytes/v1", (64u64 << 20).to_be_bytes().to_vec());
    let mut acp = AcpModule::from_store(store);
    let before = (hub.store().serialize(), acp.store().serialize());
    let error = apply(&mut hub, &mut acp, &RingCommand::Create(config), 1).unwrap_err();
    assert!(error.to_string().contains("storage budget reached"));
    assert_eq!((hub.store().serialize(), acp.store().serialize()), before);
}

#[test]
fn cancellation_conflict_revocation_and_bad_signatures_cannot_reuse_a_ring() {
    let (mut hub, mut acp, mut config) = fixture(POLICY);
    let create = RingCommand::Create(config.clone());
    let record = apply(&mut hub, &mut acp, &create, 1).unwrap();
    let before = hub.store().serialize();
    let mut altered = confirm(&record.id, 2, "aabb");
    altered.request.deployment_id += 1;
    assert!(
        hub.apply_ring_participant_request(&context(), &altered)
            .is_err()
    );
    let mut altered = confirm(&record.id, 2, "aabb");
    altered.request.command = RingParticipantCommand::Confirm("ccdd".into());
    assert!(
        hub.apply_ring_participant_request(&context(), &altered)
            .is_err()
    );
    assert!(
        hub.apply_ring_participant_request(&context(), &confirm(&record.id, 4, "aabb"))
            .is_err()
    );
    assert_eq!(hub.store().serialize(), before);
    hub.apply_ring_participant_request(&context(), &confirm(&record.id, 2, "aabb"))
        .unwrap();
    let conflict = hub
        .apply_ring_participant_request(&context(), &confirm(&record.id, 3, "ccdd"))
        .unwrap();
    assert!(matches!(conflict.state, RingState::Conflict { .. }));
    assert!(apply(&mut hub, &mut acp, &create, 2).is_err());
    assert!(
        hub.apply_ring_participant_request(&context(), &confirm(&record.id, 3, "aabb"))
            .is_err()
    );

    config.nonce = [10; 32];
    let create = RingCommand::Create(config);
    let record = apply(&mut hub, &mut acp, &create, 3).unwrap();
    let cancel = RingCommand::Cancel {
        ring_id: record.id.clone(),
    };
    hub.revoke_delegation(&context(), &actor(), &token(&cancel, 4))
        .unwrap();
    let before = (hub.store().serialize(), acp.store().serialize());
    assert!(apply(&mut hub, &mut acp, &cancel, 4).is_err());
    assert_eq!((hub.store().serialize(), acp.store().serialize()), before);
    assert!(matches!(
        apply(&mut hub, &mut acp, &cancel, 5).unwrap().state,
        RingState::Cancelled { .. }
    ));
    assert!(apply(&mut hub, &mut acp, &create, 6).is_err());
}

#[test]
fn ring_configuration_and_stored_records_are_bounded_and_validated() {
    let (mut hub, mut acp, config) = fixture(POLICY);
    for bad in [
        RingConfig {
            peer_node_keys: vec![public(&secret(2)); 2],
            ..config.clone()
        },
        RingConfig {
            threshold: 3,
            ..config.clone()
        },
        RingConfig {
            pss_interval: 0,
            ..config.clone()
        },
        RingConfig {
            trusted_auth_relay_dids: Some(vec![actor().to_string()]),
            ..config.clone()
        },
        RingConfig {
            reporting: ReportingConfig {
                kick_threshold: 0,
                ..ReportingConfig::default()
            },
            ..config.clone()
        },
    ] {
        assert!(bad.validate().is_err());
    }
    let mut with_relay = config.clone();
    with_relay.trusted_auth_relay_dids = Some(vec![
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".into(),
    ]);
    with_relay.validate().unwrap();
    let record = apply(&mut hub, &mut acp, &RingCommand::Create(config), 1).unwrap();
    hub.store.put(
        &ring_key(&record.id).unwrap(),
        vec![0; MAX_RING_RECORD_BYTES + 1],
    );
    assert!(hub.threshold_ring(&record.id).is_err());
}
