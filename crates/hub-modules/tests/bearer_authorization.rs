//! Expiration semantics from Vera 205df1ad, x/acp/bearer_token/spec.go.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hub_modules::{
    acp::{
        AcpModule,
        error::AcpError,
        types::{Object, PolicyCmd, PolicyMarshalingType},
    },
    types::{BlockExecCtx, Timestamp},
};
use identity::Did;
use k256::ecdsa::{Signature, SigningKey, signature::Signer as _};

fn signed_token(key: &SigningKey, claims: serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let message = format!("{header}.{payload}");
    let signature: Signature = key.sign(message.as_bytes());
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

#[test]
fn bearer_expiration_uses_execution_time_before_mutating_state() {
    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    let issuer = hub_crypto::secp256k1::did_from_secp256k1_pubkey(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    let actor = Did::new(&issuer).unwrap();
    let mut base = AcpModule::new();
    let policy_id = base
        .create_policy(
            &actor,
            "name: files\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;

    for (expiration, now, allowed) in [
        (Some(100), 99, true),
        (Some(100), 100, true),
        (Some(100), 101, false),
        (Some(0), 0, false),
        (None, 0, false),
    ] {
        let mut claims = serde_json::json!({"iss": issuer, "sub": issuer, "aud": "vera:9001", "scope": "acp:policy", "iat": 0, "nbf": 0});
        if let Some(expiration) = expiration {
            claims["exp"] = expiration.into();
        }
        let token = signed_token(&key, claims);
        let context = BlockExecCtx {
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds: now,
                block_height: 1,
            },
        };
        let object = Object {
            resource: "file".into(),
            id: "report".into(),
        };
        let mut module = base.clone();
        let before = module.store().serialize();
        let result = module.bearer_policy_cmd(
            &mut hub_modules::hub::HubModule::new(),
            &context,
            &actor,
            &token,
            &policy_id,
            PolicyCmd::RegisterObject(object.clone()),
        );

        if allowed {
            result.unwrap();
            let (registered, record) = module.query_object_owner(&policy_id, &object).unwrap();
            assert!(registered);
            assert_eq!(record.unwrap().metadata.owner_did, issuer);
        } else {
            assert!(
                matches!(result, Err(AcpError::InvalidBearerToken { .. })),
                "{result:?}"
            );
            assert_eq!(module.store().serialize(), before);
        }
    }
}

#[test]
fn delegation_binds_caller_deployment_and_revocation() {
    use hub_modules::hub::{HubModule, types::JWSTokenStatus};
    use hub_modules::kv_store::InMemoryKvStore;

    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    let issuer = hub_crypto::secp256k1::did_from_secp256k1_pubkey(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    let owner = Did::new(&issuer).unwrap();
    let caller = Did::new("did:key:caller").unwrap();
    let stranger = Did::new("did:key:stranger").unwrap();
    let token = signed_token(
        &key,
        serde_json::json!({
            "iss": issuer, "sub": caller.to_string(), "aud": "vera:9001",
            "scope": "acp:policy", "iat": 10, "nbf": 5, "exp": 100,
        }),
    );
    let mut context = BlockExecCtx {
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: 20,
            block_height: 1,
        },
    };
    let mut base = AcpModule::new();
    let policy = base
        .create_policy(
            &owner,
            "name: files\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    let command = || PolicyCmd::RegisterObject(object.clone());
    let mut hub = HubModule::new();
    let before = base.store().serialize();
    assert!(
        base.bearer_policy_cmd(&mut hub, &context, &stranger, &token, &policy, command())
            .is_err()
    );
    context.deployment_id = 9002;
    assert!(
        base.bearer_policy_cmd(&mut hub, &context, &caller, &token, &policy, command())
            .is_err()
    );
    context.deployment_id = 9001;
    context.timestamp.seconds = 4;
    assert!(
        base.bearer_policy_cmd(&mut hub, &context, &caller, &token, &policy, command())
            .is_err()
    );
    assert_eq!(base.store().serialize(), before);
    assert!(hub.store().is_empty());
    context.timestamp.seconds = 20;

    // Both the issuer and bound submitter can revoke before any use.
    for revoker in [&owner, &caller] {
        let mut revoked = hub.clone();
        let denied = revoked.store().serialize();
        assert!(
            revoked
                .revoke_delegation(&context, &stranger, &token)
                .is_err()
        );
        assert_eq!(revoked.store().serialize(), denied);
        let record = revoked
            .revoke_delegation(&context, revoker, &token)
            .unwrap();
        assert_eq!(record.status, JWSTokenStatus::Invalid);
        assert!(record.first_used_at.is_none());
        let mut reopened = HubModule::from_store(
            InMemoryKvStore::deserialize(&revoked.store().serialize()).unwrap(),
        );
        assert!(
            base.bearer_policy_cmd(&mut reopened, &context, &caller, &token, &policy, command())
                .is_err()
        );
        assert_eq!(base.store().serialize(), before);
        assert_eq!(
            reopened.get_jws_token(&record.token_hash).unwrap(),
            Some(record)
        );
    }

    // A rejected command cannot register token usage.
    let invalid = PolicyCmd::RegisterObject(Object {
        resource: "missing".into(),
        id: "report".into(),
    });
    assert!(
        base.bearer_policy_cmd(&mut hub, &context, &caller, &token, &policy, invalid)
            .is_err()
    );
    assert!(hub.store().is_empty());
    base.bearer_policy_cmd(&mut hub, &context, &caller, &token, &policy, command())
        .unwrap();
    let (_, record) = base.query_object_owner(&policy, &object).unwrap();
    assert_eq!(record.unwrap().metadata.owner_did, issuer);
    let hash = hub_modules::hub::keys::hash_jws_token(&token);
    let used = hub.get_jws_token(&hash).unwrap().unwrap();
    assert_eq!(used.authorized_account, caller.to_string());
    assert_eq!(used.first_used_at, Some(context.timestamp.clone()));
    hub.revoke_delegation(&context, &owner, &token).unwrap();
    let before = base.store().serialize();
    assert!(
        base.bearer_policy_cmd(&mut hub, &context, &caller, &token, &policy, command())
            .is_err()
    );
    assert_eq!(base.store().serialize(), before);
    assert_eq!(
        hub.get_jws_token(&hash).unwrap().unwrap().status,
        JWSTokenStatus::Invalid
    );
}
