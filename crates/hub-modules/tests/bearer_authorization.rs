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
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256K","typ":"JWT"}"#);
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
        let mut claims = serde_json::json!({"iss": issuer, "sub": policy_id});
        if let Some(expiration) = expiration {
            claims["exp"] = expiration.into();
        }
        let token = signed_token(&key, claims);
        let context = BlockExecCtx {
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
