use super::*;

#[test]
fn threshold_object_ids_match_rust_orbis_and_bind_optional_metadata() {
    let document = EncryptedDocument {
        ring_id: "ring-1".into(),
        document:
            r#"{"enc_cmt":[1,2,3],"encrypted_data":[4,5,6],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0]}"#
                .into(),
        proof: r#"{"challenge":[7,8],"response":[9,10]}"#.into(),
        policy_id: "policy-b".into(),
        resource: "document".into(),
        permission: "read".into(),
        tier: Some("gold".into()),
        timestamp: Some(1_700_000_000),
    };
    let id = ThresholdObject::Document(document.clone()).id().unwrap();
    assert_eq!(
        id,
        "e555cfcb145edf3d4cd8acbae93e05dc3a48eb0162b3af90f42064ab837c9a06"
    );
    let mut changed = document.clone();
    changed.document =
        r#"{ "nonce": [0,0,0,0,0,0,0,0,0,0,0,0], "encrypted_data": [4,5,6], "enc_cmt": [1,2,3] }"#
            .into();
    assert_eq!(ThresholdObject::Document(changed.clone()).id().unwrap(), id);
    changed.timestamp = None;
    assert_ne!(ThresholdObject::Document(changed.clone()).id().unwrap(), id);
    changed.timestamp = document.timestamp;
    changed.tier = None;
    assert_ne!(ThresholdObject::Document(changed).id().unwrap(), id);
    for field in ["enc_cmt", "ENC_CMT", "extra"] {
        let mut changed = document.clone();
        changed.document.pop();
        changed.document.push_str(&format!(",\"{field}\":[9]}}"));
        assert!(ThresholdObject::Document(changed).id().is_err());
    }
    let mut changed = document;
    changed.proof = r#"{"challenge":[],"response":[9,10]}"#.into();
    assert!(ThresholdObject::Document(changed).id().is_err());
}
