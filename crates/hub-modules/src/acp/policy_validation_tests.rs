use super::*;

const VALID: &str = "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n    permissions:\n      - name: read\n        expr: reader\n";
const UNDECLARED: &str = "name: files\nresources:\n  - name: file\n    permissions:\n      - name: read\n        expr: missing\n";

#[test]
fn validation_and_execution_reject_undeclared_references() {
    let owner = Did::new("did:key:owner").unwrap();
    let mut module = AcpModule::new();
    assert!(
        !module
            .query_validate_policy(UNDECLARED, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .0
    );
    assert!(
        module
            .create_policy(&owner, UNDECLARED, PolicyMarshalingType::ShortYaml)
            .is_err()
    );
    let policy = module
        .create_policy(&owner, VALID, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    let before = module.store.serialize();
    assert!(
        module
            .edit_policy(&owner, &policy, UNDECLARED, PolicyMarshalingType::ShortYaml)
            .is_err()
    );
    assert_eq!(module.store.serialize(), before);
}

#[test]
fn failed_policy_construction_does_not_consume_a_counter() {
    let owner = Did::new("did:key:owner").unwrap();
    let mut module = AcpModule::new();
    let before = module.store.serialize();
    let invalid = VALID.replace("expr: reader", "expr: reader ^ writer");
    assert!(
        module
            .create_policy(&owner, &invalid, PolicyMarshalingType::ShortYaml)
            .is_err()
    );
    assert_eq!(module.store.serialize(), before);
    let expected = AcpModule::new()
        .create_policy(&owner, VALID, PolicyMarshalingType::ShortYaml)
        .unwrap();
    assert_eq!(
        module
            .create_policy(&owner, VALID, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .policy
            .id,
        expected.policy.id
    );
}

#[test]
fn validation_respects_the_requested_format() {
    let module = AcpModule::new();
    for format in [
        PolicyMarshalingType::Unknown,
        PolicyMarshalingType::ShortJson,
    ] {
        assert!(!module.query_validate_policy(VALID, format).unwrap().0);
    }
}

#[test]
fn creation_rejects_invalid_counter_state_without_mutation() {
    let owner = Did::new("did:key:owner").unwrap();
    for counter in [
        Vec::new(),
        vec![0; 7],
        vec![0; 9],
        u64::MAX.to_be_bytes().to_vec(),
    ] {
        let mut module = AcpModule::new();
        module.store.put(keys::POLICY_COUNTER_KEY, counter);
        let before = module.store.serialize();
        assert!(matches!(
            module.create_policy(&owner, VALID, PolicyMarshalingType::ShortYaml),
            Err(AcpError::State(_))
        ));
        assert_eq!(module.store.serialize(), before);
        assert!(module.zanzibar_policies.is_empty());
    }
}

#[test]
fn json_policy_uses_shared_semantics_for_creation_and_editing() {
    let json = r#"{"name":"files","resources":[{"name":"file","relations":[{"name":"reader"}],"permissions":[{"name":"read","expr":"reader"}]}]}"#;
    let yaml_policy =
        AcpModule::validate_policy_definition(VALID, PolicyMarshalingType::ShortYaml).unwrap();
    let json_policy =
        AcpModule::validate_policy_definition(json, PolicyMarshalingType::ShortJson).unwrap();
    assert_eq!(
        serde_json::to_value(yaml_policy).unwrap(),
        serde_json::to_value(json_policy).unwrap()
    );
    let owner = Did::new("did:key:owner").unwrap();
    let mut module = AcpModule::new();
    let record = module
        .create_policy(&owner, json, PolicyMarshalingType::ShortJson)
        .unwrap();
    assert_eq!(record.marshal_type, PolicyMarshalingType::ShortJson);
    let id = record.policy.id;
    module
        .edit_policy(
            &owner,
            &id,
            &json.replace("reader", "editor"),
            PolicyMarshalingType::ShortJson,
        )
        .unwrap();
    let before = module.store.serialize();
    for invalid in [
        json.replace("\"expr\":\"reader\"", "\"expr\":\"missing\""),
        json.replace(
            "\"name\":\"files\"",
            "\"name\":\"files\",\"name\":\"duplicate\"",
        ),
        format!("{json} trailing"),
        format!("{}{}", " ".repeat(64 * 1024), json),
    ] {
        assert!(
            module
                .edit_policy(&owner, &id, &invalid, PolicyMarshalingType::ShortJson)
                .is_err()
        );
        assert_eq!(module.store.serialize(), before);
    }
    let restored = AcpModule::from_store(InMemoryKvStore::deserialize(&before).unwrap());
    restored.validate_restored_state().unwrap();
    assert_eq!(
        restored.query_policy(&id).unwrap().marshal_type,
        PolicyMarshalingType::ShortJson
    );
}

#[test]
fn policy_id_listing_is_bounded_and_rejects_invalid_keys() {
    let mut module = AcpModule::new();
    for n in 0..128u64 {
        module
            .store
            .put(&keys::policy_key(&format!("{n:064x}")), vec![0; 8192]);
    }
    let ids = module.query_policy_ids().unwrap();
    assert_eq!(ids.len(), 128);
    assert_eq!(ids.first().unwrap(), &format!("{:064x}", 0));
    assert_eq!(ids.last().unwrap(), &format!("{:064x}", 127));
    module
        .store
        .put(&keys::policy_key(&format!("{:064x}", 128)), Vec::new());
    assert!(matches!(
        module.query_policy_ids(),
        Err(AcpError::InvalidAccessRequest { .. })
    ));
    for suffix in [vec![255], b"short".to_vec(), vec![b'A'; 64]] {
        let mut module = AcpModule::new();
        let mut key = keys::POLICY_PREFIX.to_vec();
        key.extend(suffix);
        module.store.put(&key, Vec::new());
        assert!(matches!(module.query_policy_ids(), Err(AcpError::State(_))));
    }
}
