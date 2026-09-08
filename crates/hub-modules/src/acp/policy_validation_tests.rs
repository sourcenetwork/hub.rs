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
