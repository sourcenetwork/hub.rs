use super::*;

#[test]
fn editing_rejects_corrupt_relationships_without_partial_pruning() {
    let owner = Did::new("did:key:owner").unwrap();
    let original =
        "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n";
    let replacement = "name: files\nresources:\n  - name: file\n";
    for corruption in 0..3 {
        let mut module = AcpModule::new();
        let policy = module
            .create_policy(&owner, original, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .policy
            .id;
        for id in ["before", "report"] {
            module
                .direct_policy_cmd(
                    &owner,
                    &policy,
                    PolicyCmd::RegisterObject(Object {
                        resource: "file".into(),
                        id: id.into(),
                    }),
                )
                .unwrap();
            module
                .direct_policy_cmd(
                    &owner,
                    &policy,
                    PolicyCmd::SetRelationship(Relationship::with_entity(
                        "file",
                        id,
                        "reader",
                        owner.clone(),
                    )),
                )
                .unwrap();
        }
        let relationship = Relationship::with_entity("file", "report", "reader", owner.clone());
        let key = keys::relationship_key(&policy, &relationship.storage_key());
        let bytes = module.store.get(&key).unwrap();
        let mut record: RelationshipRecord = serde_json::from_slice(&bytes).unwrap();
        let bad = match corruption {
            0 => b"{".to_vec(),
            1 => {
                record.policy_id = "other".into();
                serde_json::to_vec(&record).unwrap()
            }
            _ => {
                record.relationship.object_id = "other".into();
                serde_json::to_vec(&record).unwrap()
            }
        };
        module.store.put(&key, bad);
        let before = module.store.serialize();
        assert!(
            module
                .edit_policy(
                    &owner,
                    &policy,
                    replacement,
                    PolicyMarshalingType::ShortYaml
                )
                .is_err(),
            "corruption {corruption} accepted"
        );
        assert_eq!(module.store.serialize(), before);
        assert!(
            module.zanzibar_policies[&policy]
                .get_relation("file", "reader")
                .is_some()
        );
    }
}
