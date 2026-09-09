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
        let key = keys::relationship_key(&policy, &keys::relationship_storage_key(&relationship));
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

#[test]
fn policy_edits_isolate_forks_and_share_unchanged_definitions() {
    let owner = Did::new("did:key:owner").unwrap();
    let original =
        "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n";
    let replacement =
        "name: files\nresources:\n  - name: file\n    relations:\n      - name: writer\n";
    let mut parent = AcpModule::new();
    let ids: Vec<_> = (0..128)
        .map(|_| {
            parent
                .create_policy(&owner, original, PolicyMarshalingType::ShortYaml)
                .unwrap()
                .policy
                .id
        })
        .collect();
    let before = parent.store.serialize();
    let mut fork = parent.clone();
    let sibling = parent.clone();
    fork.edit_policy(
        &owner,
        &ids[64],
        replacement,
        PolicyMarshalingType::ShortYaml,
    )
    .unwrap();
    for (i, id) in ids.iter().enumerate() {
        assert!(Arc::ptr_eq(
            &parent.zanzibar_policies[id],
            &sibling.zanzibar_policies[id]
        ));
        assert_eq!(
            Arc::ptr_eq(&parent.zanzibar_policies[id], &fork.zanzibar_policies[id]),
            i != 64
        );
        assert!(
            parent.zanzibar_policies[id]
                .get_relation("file", "reader")
                .is_some()
        );
    }
    assert!(
        fork.zanzibar_policies[&ids[64]]
            .get_relation("file", "reader")
            .is_none()
    );
    assert!(
        fork.zanzibar_policies[&ids[64]]
            .get_relation("file", "writer")
            .is_some()
    );
    assert_eq!(parent.store.serialize(), before);
    assert_eq!(sibling.store.serialize(), before);
    let restored =
        AcpModule::from_store(InMemoryKvStore::deserialize(&fork.store.serialize()).unwrap());
    assert_eq!(restored.store.serialize(), fork.store.serialize());
    for id in &ids {
        assert_eq!(
            serde_json::to_vec(restored.zanzibar_policies[id].as_ref()).unwrap(),
            serde_json::to_vec(fork.zanzibar_policies[id].as_ref()).unwrap()
        );
    }
}
