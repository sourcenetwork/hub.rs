use super::*;

fn setup() -> (AcpModule, Did, Did, String, Object) {
    let first = Did::new("did:key:first").unwrap();
    let second = Did::new("did:key:second").unwrap();
    let mut module = AcpModule::new();
    let policy = module.create_policy(
        &first,
        "name: registrations\nresources:\n  - name: file\n    permissions:\n      - name: read\n        expr: owner\n",
        PolicyMarshalingType::ShortYaml,
    ).unwrap().policy.id;
    (
        module,
        first,
        second,
        policy,
        Object {
            resource: "file".into(),
            id: "report".into(),
        },
    )
}

#[test]
fn amendment_moves_the_owner_key_and_revokes_the_previous_owner() {
    let (mut module, first, second, policy, object) = setup();
    let generated = module
        .query_generate_commitment(
            &policy,
            std::slice::from_ref(&object),
            &Actor(second.clone()),
        )
        .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = module
        .direct_policy_cmd(
            &second,
            &policy,
            PolicyCmd::CommitRegistrations {
                commitment: generated.commitment,
            },
        )
        .unwrap()
    else {
        panic!("expected commitment")
    };
    module
        .direct_policy_cmd(&first, &policy, PolicyCmd::RegisterObject(object.clone()))
        .unwrap();
    assert!(module.check_permission(
        &policy,
        &module.zanzibar_policies[&policy],
        "file",
        "report",
        "read",
        &first
    ));
    let PolicyCmdResult::RevealRegistration { record, event } = module
        .direct_policy_cmd(
            &second,
            &policy,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: registrations_commitment.id,
                proof: generated.proofs[0].clone(),
            },
        )
        .unwrap()
    else {
        panic!("expected amendment")
    };
    assert_eq!(event.previous_owner.0, first);
    assert_eq!(event.new_owner.0, second);
    let old = Relationship::with_entity("file", "report", "owner", first.clone());
    assert!(!module.has_relationship(&policy, &old.storage_key()));
    let stored = module
        .get_relationship(&policy, &record.relationship.storage_key())
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(stored).unwrap(),
        serde_json::to_value(&record).unwrap()
    );
    assert_eq!(
        serde_json::to_value(
            module
                .query_object_owner(&policy, &object)
                .unwrap()
                .1
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(&record).unwrap()
    );
    assert!(module.check_permission(
        &policy,
        &module.zanzibar_policies[&policy],
        "file",
        "report",
        "read",
        &second
    ));
    assert!(!module.check_permission(
        &policy,
        &module.zanzibar_policies[&policy],
        "file",
        "report",
        "read",
        &first
    ));
    assert!(
        module
            .direct_policy_cmd(&first, &policy, PolicyCmd::ArchiveObject(object.clone()))
            .is_err()
    );
    module
        .direct_policy_cmd(&second, &policy, PolicyCmd::ArchiveObject(object.clone()))
        .unwrap();
    module
        .direct_policy_cmd(&second, &policy, PolicyCmd::UnarchiveObject(object))
        .unwrap();
}

#[test]
fn reveal_cannot_reassign_a_commitment_to_another_policy() {
    let (mut module, first, second, policy, object) = setup();
    let other = module
        .create_policy(
            &first,
            "name: other\nresources:\n  - name: file\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    let generated = module
        .query_generate_commitment(&policy, &[object], &Actor(second.clone()))
        .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = module
        .direct_policy_cmd(
            &second,
            &other,
            PolicyCmd::CommitRegistrations {
                commitment: generated.commitment,
            },
        )
        .unwrap()
    else {
        panic!("expected commitment")
    };
    let before = module.store.serialize();
    let error = module
        .direct_policy_cmd(
            &second,
            &policy,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: registrations_commitment.id,
                proof: generated.proofs[0].clone(),
            },
        )
        .unwrap_err();
    assert!(matches!(error, AcpError::InvalidProof { .. }));
    assert_eq!(module.store.serialize(), before);
}

fn execute(
    module: &mut AcpModule,
    actor: &Did,
    policy: &str,
    command: PolicyCmd,
    height: u64,
) -> Result<PolicyCmdResult> {
    module.execute_policy_cmd(
        actor,
        policy,
        command,
        &BlockExecCtx {
            genesis_id: [1; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                block_height: height,
                seconds: height + 100,
            },
        },
        &TxExecCtx {
            signer: actor.to_string(),
            tx_hash: vec![height as u8; 32],
            sequence: height,
        },
    )
}

#[test]
fn registration_priority_uses_committed_revisions_and_survives_amendment() {
    let (mut module, first, second, policy, object) = setup();
    let generated = module
        .query_generate_commitment(
            &policy,
            std::slice::from_ref(&object),
            &Actor(second.clone()),
        )
        .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment: early,
    } = execute(
        &mut module,
        &second,
        &policy,
        PolicyCmd::CommitRegistrations {
            commitment: generated.commitment.clone(),
        },
        10,
    )
    .unwrap()
    else {
        panic!("expected commitment")
    };
    execute(
        &mut module,
        &first,
        &policy,
        PolicyCmd::RegisterObject(object.clone()),
        20,
    )
    .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment: late,
    } = execute(
        &mut module,
        &second,
        &policy,
        PolicyCmd::CommitRegistrations {
            commitment: generated.commitment,
        },
        30,
    )
    .unwrap()
    else {
        panic!("expected commitment")
    };
    let before = module.store.serialize();
    assert!(matches!(
        execute(
            &mut module,
            &second,
            &policy,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: late.id,
                proof: generated.proofs[0].clone(),
            },
            31
        ),
        Err(AcpError::InvalidProof { .. })
    ));
    assert_eq!(module.store.serialize(), before);
    let PolicyCmdResult::RevealRegistration { record, event } = execute(
        &mut module,
        &second,
        &policy,
        PolicyCmd::RevealRegistration {
            registrations_commitment_id: early.id,
            proof: generated.proofs[0].clone(),
        },
        32,
    )
    .unwrap() else {
        panic!("expected amendment")
    };
    assert_eq!(record.metadata.creation_ts.block_height, 10);
    assert_eq!(record.metadata.tx_hash, vec![32; 32]);
    assert_eq!(event.metadata.creation_ts.block_height, 32);
    assert_eq!(
        module
            .query_object_owner(&policy, &object)
            .unwrap()
            .1
            .unwrap()
            .metadata
            .creation_ts
            .block_height,
        10
    );
    let before = module.store.serialize();
    assert!(
        execute(
            &mut module,
            &second,
            &policy,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: late.id,
                proof: generated.proofs[0].clone(),
            },
            33
        )
        .is_err()
    );
    assert_eq!(module.store.serialize(), before);
}

#[test]
fn registration_leaf_binds_object_field_boundaries() {
    let (mut module, first, second, _, _) = setup();
    let policy = module
        .create_policy(
            &first,
            "name: boundaries\nresources:\n  - name: a\n  - name: ab\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    let object = Object {
        resource: "a".into(),
        id: "bc".into(),
    };
    let generated = module
        .query_generate_commitment(&policy, &[object], &Actor(second.clone()))
        .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = execute(
        &mut module,
        &second,
        &policy,
        PolicyCmd::CommitRegistrations {
            commitment: generated.commitment,
        },
        10,
    )
    .unwrap()
    else {
        panic!("expected commitment")
    };
    let mut substituted = generated.proofs[0].clone();
    substituted.object = Object {
        resource: "ab".into(),
        id: "c".into(),
    };
    let before = module.store.serialize();
    assert!(matches!(
        execute(
            &mut module,
            &second,
            &policy,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: registrations_commitment.id,
                proof: substituted,
            },
            11
        ),
        Err(AcpError::InvalidProof { .. })
    ));
    assert_eq!(module.store.serialize(), before);
    execute(
        &mut module,
        &second,
        &policy,
        PolicyCmd::RevealRegistration {
            registrations_commitment_id: registrations_commitment.id,
            proof: generated.proofs[0].clone(),
        },
        11,
    )
    .unwrap();
}

#[test]
fn registration_proofs_support_odd_trees_and_reject_invalid_shapes() {
    let (module, _, actor, policy, _) = setup();
    for count in [1, 2, 3, 5, 6] {
        let objects: Vec<_> = (0..count)
            .map(|index| Object {
                resource: "file".into(),
                id: index.to_string(),
            })
            .collect();
        let generated = module
            .query_generate_commitment(&policy, &objects, &Actor(actor.clone()))
            .unwrap();
        for proof in &generated.proofs {
            let leaf =
                AcpModule::registration_leaf(&policy, &proof.object, actor.as_str()).unwrap();
            assert!(AcpModule::verify_merkle_proof(
                &generated.commitment,
                proof,
                &leaf
            ));
            let mut bad = proof.clone();
            bad.leaf_count = 0;
            assert!(!AcpModule::verify_merkle_proof(
                &generated.commitment,
                &bad,
                &leaf
            ));
            bad = proof.clone();
            bad.leaf_index = bad.leaf_count;
            assert!(!AcpModule::verify_merkle_proof(
                &generated.commitment,
                &bad,
                &leaf
            ));
            bad = proof.clone();
            bad.merkle_proof.push(vec![0; 32]);
            assert!(!AcpModule::verify_merkle_proof(
                &generated.commitment,
                &bad,
                &leaf
            ));
        }
    }
}

#[test]
fn default_commitment_expires_after_ten_minutes() {
    let (mut module, actor, _, policy, _) = setup();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = execute(
        &mut module,
        &actor,
        &policy,
        PolicyCmd::CommitRegistrations {
            commitment: vec![1; 32],
        },
        10,
    )
    .unwrap()
    else {
        panic!("expected commitment")
    };
    let mut context = BlockExecCtx {
        genesis_id: [1; 32],
        deployment_id: 9001,
        timestamp: Timestamp {
            block_height: 11,
            seconds: 710,
        },
    };
    assert!(module.end_blocker(&context).unwrap().is_empty());
    context.timestamp.seconds += 1;
    let expired = module.end_blocker(&context).unwrap();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].id, registrations_commitment.id);
    assert!(expired[0].expired);
}

#[test]
fn reveal_checks_deadline_without_waiting_for_cleanup() {
    for validity in [Duration::Seconds(600), Duration::Blocks(600)] {
        let (mut module, actor, _, policy, object) = setup();
        module
            .set_params(&AcpParams {
                registrations_commitment_validity: validity,
                ..AcpParams::default()
            })
            .unwrap();
        let generated = module
            .query_generate_commitment(&policy, &[object], &Actor(actor.clone()))
            .unwrap();
        let PolicyCmdResult::CommitRegistrations {
            registrations_commitment,
        } = execute(
            &mut module,
            &actor,
            &policy,
            PolicyCmd::CommitRegistrations {
                commitment: generated.commitment,
            },
            10,
        )
        .unwrap()
        else {
            panic!("expected commitment")
        };
        let reveal = PolicyCmd::RevealRegistration {
            registrations_commitment_id: registrations_commitment.id,
            proof: generated.proofs[0].clone(),
        };
        let before = module.store.serialize();
        assert!(matches!(
            execute(&mut module, &actor, &policy, reveal.clone(), 611),
            Err(AcpError::CommitmentExpired { .. })
        ));
        assert_eq!(module.store.serialize(), before);
        execute(&mut module, &actor, &policy, reveal, 610).unwrap();
    }
}

#[test]
fn corrupt_policy_and_relationship_records_cannot_authorize_or_be_overwritten() {
    let (mut module, first, second, policy, object) = setup();
    module
        .direct_policy_cmd(&second, &policy, PolicyCmd::RegisterObject(object))
        .unwrap();
    let grant = Relationship::with_entity("file", "report", "reader", first.clone());
    let policy_key = keys::policy_key(&policy);
    let policy_bytes = module.store.get(&policy_key).unwrap();
    for invalid in [b"{".to_vec(), {
        let mut record: PolicyRecord = serde_json::from_slice(&policy_bytes).unwrap();
        record.policy.id = "other".into();
        serde_json::to_vec(&record).unwrap()
    }] {
        module.store.put(&policy_key, invalid);
        let before = module.store.serialize();
        assert!(matches!(
            module.query_policy(&policy),
            Err(AcpError::State(_))
        ));
        assert!(matches!(
            module.edit_policy(&first, &policy, "", PolicyMarshalingType::ShortYaml),
            Err(AcpError::State(_))
        ));
        assert!(matches!(
            module.direct_policy_cmd(&second, &policy, PolicyCmd::SetRelationship(grant.clone())),
            Err(AcpError::State(_))
        ));
        assert_eq!(module.store.serialize(), before);
    }
    module.store.put(&policy_key, policy_bytes);
    let owner = Relationship::with_entity("file", "report", "owner", second.clone());
    let owner_key = keys::relationship_key(&policy, &owner.storage_key());
    let owner_bytes = module.store.get(&owner_key).unwrap();
    module.store.put(&owner_key, b"{".to_vec());
    let before = module.store.serialize();
    assert!(matches!(
        module.direct_policy_cmd(&second, &policy, PolicyCmd::SetRelationship(grant.clone())),
        Err(AcpError::State(_))
    ));
    assert_eq!(module.store.serialize(), before);
    module.store.put(&owner_key, owner_bytes.clone());
    let grant_key = keys::relationship_key(&policy, &grant.storage_key());
    for invalid in [b"{".to_vec(), owner_bytes] {
        module.store.put(&grant_key, invalid);
        let before = module.store.serialize();
        for command in [
            PolicyCmd::SetRelationship(grant.clone()),
            PolicyCmd::DeleteRelationship(grant.clone()),
        ] {
            assert!(matches!(
                module.direct_policy_cmd(&first, &policy, command),
                Err(AcpError::State(_))
            ));
            assert_eq!(module.store.serialize(), before);
        }
    }
}
