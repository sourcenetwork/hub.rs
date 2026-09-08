//! Ownership and revocation cases from Vera 205df1ad (acp_core v0.8.2).
//! Reference: https://github.com/sourcenetwork/vera/tree/205df1ad/tests/integration/acp/suite

use acp::Relationship;
use hub_modules::{
    acp::{
        AcpModule,
        error::AcpError,
        types::{
            AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyCmdResult,
            PolicyMarshalingType,
        },
    },
    kv_store::InMemoryKvStore,
};
use identity::Did;

const POLICY: &str = r#"
name: documents
resources:
  - name: file
    relations:
      - name: reader
        types: [actor]
      - name: writer
        types: [actor]
      - name: admin
        types: [actor]
        manages: [reader]
    permissions:
      - name: read
        expr: reader
"#;

fn owner() -> Did {
    Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap()
}

fn reader() -> Did {
    Did::new("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").unwrap()
}

fn object() -> Object {
    Object {
        resource: "file".into(),
        id: "report".into(),
    }
}

fn restore(module: &AcpModule) -> AcpModule {
    AcpModule::from_store(InMemoryKvStore::deserialize(&module.store().serialize()).unwrap())
}

fn setup() -> (AcpModule, String) {
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(&owner(), POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap();
    module
        .direct_policy_cmd(
            &owner(),
            &policy.policy.id,
            PolicyCmd::RegisterObject(object()),
        )
        .unwrap();
    (module, policy.policy.id)
}

fn can_read(module: &AcpModule, policy_id: &str) -> bool {
    module
        .query_verify_access_request(
            policy_id,
            &AccessRequest {
                actor: Actor(reader()),
                operations: vec![Operation {
                    object: object(),
                    permission: "read".into(),
                }],
            },
        )
        .unwrap()
}

#[test]
fn archived_objects_remain_reserved_after_restore() {
    let (mut module, policy_id) = setup();
    module
        .direct_policy_cmd(&owner(), &policy_id, PolicyCmd::ArchiveObject(object()))
        .unwrap();

    for mut candidate in [module.clone(), restore(&module)] {
        for actor in [owner(), reader()] {
            let before = candidate.store().serialize();
            let result = candidate.direct_policy_cmd(
                &actor,
                &policy_id,
                PolicyCmd::RegisterObject(object()),
            );
            assert!(
                matches!(result, Err(AcpError::ObjectAlreadyRegistered { .. })),
                "{result:?}"
            );
            assert_eq!(candidate.store().serialize(), before);
        }
        assert!(
            candidate
                .direct_policy_cmd(&reader(), &policy_id, PolicyCmd::UnarchiveObject(object()))
                .is_err()
        );
        candidate
            .direct_policy_cmd(&owner(), &policy_id, PolicyCmd::UnarchiveObject(object()))
            .unwrap();
        let (registered, record) = candidate.query_object_owner(&policy_id, &object()).unwrap();
        assert!(registered);
        assert_eq!(record.unwrap().metadata.owner_did, owner().to_string());
    }
}

#[test]
fn revocation_survives_restore_and_stays_within_its_policy() {
    let (mut module, policy_id) = setup();
    let other_policy = module
        .create_policy(&owner(), POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    module
        .direct_policy_cmd(&owner(), &other_policy, PolicyCmd::RegisterObject(object()))
        .unwrap();
    let grant = Relationship::with_entity("file", "report", "reader", reader());
    for id in [&policy_id, &other_policy] {
        module
            .direct_policy_cmd(&owner(), id, PolicyCmd::SetRelationship(grant.clone()))
            .unwrap();
        assert!(can_read(&module, id));
    }

    let before = module.store().serialize();
    assert!(matches!(
        module.direct_policy_cmd(
            &reader(),
            &policy_id,
            PolicyCmd::DeleteRelationship(grant.clone())
        ),
        Err(AcpError::Unauthorized { .. })
    ));
    assert_eq!(module.store().serialize(), before);
    module
        .direct_policy_cmd(&owner(), &policy_id, PolicyCmd::DeleteRelationship(grant))
        .unwrap();

    for candidate in [module.clone(), restore(&module)] {
        assert!(!can_read(&candidate, &policy_id));
        assert!(can_read(&candidate, &other_policy));
    }
}

#[test]
fn delegated_management_is_limited_to_declared_relations() {
    let (mut module, policy_id) = setup();
    for relation in ["reader", "writer", "admin"] {
        module
            .direct_policy_cmd(
                &owner(),
                &policy_id,
                PolicyCmd::SetRelationship(Relationship::with_entity(
                    "file",
                    "report",
                    relation,
                    reader(),
                )),
            )
            .unwrap();
    }
    let mut module = restore(&module);
    let before = module.store().serialize();
    assert!(matches!(
        module.direct_policy_cmd(
            &reader(),
            &policy_id,
            PolicyCmd::DeleteRelationship(Relationship::with_entity(
                "file",
                "report",
                "writer",
                reader()
            ))
        ),
        Err(AcpError::Unauthorized { .. })
    ));
    assert_eq!(module.store().serialize(), before);
    module
        .direct_policy_cmd(
            &reader(),
            &policy_id,
            PolicyCmd::DeleteRelationship(Relationship::with_entity(
                "file",
                "report",
                "reader",
                reader(),
            )),
        )
        .unwrap();
    assert!(!can_read(&module, &policy_id));
}

#[test]
fn commitment_opening_cannot_reactivate_an_archived_object() {
    let mut module = AcpModule::new();
    let policy_id = module
        .create_policy(&owner(), POLICY, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    let opening = module
        .query_generate_commitment(&policy_id, &[object()], &Actor(reader()))
        .unwrap();
    let result = module
        .direct_policy_cmd(
            &reader(),
            &policy_id,
            PolicyCmd::CommitRegistrations {
                commitment: opening.commitment,
            },
        )
        .unwrap();
    let PolicyCmdResult::CommitRegistrations {
        registrations_commitment,
    } = result
    else {
        panic!("unexpected result: {result:?}");
    };
    module
        .direct_policy_cmd(&owner(), &policy_id, PolicyCmd::RegisterObject(object()))
        .unwrap();
    module
        .direct_policy_cmd(&owner(), &policy_id, PolicyCmd::ArchiveObject(object()))
        .unwrap();

    for mut candidate in [module.clone(), restore(&module)] {
        let before = candidate.store().serialize();
        assert!(matches!(
            candidate.query_generate_commitment(&policy_id, &[object()], &Actor(reader())),
            Err(AcpError::ObjectAlreadyRegistered { .. })
        ));
        let result = candidate.direct_policy_cmd(
            &reader(),
            &policy_id,
            PolicyCmd::RevealRegistration {
                registrations_commitment_id: registrations_commitment.id,
                proof: opening.proofs[0].clone(),
            },
        );
        assert!(
            matches!(result, Err(AcpError::ObjectAlreadyRegistered { .. })),
            "{result:?}"
        );
        assert_eq!(candidate.store().serialize(), before);
    }
}

#[test]
fn policy_edits_preserve_defra_specification_across_restore() {
    let definition = "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n      - name: writer\n    permissions:\n      - name: read\n        expr: reader\n      - name: write\n        expr: writer\n";
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(
            &owner(),
            &format!("spec: defra\n{definition}"),
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    module
        .direct_policy_cmd(&owner(), &policy, PolicyCmd::RegisterObject(object()))
        .unwrap();
    module
        .direct_policy_cmd(
            &owner(),
            &policy,
            PolicyCmd::SetRelationship(Relationship::with_entity(
                "file",
                "report",
                "writer",
                reader(),
            )),
        )
        .unwrap();
    assert!(can_read(&module, &policy));

    for spec in ["", "spec: none\n", "spec: defra\n"] {
        module = restore(&module);
        module
            .edit_policy(
                &owner(),
                &policy,
                &format!("{spec}{definition}"),
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap();
        assert!(can_read(&module, &policy));
        assert!(can_read(&restore(&module), &policy));
        let before = module.store().serialize();
        let invalid = definition.replace("      - name: write\n        expr: writer\n", "");
        assert!(
            module
                .edit_policy(&owner(), &policy, &invalid, PolicyMarshalingType::ShortYaml)
                .is_err()
        );
        assert_eq!(module.store().serialize(), before);
    }
}
