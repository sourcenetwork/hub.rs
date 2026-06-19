//! A [`ZanzibarStore`] backed by hub's module KV store.

use std::sync::RwLock;

use async_trait::async_trait;
use identity::Did;
use zanzibar::error::Result;
use zanzibar::{ObjectRef, Policy, Relationship, Subject, ZanzibarStore};

use super::keys;
use super::types::{PolicyMarshalingType, PolicyRecord, RecordMetadata, RelationshipRecord};
use crate::kv_store::{InMemoryKvStore, ModuleKvStore};
use crate::types::Timestamp;

/// A [`ZanzibarStore`] adapter over hub's module KV store.
///
/// Maps the zanzibar engine's storage interface onto hub's existing
/// `relationship/{policy_id}/{storage_key}` and `policy/objs/{id}` keyspace, so
/// [`zanzibar::PermissionEngine`] can evaluate permissions (including
/// `TupleToUserset`) directly over committed module state instead of a
/// divergent bespoke evaluator.
///
/// Relationship reads honor the `archived` flag: an archived record is treated
/// as absent, matching hub's access-check semantics.
#[derive(Debug, Default)]
pub struct QmdbZanzibarStore<S: ModuleKvStore = InMemoryKvStore> {
    store: RwLock<S>,
}

impl<S: ModuleKvStore> QmdbZanzibarStore<S> {
    /// Wrap a module KV store.
    pub const fn new(store: S) -> Self {
        Self {
            store: RwLock::new(store),
        }
    }

    /// Live (non-archived) relationship records under a `storage_key` prefix.
    fn live_records(&self, policy_id: &str, storage_prefix: &str) -> Vec<RelationshipRecord> {
        let scan = keys::relationship_storage_prefix(policy_id, storage_prefix);
        self.store
            .read()
            .unwrap()
            .prefix_scan(&scan)
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice::<RelationshipRecord>(&v).ok())
            .filter(|rec| !rec.archived)
            .collect()
    }

    /// Whether a specific relationship exists and is live.
    fn is_live(&self, policy_id: &str, rel: &Relationship) -> bool {
        self.store
            .read()
            .unwrap()
            .get(&keys::relationship_key(policy_id, &rel.storage_key()))
            .and_then(|bytes| serde_json::from_slice::<RelationshipRecord>(&bytes).ok())
            .is_some_and(|rec| !rec.archived)
    }
}

fn default_metadata() -> RecordMetadata {
    RecordMetadata {
        creation_ts: Timestamp::default(),
        tx_hash: Vec::new(),
        tx_signer: String::new(),
        owner_did: String::new(),
    }
}

#[async_trait]
impl<S: ModuleKvStore> ZanzibarStore for QmdbZanzibarStore<S> {
    async fn store_policy(&self, policy: &Policy) -> Result<()> {
        let record = PolicyRecord {
            policy: policy.clone(),
            raw_policy: String::new(),
            marshal_type: PolicyMarshalingType::ShortYaml,
            metadata: default_metadata(),
        };
        let bytes = serde_json::to_vec(&record).expect("serialize PolicyRecord");
        self.store
            .write()
            .unwrap()
            .put(&keys::policy_key(&policy.id), bytes);
        Ok(())
    }

    async fn get_policy(&self, policy_id: &str) -> Result<Option<Policy>> {
        Ok(self
            .store
            .read()
            .unwrap()
            .get(&keys::policy_key(policy_id))
            .and_then(|bytes| serde_json::from_slice::<PolicyRecord>(&bytes).ok())
            .map(|record| record.policy))
    }

    async fn list_policies(&self) -> Result<Vec<Policy>> {
        Ok(self
            .store
            .read()
            .unwrap()
            .prefix_scan(keys::POLICY_PREFIX)
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice::<PolicyRecord>(&v).ok())
            .map(|record| record.policy)
            .collect())
    }

    async fn delete_policy(&self, policy_id: &str) -> Result<bool> {
        let mut guard = self.store.write().unwrap();
        let policy_key = keys::policy_key(policy_id);
        if !guard.has(&policy_key) {
            return Ok(false);
        }
        guard.delete(&policy_key);
        let rel_keys: Vec<_> = guard
            .prefix_scan(&keys::relationship_policy_prefix(policy_id))
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        for key in rel_keys {
            guard.delete(&key);
        }
        Ok(true)
    }

    async fn store_relationship(&self, policy_id: &str, rel: &Relationship) -> Result<()> {
        let record = RelationshipRecord {
            policy_id: policy_id.to_string(),
            relationship: rel.clone(),
            archived: false,
            metadata: default_metadata(),
        };
        let bytes = serde_json::to_vec(&record).expect("serialize RelationshipRecord");
        self.store.write().unwrap().put(
            &keys::relationship_key(policy_id, &rel.storage_key()),
            bytes,
        );
        Ok(())
    }

    async fn delete_relationship(&self, policy_id: &str, rel: &Relationship) -> Result<bool> {
        let key = keys::relationship_key(policy_id, &rel.storage_key());
        let mut guard = self.store.write().unwrap();
        if guard.has(&key) {
            guard.delete(&key);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn has_relationship(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject: &Subject,
    ) -> Result<bool> {
        let rel = Relationship::new(resource, object_id, relation, subject.clone());
        Ok(self.is_live(policy_id, &rel))
    }

    async fn check_permission_direct(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject: &Did,
    ) -> Result<bool> {
        let direct = Relationship::with_entity(resource, object_id, relation, subject.clone());
        if self.is_live(policy_id, &direct) {
            return Ok(true);
        }
        let wildcard = Relationship::new(resource, object_id, relation, Subject::Wildcard);
        if self.is_live(policy_id, &wildcard) {
            return Ok(true);
        }
        // Any typed wildcard on this object#relation grants every subject.
        let prefix = Relationship::relation_prefix(resource, object_id, relation);
        Ok(self
            .live_records(policy_id, &prefix)
            .iter()
            .any(|rec| rec.relationship.subject.is_typed_wildcard()))
    }

    async fn get_relation_subjects(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<Vec<Subject>> {
        let prefix = Relationship::relation_prefix(resource, object_id, relation);
        Ok(self
            .live_records(policy_id, &prefix)
            .into_iter()
            .map(|rec| rec.relationship.subject)
            .collect())
    }

    async fn get_relation_targets(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<Vec<ObjectRef>> {
        let prefix = Relationship::relation_prefix(resource, object_id, relation);
        Ok(self
            .live_records(policy_id, &prefix)
            .into_iter()
            .filter_map(|rec| match rec.relationship.subject {
                Subject::EntitySet {
                    resource,
                    object_id,
                    ..
                } => Some(ObjectRef::new(resource, object_id)),
                _ => None,
            })
            .collect())
    }

    async fn delete_object_relationships(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
    ) -> Result<()> {
        let prefix = keys::relationship_storage_prefix(
            policy_id,
            &Relationship::object_prefix(resource, object_id),
        );
        let mut guard = self.store.write().unwrap();
        let keys_to_delete: Vec<_> = guard
            .prefix_scan(&prefix)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        for key in keys_to_delete {
            guard.delete(&key);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures::executor::block_on;
    use zanzibar::{PermissionEngine, Relation, RelationExpression, Resource};

    use super::*;

    const POLICY: &str = "policy-1";

    fn did(s: &str) -> Did {
        Did::new(s).expect("valid did")
    }

    /// Seed a relationship record directly into the kv store under hub's keyspace.
    fn seed(store: &mut InMemoryKvStore, rel: &Relationship, archived: bool) {
        let record = RelationshipRecord {
            policy_id: POLICY.to_string(),
            relationship: rel.clone(),
            archived,
            metadata: default_metadata(),
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        store.put(&keys::relationship_key(POLICY, &rel.storage_key()), bytes);
    }

    #[test]
    fn get_relation_subjects_returns_live_subjects_for_object_relation() {
        let mut kv = InMemoryKvStore::default();
        let entity = Relationship::with_entity(
            "document",
            "doc1",
            "reader",
            did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
        );
        let parent = Relationship::new(
            "document",
            "doc1",
            "reader",
            Subject::entity_set("collection", "col1", "reader"),
        );
        // Unrelated: same relation on a different object must not leak in.
        let other = Relationship::with_entity(
            "document",
            "doc2",
            "reader",
            did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
        );
        seed(&mut kv, &entity, false);
        seed(&mut kv, &parent, false);
        seed(&mut kv, &other, false);

        let store = QmdbZanzibarStore::new(kv);
        let subjects =
            block_on(store.get_relation_subjects(POLICY, "document", "doc1", "reader")).unwrap();

        assert_eq!(
            subjects.len(),
            2,
            "should return both subjects on doc1#reader"
        );
        assert!(subjects.contains(&entity.subject));
        assert!(subjects.contains(&parent.subject));
    }

    #[test]
    fn get_relation_subjects_excludes_archived() {
        let mut kv = InMemoryKvStore::default();
        let live = Relationship::with_entity(
            "document",
            "doc1",
            "reader",
            did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
        );
        let archived = Relationship::new(
            "document",
            "doc1",
            "reader",
            Subject::entity_set("collection", "col1", "reader"),
        );
        seed(&mut kv, &live, false);
        seed(&mut kv, &archived, true);

        let store = QmdbZanzibarStore::new(kv);
        let subjects =
            block_on(store.get_relation_subjects(POLICY, "document", "doc1", "reader")).unwrap();

        assert_eq!(subjects, vec![live.subject]);
    }

    #[test]
    fn get_relation_targets_returns_entityset_objectrefs_only() {
        let mut kv = InMemoryKvStore::default();
        let entity = Relationship::with_entity(
            "document",
            "doc1",
            "parent",
            did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
        );
        let parent = Relationship::new(
            "document",
            "doc1",
            "parent",
            Subject::entity_set("collection", "col1", "reader"),
        );
        seed(&mut kv, &entity, false);
        seed(&mut kv, &parent, false);

        let store = QmdbZanzibarStore::new(kv);
        let targets =
            block_on(store.get_relation_targets(POLICY, "document", "doc1", "parent")).unwrap();

        assert_eq!(targets, vec![ObjectRef::new("collection", "col1")]);
    }

    const ALICE: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    #[test]
    fn check_permission_direct_matches_entity_grant() {
        let mut kv = InMemoryKvStore::default();
        seed(
            &mut kv,
            &Relationship::with_entity("document", "doc1", "reader", did(ALICE)),
            false,
        );
        let store = QmdbZanzibarStore::new(kv);

        assert!(
            block_on(store.check_permission_direct(
                POLICY,
                "document",
                "doc1",
                "reader",
                &did(ALICE)
            ))
            .unwrap()
        );
        assert!(
            !block_on(store.check_permission_direct(
                POLICY,
                "document",
                "doc1",
                "writer",
                &did(ALICE)
            ))
            .unwrap(),
            "different relation must not match"
        );
    }

    #[test]
    fn check_permission_direct_matches_wildcard_and_typed_wildcard() {
        let mut wild = InMemoryKvStore::default();
        seed(
            &mut wild,
            &Relationship::new("document", "doc1", "reader", Subject::Wildcard),
            false,
        );
        let wstore = QmdbZanzibarStore::new(wild);
        assert!(
            block_on(wstore.check_permission_direct(
                POLICY,
                "document",
                "doc1",
                "reader",
                &did(ALICE)
            ))
            .unwrap(),
            "public wildcard grants everyone"
        );

        let mut typed = InMemoryKvStore::default();
        seed(
            &mut typed,
            &Relationship::new(
                "document",
                "doc1",
                "reader",
                Subject::typed_wildcard("document"),
            ),
            false,
        );
        let tstore = QmdbZanzibarStore::new(typed);
        assert!(
            block_on(tstore.check_permission_direct(
                POLICY,
                "document",
                "doc1",
                "reader",
                &did(ALICE)
            ))
            .unwrap(),
            "typed wildcard grants everyone"
        );
    }

    #[test]
    fn check_permission_direct_ignores_archived_grant() {
        let mut kv = InMemoryKvStore::default();
        seed(
            &mut kv,
            &Relationship::with_entity("document", "doc1", "reader", did(ALICE)),
            true,
        );
        let store = QmdbZanzibarStore::new(kv);

        assert!(
            !block_on(store.check_permission_direct(
                POLICY,
                "document",
                "doc1",
                "reader",
                &did(ALICE)
            ))
            .unwrap(),
            "archived grant must not authorize"
        );
    }

    #[test]
    fn has_relationship_reflects_presence_and_archival() {
        let mut kv = InMemoryKvStore::default();
        let live = Relationship::with_entity("document", "doc1", "reader", did(ALICE));
        let arch = Relationship::new(
            "document",
            "doc1",
            "reader",
            Subject::entity_set("collection", "col1", "reader"),
        );
        seed(&mut kv, &live, false);
        seed(&mut kv, &arch, true);
        let store = QmdbZanzibarStore::new(kv);

        assert!(
            block_on(store.has_relationship(POLICY, "document", "doc1", "reader", &live.subject))
                .unwrap()
        );
        assert!(
            !block_on(store.has_relationship(POLICY, "document", "doc1", "reader", &arch.subject))
                .unwrap(),
            "archived relationship reads as absent"
        );
        assert!(
            !block_on(store.has_relationship(
                POLICY,
                "document",
                "doc1",
                "reader",
                &Subject::Wildcard
            ))
            .unwrap(),
            "never-seeded subject reads as absent"
        );
    }

    #[test]
    fn policy_round_trips() {
        let store = QmdbZanzibarStore::<InMemoryKvStore>::default();
        let policy = Policy::new("pol-x", "test");

        block_on(store.store_policy(&policy)).unwrap();

        let got = block_on(store.get_policy("pol-x"))
            .unwrap()
            .expect("present");
        assert_eq!(got.id, "pol-x");
        assert!(block_on(store.get_policy("missing")).unwrap().is_none());

        let listed = block_on(store.list_policies()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "pol-x");
    }

    #[test]
    fn delete_policy_removes_policy_and_its_relationships() {
        let store = QmdbZanzibarStore::<InMemoryKvStore>::default();
        block_on(store.store_policy(&Policy::new(POLICY, "test"))).unwrap();
        block_on(store.store_relationship(
            POLICY,
            &Relationship::with_entity("document", "doc1", "reader", did(ALICE)),
        ))
        .unwrap();

        assert!(block_on(store.delete_policy(POLICY)).unwrap());
        assert!(block_on(store.get_policy(POLICY)).unwrap().is_none());
        assert!(
            block_on(store.get_relation_subjects(POLICY, "document", "doc1", "reader"))
                .unwrap()
                .is_empty(),
            "relationships must be removed with the policy"
        );
        assert!(
            !block_on(store.delete_policy(POLICY)).unwrap(),
            "deleting an absent policy returns false"
        );
    }

    #[test]
    fn store_and_delete_relationship_round_trip() {
        let store = QmdbZanzibarStore::<InMemoryKvStore>::default();
        let rel = Relationship::with_entity("document", "doc1", "reader", did(ALICE));

        block_on(store.store_relationship(POLICY, &rel)).unwrap();
        assert!(
            block_on(store.has_relationship(POLICY, "document", "doc1", "reader", &rel.subject))
                .unwrap()
        );

        assert!(block_on(store.delete_relationship(POLICY, &rel)).unwrap());
        assert!(
            !block_on(store.has_relationship(POLICY, "document", "doc1", "reader", &rel.subject))
                .unwrap()
        );
        assert!(
            !block_on(store.delete_relationship(POLICY, &rel)).unwrap(),
            "deleting an absent relationship returns false"
        );
    }

    #[test]
    fn delete_object_relationships_clears_only_that_object() {
        let store = QmdbZanzibarStore::<InMemoryKvStore>::default();
        block_on(store.store_relationship(
            POLICY,
            &Relationship::with_entity("document", "doc1", "reader", did(ALICE)),
        ))
        .unwrap();
        block_on(store.store_relationship(
            POLICY,
            &Relationship::with_entity("document", "doc1", "owner", did(ALICE)),
        ))
        .unwrap();
        let keep = Relationship::with_entity("document", "doc2", "reader", did(ALICE));
        block_on(store.store_relationship(POLICY, &keep)).unwrap();

        block_on(store.delete_object_relationships(POLICY, "document", "doc1")).unwrap();

        assert!(
            block_on(store.get_relation_subjects(POLICY, "document", "doc1", "reader"))
                .unwrap()
                .is_empty()
        );
        assert!(
            block_on(store.get_relation_subjects(POLICY, "document", "doc1", "owner"))
                .unwrap()
                .is_empty()
        );
        assert!(
            block_on(store.has_relationship(POLICY, "document", "doc2", "reader", &keep.subject))
                .unwrap(),
            "other objects are untouched"
        );
    }

    /// A policy where `document#read` inherits from `reader` on the document's
    /// parent collection: `read = parent->reader` (a cross-object TupleToUserset).
    fn ttu_policy(id: &str) -> Policy {
        Policy::new(id, "ttu")
            .with_resource(Resource::new("collection").with_relation(Relation::direct("reader")))
            .with_resource(
                Resource::new("document")
                    .with_relation(Relation::direct("parent"))
                    .with_relation(Relation::computed(
                        "read",
                        RelationExpression::tuple_to_userset("parent", "reader"),
                    )),
            )
    }

    #[test]
    fn engine_resolves_cross_object_tuple_to_userset() {
        let store = Arc::new(QmdbZanzibarStore::<InMemoryKvStore>::default());
        let pid = "ttu-policy";

        // Parent edge: doc1's parent is collection col1.
        block_on(store.store_relationship(
            pid,
            &Relationship::new(
                "document",
                "doc1",
                "parent",
                Subject::entity_set("collection", "col1", "reader"),
            ),
        ))
        .unwrap();
        // Grant on the parent: alice is a reader of col1.
        block_on(store.store_relationship(
            pid,
            &Relationship::with_entity("collection", "col1", "reader", did(ALICE)),
        ))
        .unwrap();

        let mut engine = PermissionEngine::new(store);
        engine.add_policy(&ttu_policy(pid));

        assert!(
            block_on(engine.check(pid, "document", "doc1", "read", &did(ALICE))).unwrap(),
            "alice inherits read on doc1 via reader on its parent collection"
        );
        assert!(
            !block_on(engine.check(pid, "document", "doc2", "read", &did(ALICE))).unwrap(),
            "doc2 has no parent edge, so nothing is inherited (fail closed)"
        );
    }

    #[test]
    fn engine_check_errors_on_unknown_policy_or_relation() {
        let store = Arc::new(QmdbZanzibarStore::<InMemoryKvStore>::default());
        let pid = "ttu-policy";
        let mut engine = PermissionEngine::new(store);
        engine.add_policy(&ttu_policy(pid));

        // Unknown policy and unknown relation both error — never silently allow.
        let unknown_policy =
            block_on(engine.check("nope", "document", "doc1", "read", &did(ALICE)));
        assert!(unknown_policy.is_err(), "unknown policy must error");
        assert!(
            !unknown_policy.unwrap_or(false),
            "error maps to deny, not allow"
        );

        let unknown_relation =
            block_on(engine.check(pid, "document", "doc1", "write", &did(ALICE)));
        assert!(unknown_relation.is_err(), "unknown relation must error");
        assert!(!unknown_relation.unwrap_or(false), "error maps to deny");
    }
}
