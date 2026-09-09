use super::*;

const MAX_RECORDS: usize = 128;
const MAX_BYTES: usize = 1 << 20;

impl AcpModule {
    /// Filter a bounded policy prefix; invalid records and incomplete results are errors.
    pub fn query_filter_relationships(
        &self,
        policy_id: &str,
        selector: &RelationshipSelector,
    ) -> Result<Vec<RelationshipRecord>> {
        let mut records = Vec::new();
        let mut bytes = 0usize;
        for (count, (key, value)) in self
            .store
            .prefix_iter(&keys::relationship_policy_prefix(policy_id))
            .enumerate()
        {
            bytes = bytes.saturating_add(key.len()).saturating_add(value.len());
            if count >= MAX_RECORDS || bytes > MAX_BYTES {
                return Err(AcpError::State("relationship query budget exceeded".into()));
            }
            let record: RelationshipRecord = serde_json::from_slice(value)
                .map_err(|e| AcpError::State(format!("invalid relationship record: {e}")))?;
            if record.policy_id != policy_id
                || keys::relationship_key(policy_id, &record.relationship.storage_key()) != key
            {
                return Err(AcpError::State(
                    "relationship record identity mismatch".into(),
                ));
            }
            if self.matches_selector(&record, selector) {
                records.push(record);
            }
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selector() -> RelationshipSelector {
        RelationshipSelector {
            object_selector: None,
            relation_selector: None,
            subject_selector: None,
        }
    }

    fn insert(module: &mut AcpModule, policy: &str, id: &str) -> Vec<u8> {
        let owner = Did::new("did:key:owner").unwrap();
        let record = RelationshipRecord {
            policy_id: policy.into(),
            relationship: Relationship::with_entity("file", id, "owner", owner),
            archived: false,
            metadata: RecordMetadata {
                creation_ts: Timestamp::default(),
                tx_hash: vec![],
                tx_signer: "worker".into(),
                owner_did: "did:key:owner".into(),
            },
        };
        let key = keys::relationship_key(policy, &record.relationship.storage_key());
        module.store.put(&key, serde_json::to_vec(&record).unwrap());
        key
    }

    #[test]
    fn relationship_query_bounds_inspected_records_before_filtering() {
        let mut module = AcpModule::new();
        for i in 0..1000 {
            insert(&mut module, "other", &i.to_string());
        }
        for i in 0..MAX_RECORDS {
            insert(&mut module, "selected", &i.to_string());
        }
        assert_eq!(
            module
                .query_filter_relationships("selected", &selector())
                .unwrap()
                .len(),
            MAX_RECORDS
        );
        let mut excluded = selector();
        excluded.relation_selector = Some(RelationSelector::Exact("reader".into()));
        assert!(
            module
                .query_filter_relationships("selected", &excluded)
                .unwrap()
                .is_empty()
        );
        insert(&mut module, "selected", "overflow");
        assert!(
            module
                .query_filter_relationships("selected", &excluded)
                .is_err()
        );
    }

    #[test]
    fn relationship_query_rejects_corruption_and_oversized_records() {
        let mut module = AcpModule::new();
        let key = insert(&mut module, "selected", "report");
        let valid = module.store.get(&key).unwrap();
        let mut excluded = selector();
        excluded.relation_selector = Some(RelationSelector::Exact("reader".into()));
        module.store.put(&key, valid[..valid.len() - 1].to_vec());
        assert!(
            module
                .query_filter_relationships("selected", &excluded)
                .is_err()
        );
        let mut record: RelationshipRecord = serde_json::from_slice(&valid).unwrap();
        record.policy_id = "other".into();
        module.store.put(&key, serde_json::to_vec(&record).unwrap());
        assert!(
            module
                .query_filter_relationships("selected", &excluded)
                .is_err()
        );
        record.policy_id = "selected".into();
        record.relationship.object_id = "another".into();
        module.store.put(&key, serde_json::to_vec(&record).unwrap());
        assert!(
            module
                .query_filter_relationships("selected", &excluded)
                .is_err()
        );
        module.store.put(&key, vec![b' '; MAX_BYTES]);
        assert!(
            module
                .query_filter_relationships("selected", &excluded)
                .is_err()
        );
    }
}
