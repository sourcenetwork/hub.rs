use super::*;

impl AcpModule {
    /// Validate retained ACP records before publishing native recovery state.
    pub fn validate_restored_state(&self) -> Result<()> {
        for (key, _) in self.store.prefix_iter(keys::POLICY_PREFIX) {
            let id = std::str::from_utf8(&key[keys::POLICY_PREFIX.len()..])
                .map_err(|_| AcpError::State("invalid policy key".into()))?;
            self.get_policy_record(id)?;
        }
        for (key, bytes) in self.store.prefix_iter(keys::RELATIONSHIP_PREFIX) {
            let record: RelationshipRecord = serde_json::from_slice(bytes)
                .map_err(|e| AcpError::State(format!("invalid relationship record: {e}")))?;
            if keys::relationship_key(&record.policy_id, &record.relationship.storage_key()) != key
                || !self.zanzibar_policies.contains_key(&record.policy_id)
            {
                return Err(AcpError::State(
                    "relationship key or policy mismatch".into(),
                ));
            }
        }
        for (key, _) in self.store.prefix_iter(keys::ACCESS_DECISION_PREFIX) {
            let id = std::str::from_utf8(&key[keys::ACCESS_DECISION_PREFIX.len()..])
                .map_err(|_| AcpError::State("invalid access decision key".into()))?;
            self.get_access_decision(id)?;
        }
        self.get_params()?;
        self.validate_amendment_indexes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restoration_rejects_invalid_policy_relationship_decision_and_parameter_records() {
        let mut module = AcpModule::new();
        let owner = Did::new("did:key:owner").unwrap();
        let policy = module
            .create_policy(
                &owner,
                "name: restored\nresources:\n  - name: file\n",
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap()
            .policy
            .id;
        module
            .direct_policy_cmd(
                &owner,
                &policy,
                PolicyCmd::RegisterObject(Object {
                    resource: "file".into(),
                    id: "report".into(),
                }),
            )
            .unwrap();
        let original = module.store.clone();
        AcpModule::from_store(original.clone())
            .validate_restored_state()
            .unwrap();
        let policy_key = keys::policy_key(&policy);
        let owner_key = keys::relationship_key(
            &policy,
            &Relationship::with_entity("file", "report", "owner", owner).storage_key(),
        );
        for key in [&policy_key, &owner_key] {
            let bytes = original.get(key).unwrap();
            for length in 0..bytes.len() {
                let mut store = original.clone();
                store.put(key, bytes[..length].to_vec());
                assert!(
                    AcpModule::from_store(store)
                        .validate_restored_state()
                        .is_err()
                );
            }
            let mut store = original.clone();
            let mut alias = key.to_vec();
            alias.push(b'x');
            store.put(&alias, bytes);
            assert!(
                AcpModule::from_store(store)
                    .validate_restored_state()
                    .is_err()
            );
        }
        let mut orphan = original.clone();
        orphan.delete(&policy_key);
        assert!(
            AcpModule::from_store(orphan)
                .validate_restored_state()
                .is_err()
        );
        for key in [
            keys::PARAMS_KEY.to_vec(),
            keys::access_decision_key("invalid"),
        ] {
            let mut store = original.clone();
            store.put(&key, vec![0]);
            assert!(
                AcpModule::from_store(store)
                    .validate_restored_state()
                    .is_err()
            );
        }
        AcpModule::new().validate_restored_state().unwrap();
    }
}
