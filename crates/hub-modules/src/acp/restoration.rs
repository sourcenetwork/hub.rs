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
        self.validate_counter(
            keys::POLICY_COUNTER_KEY,
            self.zanzibar_policies.len() as u64,
        )?;
        for (prefix, counter_key) in [
            (
                [keys::COMMITMENT_PREFIX, keys::OBJS_SUBPREFIX].concat(),
                keys::commitment_counter_key(),
            ),
            (
                Self::amendment_event_objs_prefix(),
                keys::amendment_event_counter_key(),
            ),
        ] {
            let mut maximum = 0;
            for (key, _) in self.store.prefix_iter(&prefix) {
                let id =
                    u64::from_be_bytes(key[prefix.len()..].try_into().map_err(|_| {
                        AcpError::State("invalid indexed record identifier".into())
                    })?);
                if id == 0 {
                    return Err(AcpError::State("zero indexed record identifier".into()));
                }
                maximum = maximum.max(id);
            }
            self.validate_counter(&counter_key, maximum)?;
        }
        self.validate_amendment_indexes()
    }

    fn validate_counter(&self, key: &[u8], minimum: u64) -> Result<()> {
        let counter = self
            .store
            .get_ref(key)
            .map(|bytes| {
                bytes
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| AcpError::State("invalid restored record counter".into()))
            })
            .transpose()?
            .unwrap_or(0);
        if counter < minimum {
            return Err(AcpError::State(
                "restored record counter precedes retained records".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_counters_cannot_reuse_retained_identifiers() {
        let mut module = AcpModule::new();
        let actor = Did::new("did:key:owner").unwrap();
        let definition = "name: counter\nresources:\n  - name: file\n";
        let policy = module
            .create_policy(&actor, definition, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .policy
            .id;
        let PolicyCmdResult::CommitRegistrations {
            registrations_commitment: mut commitment,
        } = module
            .direct_policy_cmd(
                &actor,
                &policy,
                PolicyCmd::CommitRegistrations {
                    commitment: vec![7; 32],
                },
            )
            .unwrap()
        else {
            panic!("expected commitment")
        };
        let mut event = AmendmentEvent {
            id: 0,
            policy_id: policy,
            object: Object {
                resource: "file".into(),
                id: "report".into(),
            },
            new_owner: Actor(actor.clone()),
            previous_owner: Actor(Did::new("did:key:previous").unwrap()),
            commitment_id: commitment.id,
            hijack_flag: false,
            metadata: commitment.metadata.clone(),
        };
        module.create_amendment_event(&mut event).unwrap();
        module.validate_restored_state().unwrap();
        let original = module.store.clone();
        for key in [
            keys::POLICY_COUNTER_KEY.to_vec(),
            keys::commitment_counter_key(),
            keys::amendment_event_counter_key(),
        ] {
            for invalid in [None, Some(vec![0; 8]), Some(vec![1; 7])] {
                let mut store = original.clone();
                match invalid {
                    None => store.delete(&key),
                    Some(bytes) => store.put(&key, bytes),
                }
                assert!(
                    AcpModule::from_store(store)
                        .validate_restored_state()
                        .is_err()
                );
            }
            module.store.delete(&key);
        }
        let before = module.store.serialize();
        assert!(
            module
                .create_policy(&actor, definition, PolicyMarshalingType::ShortYaml)
                .is_err()
        );
        assert_eq!(module.store.serialize(), before);
        assert!(module.create_commitment(&mut commitment).is_err());
        assert_eq!(module.store.serialize(), before);
        assert!(module.create_amendment_event(&mut event).is_err());
        assert_eq!(module.store.serialize(), before);
    }

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
