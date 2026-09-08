use crate::kv_store::ModuleKvStore;

use super::{
    BulletinModule, Result,
    error::BulletinError,
    keys,
    types::{BulletinParams, Collaborator, Namespace, Post},
};

fn decode<T: borsh::BorshDeserialize>(bytes: &[u8]) -> Result<T> {
    borsh::from_slice(bytes)
        .map_err(|e| BulletinError::State(format!("invalid bulletin record: {e}")))
}

impl BulletinModule {
    /// Reject malformed records and legacy keys before publishing restored native state.
    pub fn validate_storage_keys(&self) -> Result<()> {
        for prefix in [
            keys::NAMESPACE_PREFIX,
            keys::POST_PREFIX,
            keys::COLLABORATOR_PREFIX,
        ] {
            for (key, value) in self.store.prefix_iter(prefix) {
                let expected = if prefix == keys::POST_PREFIX {
                    let post: Post = decode(value)?;
                    keys::post_key(&post.namespace, &post.id)
                } else if prefix == keys::COLLABORATOR_PREFIX {
                    let collaborator: Collaborator = decode(value)?;
                    keys::collaborator_key(&collaborator.namespace, &collaborator.did)
                } else {
                    let namespace: Namespace = decode(value)?;
                    keys::namespace_key(&namespace.id)
                };
                if key != expected {
                    return Err(BulletinError::State(
                        "bulletin key does not match its record; explicit storage migration required".into(),
                    ));
                }
            }
        }
        if let Some(bytes) = self.store.get(keys::POLICY_ID_KEY) {
            let policy = std::str::from_utf8(&bytes)
                .map_err(|e| BulletinError::State(format!("invalid bulletin policy ID: {e}")))?;
            if policy.is_empty() {
                return Err(BulletinError::State("empty bulletin policy ID".into()));
            }
        }
        if let Some(bytes) = self.store.get(keys::PARAMS_KEY) {
            decode::<BulletinParams>(&bytes)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{kv_store::InMemoryKvStore, types::Timestamp};

    #[test]
    fn restored_keys_reject_legacy_aliases_without_rewriting_records() {
        for namespace in ["bulletin/a/b", "bulletin/a|b", "bulletin/a%7Cb"] {
            let post = Post {
                id: "id".into(),
                namespace: namespace.into(),
                creator_did: "owner".into(),
                payload: vec![1],
                proof: vec![2],
            };
            let collaborator = Collaborator {
                did: "reader".into(),
                namespace: namespace.into(),
            };
            for (prefix, id, value, current) in [
                (
                    keys::POST_PREFIX,
                    "id",
                    borsh::to_vec(&post).unwrap(),
                    keys::post_key(namespace, "id"),
                ),
                (
                    keys::COLLABORATOR_PREFIX,
                    "reader",
                    borsh::to_vec(&collaborator).unwrap(),
                    keys::collaborator_key(namespace, "reader"),
                ),
            ] {
                let module = BulletinModule::from_store(InMemoryKvStore::from_pairs(vec![(
                    current,
                    value.clone(),
                )]));
                module.validate_storage_keys().unwrap();
                let mut old_key = prefix.to_vec();
                old_key
                    .extend_from_slice(format!("{}/{id}", namespace.replace('/', "|")).as_bytes());
                let module =
                    BulletinModule::from_store(InMemoryKvStore::from_pairs(vec![(old_key, value)]));
                let before = module.store().serialize();
                assert_eq!(
                    module.validate_storage_keys().is_ok(),
                    !namespace.contains(['|', '%'])
                );
                assert_eq!(module.store().serialize(), before);
            }
        }
        let corrupt = BulletinModule::from_store(InMemoryKvStore::from_pairs(vec![(
            b"post/bad/id".to_vec(),
            vec![255; 8],
        )]));
        assert!(corrupt.validate_storage_keys().is_err());
    }

    #[test]
    fn restored_records_require_complete_encoding_and_matching_identity() {
        let namespace = Namespace {
            id: "bulletin/ns".into(),
            creator: "signer".into(),
            owner_did: "owner".into(),
            created_at: Timestamp {
                seconds: 1,
                block_height: 1,
            },
        };
        let post = Post {
            id: "id".into(),
            namespace: namespace.id.clone(),
            creator_did: "owner".into(),
            payload: vec![1],
            proof: vec![2],
        };
        let collaborator = Collaborator {
            did: "reader".into(),
            namespace: namespace.id.clone(),
        };
        for (key, value) in [
            (
                keys::namespace_key(&namespace.id),
                borsh::to_vec(&namespace).unwrap(),
            ),
            (
                keys::post_key(&post.namespace, &post.id),
                borsh::to_vec(&post).unwrap(),
            ),
            (
                keys::collaborator_key(&collaborator.namespace, &collaborator.did),
                borsh::to_vec(&collaborator).unwrap(),
            ),
            (
                keys::PARAMS_KEY.to_vec(),
                borsh::to_vec(&BulletinParams::default()).unwrap(),
            ),
        ] {
            let restored = |bytes| {
                BulletinModule::from_store(InMemoryKvStore::from_pairs(vec![(key.clone(), bytes)]))
            };
            restored(value.clone()).validate_storage_keys().unwrap();
            for length in 0..value.len() {
                assert!(
                    restored(value[..length].to_vec())
                        .validate_storage_keys()
                        .is_err()
                );
            }
            let mut trailing = value;
            trailing.push(0);
            assert!(restored(trailing).validate_storage_keys().is_err());
        }
        let wrong_namespace = BulletinModule::from_store(InMemoryKvStore::from_pairs(vec![(
            keys::namespace_key("bulletin/other"),
            borsh::to_vec(&namespace).unwrap(),
        )]));
        assert!(wrong_namespace.validate_storage_keys().is_err());
    }

    #[test]
    fn restored_policy_id_rejects_empty_and_invalid_utf8() {
        BulletinModule::default().validate_storage_keys().unwrap();
        for bytes in [vec![], vec![255]] {
            let module = BulletinModule::from_store(InMemoryKvStore::from_pairs(vec![(
                keys::POLICY_ID_KEY.to_vec(),
                bytes,
            )]));
            assert!(module.validate_storage_keys().is_err());
        }
    }
}
