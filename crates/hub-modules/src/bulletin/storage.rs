use borsh::BorshDeserialize as _;

use super::{BulletinModule, Result, error::BulletinError, keys};

impl BulletinModule {
    /// Reject legacy or corrupt composite keys before publishing restored native state.
    pub fn validate_storage_keys(&self) -> Result<()> {
        for prefix in [keys::POST_PREFIX, keys::COLLABORATOR_PREFIX] {
            for (key, mut value) in self.store.prefix_iter(prefix) {
                // Both record formats begin with the record identifier and namespace.
                let (id, namespace) = <(String, String)>::deserialize(&mut value).map_err(|e| {
                    BulletinError::State(format!("invalid bulletin record identity: {e}"))
                })?;
                let expected = if prefix == keys::POST_PREFIX {
                    keys::post_key(&namespace, &id)
                } else {
                    keys::collaborator_key(&namespace, &id)
                };
                if key != expected {
                    return Err(BulletinError::State(
                        "bulletin key does not match its record; explicit storage migration required".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bulletin::types::{Collaborator, Post},
        kv_store::InMemoryKvStore,
    };

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
}
