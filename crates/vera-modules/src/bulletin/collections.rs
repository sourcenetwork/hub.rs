use borsh::BorshDeserialize;

use super::*;

const MAX_RECORDS: usize = 128;
const MAX_BYTES: usize = 1 << 20;
const MAX_PREFIX_BYTES: usize = 64 << 10;

impl BulletinModule {
    pub(super) fn collect_records<T: BorshDeserialize>(
        &self,
        prefix: &[u8],
        select: impl Fn(&T) -> bool,
        record_key: impl Fn(&T) -> Vec<u8>,
    ) -> Result<Vec<T>> {
        if prefix.len() > MAX_PREFIX_BYTES {
            return Err(BulletinError::QueryLimit);
        }
        let mut bytes = 0usize;
        let mut records = Vec::new();
        for (count, (key, value)) in self
            .store
            .prefix_iter(prefix)
            .take(MAX_RECORDS + 1)
            .enumerate()
        {
            bytes = bytes.saturating_add(key.len()).saturating_add(value.len());
            if count == MAX_RECORDS || bytes > MAX_BYTES {
                return Err(BulletinError::QueryLimit);
            }
            let record: T = borsh::from_slice(value).map_err(|error| {
                BulletinError::State(format!("invalid bulletin record: {error}"))
            })?;
            if record_key(&record) != key {
                return Err(BulletinError::State(
                    "bulletin record does not match its key".into(),
                ));
            }
            if select(&record) {
                records.push(record);
            }
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Timestamp;

    fn namespace(id: &str) -> Namespace {
        Namespace {
            id: id.into(),
            creator: "signer".into(),
            owner_did: "owner".into(),
            created_at: Timestamp::default(),
        }
    }
    fn post(id: usize) -> Post {
        Post {
            id: format!("{id:04}"),
            namespace: "bulletin/team".into(),
            creator_did: "owner".into(),
            payload: vec![1],
            proof: vec![2],
        }
    }

    #[test]
    fn collections_enforce_record_limits_without_truncation() {
        let mut module = BulletinModule::new();
        module.set_namespace(&namespace("bulletin/team"));
        for id in 0..MAX_RECORDS {
            module.set_post(&post(id));
            module.set_collaborator(&Collaborator {
                did: format!("actor{id}"),
                namespace: "bulletin/team".into(),
            });
        }
        assert_eq!(
            module.query_namespace_posts("team").unwrap().len(),
            MAX_RECORDS
        );
        assert_eq!(module.query_posts().unwrap().len(), MAX_RECORDS);
        assert_eq!(
            module.query_namespace_collaborators("team").unwrap().len(),
            MAX_RECORDS
        );
        assert!(
            module
                .query_iterate_glob("team", "missing*")
                .unwrap()
                .is_empty()
        );
        module.set_post(&post(MAX_RECORDS));
        module.set_collaborator(&Collaborator {
            did: "overflow".into(),
            namespace: "bulletin/team".into(),
        });
        assert!(matches!(
            module.query_namespace_posts("team"),
            Err(BulletinError::QueryLimit)
        ));
        assert!(matches!(
            module.query_posts(),
            Err(BulletinError::QueryLimit)
        ));
        assert!(matches!(
            module.query_namespace_collaborators("team"),
            Err(BulletinError::QueryLimit)
        ));
        assert!(matches!(
            module.query_iterate_glob("team", "missing*"),
            Err(BulletinError::QueryLimit)
        ));
        for id in 1..MAX_RECORDS {
            module.set_namespace(&namespace(&format!("bulletin/{id}")));
        }
        assert_eq!(module.query_namespaces().unwrap().len(), MAX_RECORDS);
        module.set_namespace(&namespace("bulletin/overflow"));
        assert!(matches!(
            module.query_namespaces(),
            Err(BulletinError::QueryLimit)
        ));
    }

    #[test]
    fn collections_budget_bytes_before_decoding_or_filtering() {
        let mut module = BulletinModule::new();
        module.set_namespace(&namespace("bulletin/team"));
        let mut record = post(0);
        record.payload.clear();
        let overhead = keys::post_key(&record.namespace, &record.id).len()
            + borsh::to_vec(&record).unwrap().len();
        record.payload = vec![0; MAX_BYTES - overhead];
        module.set_post(&record);
        assert_eq!(module.query_namespace_posts("team").unwrap().len(), 1);
        record.payload.push(0);
        module.set_post(&record);
        assert!(matches!(
            module.query_iterate_glob("team", "missing*"),
            Err(BulletinError::QueryLimit)
        ));
        assert!(matches!(
            module.query_iterate_glob("team", &"*".repeat(4097)),
            Err(BulletinError::QueryLimit)
        ));
    }

    #[test]
    fn collections_reject_corruption_and_scope_namespace_reads() {
        let mut module = BulletinModule::new();
        module.set_namespace(&namespace("bulletin/team"));
        module.set_post(&post(0));
        for id in 0..1000 {
            let mut unrelated = post(id);
            unrelated.namespace = "bulletin/other".into();
            module.set_post(&unrelated);
        }
        assert_eq!(module.query_namespace_posts("team").unwrap().len(), 1);
        let key = keys::post_key("bulletin/team", "0000");
        module.store.put(&key, vec![0]);
        assert!(matches!(
            module.query_namespace_posts("team"),
            Err(BulletinError::State(_))
        ));
        let mut mismatched = post(0);
        mismatched.namespace = "bulletin/other".into();
        module.store.put(&key, borsh::to_vec(&mismatched).unwrap());
        assert!(matches!(
            module.query_namespace_posts("team"),
            Err(BulletinError::State(_))
        ));
    }
}
