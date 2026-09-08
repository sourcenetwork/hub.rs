use super::*;

const MAX_MATCHES: usize = 128;
const MAX_RECORD_BYTES: usize = 1 << 20;

impl AcpModule {
    pub(super) fn filter_commitments_by_commitment(
        &self,
        root: &[u8],
    ) -> Result<Vec<RegistrationsCommitment>> {
        if root.len() != 32 {
            return Err(AcpError::InvalidAccessRequest {
                reason: "commitment must be 32 bytes".into(),
            });
        }
        let prefix = keys::commitment_by_commitment_index_prefix(root);
        let mut records = Vec::new();
        let mut bytes = 0usize;
        for (index, value) in self.store.prefix_iter(&prefix).take(MAX_MATCHES + 1) {
            if records.len() == MAX_MATCHES {
                return Err(AcpError::InvalidAccessRequest {
                    reason: "commitment lookup exceeds limit; use certified prefix pages".into(),
                });
            }
            if index.len() != prefix.len() + 8 || !value.is_empty() {
                return Err(AcpError::State("invalid commitment root index".into()));
            }
            let id = u64::from_be_bytes(
                index[prefix.len()..]
                    .try_into()
                    .map_err(|_| AcpError::State("invalid commitment identifier".into()))?,
            );
            let key = keys::commitment_key(id);
            let value = self
                .store
                .get_ref(&key)
                .ok_or_else(|| AcpError::State("indexed commitment missing".into()))?;
            bytes = bytes.saturating_add(value.len());
            if bytes > MAX_RECORD_BYTES {
                return Err(AcpError::InvalidAccessRequest {
                    reason: "commitment lookup byte limit exceeded; use certified prefix pages"
                        .into(),
                });
            }
            let record: RegistrationsCommitment = borsh::from_slice(value)
                .map_err(|error| AcpError::State(format!("invalid commitment: {error}")))?;
            if record.id != id || record.commitment != root {
                return Err(AcpError::State("commitment root index mismatch".into()));
            }
            records.push(record);
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn insert(module: &mut AcpModule, id: u64, root: Vec<u8>) {
        module
            .update_commitment(&RegistrationsCommitment {
                id,
                commitment: root,
                policy_id: "policy".into(),
                expired: false,
                validity: Duration::Seconds(600),
                metadata: RecordMetadata {
                    creation_ts: Timestamp::default(),
                    tx_hash: vec![0; 32],
                    tx_signer: "signer".into(),
                    owner_did: "actor".into(),
                },
            })
            .unwrap();
    }

    #[test]
    fn commitment_lookup_uses_recovered_index_and_never_truncates() {
        let mut module = AcpModule::new();
        for id in 1u64..=2000 {
            let mut root = vec![0; 32];
            root[..8].copy_from_slice(&id.to_be_bytes());
            insert(&mut module, id, root);
        }
        for id in 2001..=2128 {
            insert(&mut module, id, vec![9; 32]);
        }
        let mut module =
            AcpModule::from_store(InMemoryKvStore::deserialize(&module.store.serialize()).unwrap());
        let records = module
            .query_registrations_commitment_by_commitment(&[9; 32])
            .unwrap();
        assert_eq!(records.len(), MAX_MATCHES);
        assert_eq!(records.first().unwrap().id, 2001);
        assert_eq!(records.last().unwrap().id, 2128);
        let mut expired = records[0].clone();
        expired.expired = true;
        module.update_commitment(&expired).unwrap();
        assert!(
            module
                .query_registrations_commitment_by_commitment(&[9; 32])
                .unwrap()[0]
                .expired
        );
        insert(&mut module, 2129, vec![9; 32]);
        assert!(
            module
                .query_registrations_commitment_by_commitment(&[9; 32])
                .is_err()
        );
        assert_eq!(
            module
                .store
                .prefix_iter(&keys::commitment_by_commitment_index_prefix(&[9; 32]))
                .count(),
            129
        );
        assert!(
            module
                .query_registrations_commitment_by_commitment(&[8; 32])
                .unwrap()
                .is_empty()
        );
        assert!(
            module
                .query_registrations_commitment_by_commitment(&[])
                .is_err()
        );
    }

    #[test]
    fn commitment_lookup_rejects_corruption_and_excessive_bytes() {
        let mut module = AcpModule::new();
        insert(&mut module, 1, vec![9; 32]);
        module.store.put(&keys::commitment_key(1), vec![0]);
        assert!(
            module
                .query_registrations_commitment_by_commitment(&[9; 32])
                .is_err()
        );
        module
            .store
            .put(&keys::commitment_key(1), vec![0; MAX_RECORD_BYTES + 1]);
        assert!(
            module
                .query_registrations_commitment_by_commitment(&[9; 32])
                .is_err()
        );
    }
}
