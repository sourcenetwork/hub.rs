use super::*;

const SECONDS_PREFIX: &[u8] = b"commitment_expiry/seconds/";
const HEIGHT_PREFIX: &[u8] = b"commitment_expiry/height/";

impl AcpModule {
    pub(super) fn commitment_expiry_key(commitment: &RegistrationsCommitment) -> Vec<u8> {
        let (prefix, deadline) = match commitment.validity {
            Duration::Seconds(delta) => (
                SECONDS_PREFIX,
                commitment
                    .metadata
                    .creation_ts
                    .seconds
                    .saturating_add(delta),
            ),
            Duration::Blocks(delta) => (
                HEIGHT_PREFIX,
                commitment
                    .metadata
                    .creation_ts
                    .block_height
                    .saturating_add(delta),
            ),
        };
        [
            prefix,
            &deadline.to_be_bytes(),
            &commitment.id.to_be_bytes(),
        ]
        .concat()
    }

    pub(super) fn expire_commitments(
        &mut self,
        now: &Timestamp,
    ) -> Result<Vec<RegistrationsCommitment>> {
        let mut expired = Vec::new();
        for (prefix, current) in [
            (SECONDS_PREFIX, now.seconds),
            (HEIGHT_PREFIX, now.block_height),
        ] {
            for (index, value) in self.store.prefix_iter(prefix) {
                if index.len() != prefix.len() + 16 || !value.is_empty() {
                    return Err(AcpError::State("invalid commitment expiry index".into()));
                }
                if &index[prefix.len()..prefix.len() + 8] >= current.to_be_bytes().as_slice() {
                    break;
                }
                let id =
                    u64::from_be_bytes(index[prefix.len() + 8..].try_into().map_err(|_| {
                        AcpError::State("invalid commitment expiry identifier".into())
                    })?);
                let mut record = self
                    .get_commitment_by_id(id)?
                    .ok_or_else(|| AcpError::State("expiry commitment missing".into()))?;
                if record.expired || Self::commitment_expiry_key(&record) != index {
                    return Err(AcpError::State("commitment expiry index mismatch".into()));
                }
                record.expired = true;
                expired.push(record);
            }
        }
        for record in &expired {
            self.update_commitment(record)?;
        }
        Ok(expired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insert(module: &mut AcpModule, id: u64, validity: Duration, expired: bool) {
        module
            .update_commitment(&RegistrationsCommitment {
                id,
                policy_id: "policy".into(),
                commitment: vec![7; 32],
                expired,
                validity,
                metadata: RecordMetadata {
                    creation_ts: Timestamp {
                        seconds: 100,
                        block_height: 10,
                    },
                    tx_hash: vec![1; 32],
                    tx_signer: "signer".into(),
                    owner_did: "actor".into(),
                },
            })
            .unwrap();
    }

    #[test]
    fn expiry_index_survives_recovery_and_leaves_history_untouched() {
        let mut module = AcpModule::new();
        for id in 1..=2000 {
            insert(&mut module, id, Duration::Seconds(0), true);
        }
        insert(&mut module, 2001, Duration::Seconds(5), false);
        insert(&mut module, 2002, Duration::Blocks(5), false);
        insert(&mut module, 2003, Duration::Seconds(u64::MAX), false);
        let state = module.store.serialize();
        module.store = InMemoryKvStore::deserialize(&state).unwrap();
        assert_eq!(module.store.prefix_iter(SECONDS_PREFIX).count(), 2);
        assert_eq!(module.store.prefix_iter(HEIGHT_PREFIX).count(), 1);
        assert!(
            module
                .expire_commitments(&Timestamp {
                    seconds: 105,
                    block_height: 15
                })
                .unwrap()
                .is_empty()
        );
        let expired = module
            .expire_commitments(&Timestamp {
                seconds: 106,
                block_height: 16,
            })
            .unwrap();
        assert_eq!(
            expired.iter().map(|record| record.id).collect::<Vec<_>>(),
            vec![2001, 2002]
        );
        assert_eq!(module.store.prefix_iter(SECONDS_PREFIX).count(), 1);
        assert_eq!(module.store.prefix_iter(HEIGHT_PREFIX).count(), 0);
        assert_eq!(
            module
                .store
                .prefix_iter(&AcpModule::commitment_objs_prefix())
                .count(),
            2003
        );
        assert!(
            module
                .expire_commitments(&Timestamp {
                    seconds: u64::MAX,
                    block_height: u64::MAX
                })
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn restamping_replaces_deadline_and_corruption_does_not_expire_other_records() {
        let mut module = AcpModule::new();
        insert(&mut module, 1, Duration::Seconds(5), false);
        insert(&mut module, 1, Duration::Seconds(10), false);
        assert_eq!(module.store.prefix_iter(SECONDS_PREFIX).count(), 1);
        assert!(
            module
                .expire_commitments(&Timestamp {
                    seconds: 106,
                    block_height: 0
                })
                .unwrap()
                .is_empty()
        );
        insert(&mut module, 2, Duration::Seconds(10), false);
        module.store.put(&keys::commitment_key(2), vec![0]);
        let before = module.store.serialize();
        assert!(
            module
                .expire_commitments(&Timestamp {
                    seconds: 111,
                    block_height: 0
                })
                .is_err()
        );
        assert_eq!(module.store.serialize(), before);
    }
}
