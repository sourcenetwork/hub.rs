use super::*;

const MAX_RECORDS: usize = 128;
const MAX_BYTES: usize = 1 << 20;

impl HubModule {
    pub(super) fn validate_token_selector(value: &str) -> Result<()> {
        if value.is_empty() || value.len() > u8::MAX as usize {
            return Err(HubError::InvalidJws {
                reason: "token index components must contain 1–255 bytes".into(),
            });
        }
        Ok(())
    }

    pub(super) fn collect_tokens(
        &self,
        prefix: &[u8],
        indexed: bool,
        record_key: impl Fn(&JWSTokenRecord) -> Vec<u8>,
    ) -> Result<Vec<JWSTokenRecord>> {
        let mut records = Vec::new();
        let mut bytes = 0usize;
        for (count, (key, value)) in self
            .store
            .prefix_iter(prefix)
            .take(MAX_RECORDS + 1)
            .enumerate()
        {
            bytes = bytes.saturating_add(key.len()).saturating_add(value.len());
            if count == MAX_RECORDS || bytes > MAX_BYTES {
                return Err(HubError::State(
                    "token query exceeds limit; use certified prefix pages".into(),
                ));
            }
            let value = if indexed {
                let hash = extract_hash_from_index_suffix(&key[prefix.len()..])
                    .ok_or_else(|| HubError::State("invalid token index key".into()))?;
                if value != [1] {
                    return Err(HubError::State("invalid token index value".into()));
                }
                let primary_key = keys::jws_token_key(&hash);
                let value = self
                    .store
                    .get_ref(&primary_key)
                    .ok_or_else(|| HubError::State("indexed token missing".into()))?;
                bytes = bytes
                    .saturating_add(primary_key.len())
                    .saturating_add(value.len());
                value
            } else {
                value
            };
            if bytes > MAX_BYTES {
                return Err(HubError::State(
                    "token query exceeds byte limit; use certified prefix pages".into(),
                ));
            }
            let record: JWSTokenRecord = borsh::from_slice(value)
                .map_err(|e| HubError::State(format!("invalid token record: {e}")))?;
            Self::validate_token_selector(&record.token_hash)?;
            Self::validate_token_selector(&record.issuer_did)?;
            if !record.authorized_account.is_empty() {
                Self::validate_token_selector(&record.authorized_account)?;
            }
            if record_key(&record) != key {
                return Err(HubError::State("token index does not match record".into()));
            }
            records.push(record);
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(hash: &str) -> JWSTokenRecord {
        JWSTokenRecord {
            token_hash: hash.into(),
            bearer_token: "token".into(),
            issuer_did: "did:key:issuer".into(),
            authorized_account: "account".into(),
            issued_at: Timestamp::default(),
            expires_at: Timestamp::default(),
            status: JWSTokenStatus::Valid,
            first_used_at: None,
            last_used_at: None,
            invalidated_at: None,
            invalidated_by: String::new(),
        }
    }

    #[test]
    fn selectors_and_writes_reject_overflow_before_mutation() {
        let mut hub = HubModule::new();
        for account in ["".to_string(), "a".repeat(256)] {
            assert!(hub.get_jws_tokens_by_account(&account).is_err());
        }
        let did = Did::new(format!("did:key:{}", "a".repeat(256))).unwrap();
        assert!(hub.get_jws_tokens_by_did(&did).is_err());
        for field in 0..3 {
            let mut token = record("hash");
            match field {
                0 => token.token_hash = "a".repeat(256),
                1 => token.issuer_did = did.to_string(),
                _ => token.authorized_account = "a".repeat(256),
            }
            let before = hub.store.serialize();
            assert!(hub.set_jws_token(&token).is_err());
            assert_eq!(hub.store.serialize(), before);
        }
    }

    #[test]
    fn token_queries_are_bounded_and_reject_dangling_or_aliased_indexes() {
        let mut hub = HubModule::new();
        for id in 0..MAX_RECORDS {
            hub.set_jws_token(&record(&format!("hash{id}"))).unwrap();
        }
        assert_eq!(
            hub.get_jws_tokens_by_account("account").unwrap().len(),
            MAX_RECORDS
        );
        assert_eq!(hub.get_all_jws_tokens().unwrap().len(), MAX_RECORDS);
        hub.set_jws_token(&record("extra")).unwrap();
        assert!(hub.get_jws_tokens_by_account("account").is_err());
        assert!(hub.get_all_jws_tokens().is_err());
        let mut hub = HubModule::new();
        hub.set_jws_token(&record("hash")).unwrap();
        let primary = keys::jws_token_key("hash");
        hub.store.delete(&primary);
        assert!(hub.get_jws_tokens_by_account("account").is_err());
        hub.set_jws_token(&record("hash")).unwrap();
        let mut alias = keys::jws_token_by_account_key("account", "hash");
        alias.push(0);
        hub.store.put(&alias, vec![1]);
        assert!(hub.get_jws_tokens_by_account("account").is_err());
    }

    #[test]
    fn token_queries_bound_bytes_and_validate_record_index_binding() {
        let mut hub = HubModule::new();
        let mut token = record("hash");
        token.bearer_token = "a".repeat(MAX_BYTES);
        hub.set_jws_token(&token).unwrap();
        assert!(hub.get_jws_tokens_by_account("account").is_err());
        assert!(hub.get_all_jws_tokens().is_err());
        token.bearer_token.clear();
        token.authorized_account = "other".into();
        hub.store
            .put(&keys::jws_token_key("hash"), borsh::to_vec(&token).unwrap());
        assert!(hub.get_jws_tokens_by_account("account").is_err());
    }
}
