use super::*;

impl HubModule {
    pub(super) fn token_expiry_key(record: &JWSTokenRecord) -> Option<Vec<u8>> {
        if record.status == JWSTokenStatus::Invalid || record.expires_at == Timestamp::default() {
            return None;
        }
        Some(
            [
                keys::JWS_TOKEN_EXPIRY_PREFIX,
                &record.expires_at.seconds.to_be_bytes(),
                record.token_hash.as_bytes(),
            ]
            .concat(),
        )
    }

    /// Invalidate due tokens using their persisted ordered deadline index.
    pub fn check_and_update_expired_tokens(&mut self, block_ctx: &BlockExecCtx) -> Result<()> {
        let prefix = keys::JWS_TOKEN_EXPIRY_PREFIX;
        let mut expired = Vec::new();
        for (index, value) in self.store.prefix_iter(prefix) {
            if index.len() <= prefix.len() + 8 || !value.is_empty() {
                return Err(HubError::State("invalid token expiry index".into()));
            }
            if &index[prefix.len()..prefix.len() + 8]
                >= block_ctx.timestamp.seconds.to_be_bytes().as_slice()
            {
                break;
            }
            let hash = std::str::from_utf8(&index[prefix.len() + 8..])
                .map_err(|error| HubError::State(format!("invalid expiry token hash: {error}")))?;
            let record = self
                .get_jws_token(hash)?
                .ok_or_else(|| HubError::State("expiry token missing".into()))?;
            if Self::token_expiry_key(&record).as_deref() != Some(index) {
                return Err(HubError::State("token expiry index mismatch".into()));
            }
            expired.push(hash.to_owned());
        }
        for hash in expired {
            self.update_jws_token_status(block_ctx, &hash, JWSTokenStatus::Invalid, "")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(seconds: u64) -> BlockExecCtx {
        BlockExecCtx {
            genesis_id: [0; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds,
                block_height: seconds,
            },
        }
    }

    fn token(hub: &mut HubModule, name: &str, expiry: u64) -> String {
        hub.store_or_update_jws_token(
            &context(100),
            name,
            &Did::new("did:key:issuer").unwrap(),
            "account",
            Timestamp::default(),
            Timestamp {
                seconds: expiry,
                block_height: 0,
            },
        )
        .unwrap();
        keys::hash_jws_token(name)
    }

    #[test]
    fn token_expiry_retains_history_and_recovers_active_deadlines() {
        let mut hub = HubModule::new();
        for id in 0..2000 {
            let hash = token(&mut hub, &id.to_string(), 150);
            hub.update_jws_token_status(&context(101), &hash, JWSTokenStatus::Invalid, "operator")
                .unwrap();
        }
        let due = token(&mut hub, "due", 150);
        let future = token(&mut hub, "future", 160);
        let permanent = token(&mut hub, "permanent", 0);
        hub.record_jws_token_usage(&context(110), &due).unwrap();
        assert_eq!(
            hub.store.prefix_iter(keys::JWS_TOKEN_EXPIRY_PREFIX).count(),
            2
        );
        let mut hub =
            HubModule::from_store(InMemoryKvStore::deserialize(&hub.store.serialize()).unwrap());
        hub.check_and_update_expired_tokens(&context(150)).unwrap();
        assert_eq!(
            hub.get_jws_token(&due).unwrap().unwrap().status,
            JWSTokenStatus::Valid
        );
        hub.check_and_update_expired_tokens(&context(151)).unwrap();
        let expired = hub.get_jws_token(&due).unwrap().unwrap();
        assert_eq!(expired.status, JWSTokenStatus::Invalid);
        assert_eq!(expired.invalidated_at, Some(context(151).timestamp));
        assert_eq!(
            hub.store.prefix_iter(keys::JWS_TOKEN_EXPIRY_PREFIX).count(),
            1
        );
        assert_eq!(hub.store.prefix_iter(keys::JWS_TOKEN_PREFIX).count(), 2003);
        assert_eq!(
            hub.get_jws_token(&future).unwrap().unwrap().status,
            JWSTokenStatus::Valid
        );
        assert_eq!(
            hub.get_jws_token(&permanent).unwrap().unwrap().status,
            JWSTokenStatus::Valid
        );
        hub.update_jws_token_status(&context(152), &future, JWSTokenStatus::Invalid, "operator")
            .unwrap();
        assert_eq!(
            hub.store.prefix_iter(keys::JWS_TOKEN_EXPIRY_PREFIX).count(),
            0
        );
        hub.check_and_update_expired_tokens(&context(200)).unwrap();
        assert_eq!(
            hub.get_jws_token(&future).unwrap().unwrap().invalidated_by,
            "operator"
        );
    }

    #[test]
    fn token_expiry_rejects_mismatched_records_before_mutation() {
        let mut hub = HubModule::new();
        let first = token(&mut hub, "first", 150);
        let second = token(&mut hub, "second", 150);
        let bytes = hub.store.get(&keys::jws_token_key(&first)).unwrap();
        hub.store.put(&keys::jws_token_key(&second), bytes);
        let before = hub.store.serialize();
        assert!(hub.get_jws_token(&second).is_err());
        assert!(hub.check_and_update_expired_tokens(&context(151)).is_err());
        assert_eq!(hub.store.serialize(), before);
    }
}
