//! Certified token lifecycle records.

use crate::{ClientError, HubClient};
use alloy_primitives::B256;
use hub_domain::ConsensusPublicKey;
use hub_modules::hub::{keys, types::JWSTokenRecord};
use hub_permission::{ModuleId, RECORD_PROOF_BYTES};

/// A token record or certified absence at a finalized revision.
#[derive(Clone, Debug)]
pub struct TokenRecord {
    /// Revision authenticating the selected record.
    pub revision: u64,
    /// Execution timestamp at that revision.
    pub timestamp: u64,
    /// Stored lifecycle metadata, including status and invalidation details.
    pub value: Option<JWSTokenRecord>,
}

impl HubClient {
    /// Read a token by its SHA-256 hash and verify its stored content binding.
    /// Presence alone does not establish current authorization or token validity.
    pub async fn read_token_record(
        &self,
        hash: B256,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<TokenRecord, ClientError> {
        let hash = hex::encode(hash);
        let response = self
            .read_current_record(
                ModuleId::Hub,
                &keys::jws_token_key(&hash),
                minimum,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await?;
        let value = response
            .record
            .value
            .as_ref()
            .map(|bytes| decode(bytes, &hash))
            .transpose()?;
        Ok(TokenRecord {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            value,
        })
    }
}

fn decode(bytes: &[u8], hash: &str) -> Result<JWSTokenRecord, ClientError> {
    let record: JWSTokenRecord = borsh::from_slice(bytes)
        .map_err(|_| ClientError::InvalidResponse("invalid token record encoding"))?;
    if record.token_hash != hash || keys::hash_jws_token(&record.bearer_token) != hash {
        return Err(ClientError::InvalidResponse(
            "token record differs from selection",
        ));
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hub_modules::{hub::types::JWSTokenStatus, types::Timestamp};

    #[test]
    fn token_records_bind_content_and_require_complete_encoding() {
        let hash = keys::hash_jws_token("signed-token");
        let mut record = JWSTokenRecord {
            token_hash: hash.clone(),
            bearer_token: "signed-token".into(),
            issuer_did: "issuer".into(),
            authorized_account: "worker".into(),
            issued_at: Timestamp::default(),
            expires_at: Timestamp::default(),
            status: JWSTokenStatus::Invalid,
            first_used_at: None,
            last_used_at: None,
            invalidated_at: Some(Timestamp {
                seconds: 10,
                block_height: 2,
            }),
            invalidated_by: "worker".into(),
        };
        let bytes = borsh::to_vec(&record).unwrap();
        assert_eq!(decode(&bytes, &hash).unwrap(), record);
        assert!(decode(&bytes, &"0".repeat(64)).is_err());
        assert!(decode(&bytes[..bytes.len() - 1], &hash).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode(&trailing, &hash).is_err());
        record.bearer_token = "other-token".into();
        assert!(decode(&borsh::to_vec(&record).unwrap(), &hash).is_err());
    }
}
