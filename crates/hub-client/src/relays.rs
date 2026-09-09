//! Relay authority authenticated against independently configured consensus trust.

use crate::{ClientError, HubClient};
use hub_domain::ConsensusPublicKey;
use hub_modules::hub::relay::{RelayState, relay_key};
use hub_permission::{ModuleId, RECORD_PROOF_BYTES};

/// Operator grant or certified absence at a finalized revision.
#[derive(Clone, Debug)]
pub struct RelayRecord {
    /// Revision authenticating this record.
    pub revision: u64,
    /// Execution timestamp of that revision.
    pub timestamp: u64,
    /// Stored scopes, expiry and grant generation; an expired grant may remain present.
    pub value: Option<RelayState>,
}

impl HubClient {
    /// Read a canonical relay issuer's grant, including absence after revocation.
    /// Presence alone does not authorize an assertion; its scope, generation and expiry still apply.
    pub async fn read_relay_grant(
        &self,
        issuer: &str,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<RelayRecord, ClientError> {
        let key =
            relay_key(issuer).map_err(|_| ClientError::InvalidResponse("invalid relay issuer"))?;
        let response = self
            .read_current_record(ModuleId::Hub, &key, minimum, trusted, RECORD_PROOF_BYTES)
            .await?;
        let value = response
            .record
            .value
            .as_ref()
            .map(|bytes| decode(bytes, issuer))
            .transpose()?;
        Ok(RelayRecord {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            value,
        })
    }
}

fn decode(bytes: &[u8], issuer: &str) -> Result<RelayState, ClientError> {
    let state: RelayState = borsh::from_slice(bytes)
        .map_err(|_| ClientError::InvalidResponse("invalid relay grant encoding"))?;
    if state.grant.issuer != issuer
        || state.grant.scopes.is_empty()
        || state.grant.scopes.len() > 4
        || state.grant.scopes.windows(2).any(|pair| pair[0] >= pair[1])
        || state.grant.expires_at == 0
    {
        return Err(ClientError::InvalidResponse(
            "invalid relay grant or issuer binding",
        ));
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hub_crypto::jwt::DelegationScope;
    use hub_modules::hub::relay::RelayGrant;

    #[test]
    fn relay_records_bind_issuer_and_preserve_expired_grants() {
        let state = RelayState {
            grant: RelayGrant {
                issuer: "issuer".into(),
                scopes: vec![DelegationScope::CreatePolicy],
                expires_at: 1,
            },
            sequence: 7,
        };
        let bytes = borsh::to_vec(&state).unwrap();
        assert_eq!(decode(&bytes, "issuer").unwrap(), state);
        assert!(decode(&bytes, "another").is_err());
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end], "issuer").is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode(&trailing, "issuer").is_err());
        for scopes in [vec![], vec![DelegationScope::CreatePolicy; 2]] {
            let mut invalid = state.clone();
            invalid.grant.scopes = scopes;
            assert!(decode(&borsh::to_vec(&invalid).unwrap(), "issuer").is_err());
        }
        let mut invalid = state;
        invalid.grant.expires_at = 0;
        assert!(decode(&borsh::to_vec(&invalid).unwrap(), "issuer").is_err());
    }
}
