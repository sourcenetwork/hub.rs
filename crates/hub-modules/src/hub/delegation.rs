use hub_crypto::jwt::{JwtClaims, matches_issuer, verify_bearer_token};
use identity::Did;

use super::{HubError, HubModule, JWSTokenRecord, JWSTokenStatus, Result};
use crate::types::{BlockExecCtx, Timestamp};

impl HubModule {
    /// Verify a delegation against the authenticated caller and current revocations.
    pub fn authorize_delegation(
        &self,
        context: &BlockExecCtx,
        caller: &Did,
        token: &str,
    ) -> Result<JwtClaims> {
        let claims = verify_bearer_token(token).map_err(invalid)?;
        claims
            .authorize(
                caller.as_ref(),
                context.deployment_id,
                context.timestamp.seconds,
            )
            .map_err(invalid)?;
        if self
            .get_jws_token(&Self::hash_jws_token(token))?
            .is_some_and(|record| record.status != JWSTokenStatus::Valid)
        {
            return Err(invalid("token has been revoked"));
        }
        Ok(claims)
    }

    /// Revoke a signed delegation, including one that has never been used.
    pub fn revoke_delegation(
        &mut self,
        context: &BlockExecCtx,
        caller: &Did,
        token: &str,
    ) -> Result<JWSTokenRecord> {
        let claims = verify_bearer_token(token).map_err(invalid)?;
        let caller = caller.to_string();
        if claims.aud != format!("vera:{}", context.deployment_id)
            || (!matches_issuer(&claims.iss, &caller) && caller != claims.sub)
        {
            return Err(HubError::Unauthorized {
                reason: "delegation revocation is not authorized".into(),
            });
        }
        let hash = Self::hash_jws_token(token);
        let mut record = self
            .get_jws_token(&hash)?
            .unwrap_or_else(|| JWSTokenRecord {
                token_hash: hash,
                bearer_token: token.into(),
                issuer_did: claims.iss,
                authorized_account: claims.sub,
                issued_at: Timestamp {
                    seconds: claims.iat,
                    block_height: 0,
                },
                expires_at: Timestamp {
                    seconds: claims.exp,
                    block_height: 0,
                },
                status: JWSTokenStatus::Valid,
                first_used_at: None,
                last_used_at: None,
                invalidated_at: None,
                invalidated_by: String::new(),
            });
        if record.status == JWSTokenStatus::Invalid {
            return Err(HubError::TokenAlreadyInvalidated {
                token_hash: record.token_hash,
            });
        }
        record.status = JWSTokenStatus::Invalid;
        record.invalidated_at = Some(context.timestamp.clone());
        record.invalidated_by = caller;
        self.set_jws_token(&record)?;
        Ok(record)
    }
}

fn invalid(error: impl std::fmt::Display) -> HubError {
    HubError::InvalidJws {
        reason: error.to_string(),
    }
}
