//! Authenticated caller operation identities with immutable expiry.

use serde::{Deserialize, Serialize};

use crate::jwt::JwtError;

/// Maximum remaining execution lifetime of an operation identity, in seconds.
pub const MAX_OPERATION_TTL: u64 = 600;

/// Eight-byte big-endian expiry followed by 24 bytes of caller-generated entropy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationId(pub [u8; 32]);

impl OperationId {
    /// Exclusive execution deadline in Unix seconds.
    pub fn expires_at(self) -> u64 {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&self.0[..8]);
        u64::from_be_bytes(bytes)
    }

    /// Reject expired, excessively future-dated or empty operation identities.
    pub fn validate(self, now: u64) -> Result<(), JwtError> {
        let expiry = self.expires_at();
        if now >= expiry || expiry - now > MAX_OPERATION_TTL || self.0[8..] == [0; 24] {
            return Err(JwtError::InvalidClaims(
                "invalid operation identity or deadline".into(),
            ));
        }
        Ok(())
    }
}

/// Exact request bound to an actor's signed delegation or relay assertion.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationClaim {
    /// Stable caller identity retained across workers and retries.
    pub id: OperationId,
    /// Digest of the typed semantic operation.
    pub digest: [u8; 32],
    /// Exact genesis identity, independently provisioned by the caller.
    pub genesis_id: [u8; 32],
}
