//! Canonical operation commitments for relay assertions.

use hub_crypto::jwt::DelegationScope;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::{
    AcpError, Result,
    types::{PolicyCmd, PolicyMarshalingType},
};

/// Exact semantic arguments authorized by a relay, excluding the assertion itself.
#[derive(Debug, Serialize)]
pub enum DelegatedOperation<'a> {
    /// Policy definition and serialization format.
    CreatePolicy(&'a str, &'a PolicyMarshalingType),
    /// Policy identifier, replacement definition and serialization format.
    EditPolicy(&'a str, &'a str, &'a PolicyMarshalingType),
    /// Policy identifier and the complete graph command.
    PolicyCommand(&'a str, &'a PolicyCmd),
}

impl DelegatedOperation<'_> {
    /// Required delegation scope.
    pub const fn scope(&self) -> DelegationScope {
        match self {
            Self::CreatePolicy(..) => DelegationScope::CreatePolicy,
            Self::EditPolicy(..) => DelegationScope::EditPolicy,
            Self::PolicyCommand(..) => DelegationScope::PolicyCommands,
        }
    }

    /// SHA-256 of `vera/acp-operation/v1\0` and compact serde JSON for this typed value.
    /// Struct fields and tuple arguments retain declaration order; inputs contain no maps.
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(b"vera/acp-operation/v1\0");
        hash.update(serde_json::to_vec(self).map_err(|error| AcpError::State(error.to_string()))?);
        Ok(hash.finalize().into())
    }
}
