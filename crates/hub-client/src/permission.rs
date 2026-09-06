use crate::{ClientError, HubClient};
use hub_domain::{ConsensusPublicKey, LightBlock, verify_light_block};
use hub_permission::{
    AccessRequest, PermissionLimits, PermissionProof, PermissionResponse, validate_request,
    verify_permission_proof,
};

impl HubClient {
    /// Fetch and verify current permission evidence and its revision in one bounded response.
    /// Returns the authenticated revision and local decision. The caller supplies the
    /// trusted consensus key, minimum revision and any additional timestamp/age policy.
    pub async fn verify_current_access(
        &self,
        policy: &str,
        request: &AccessRequest,
        minimum_height: u64,
        trusted_key: &ConsensusPublicKey,
        limits: PermissionLimits,
    ) -> Result<(LightBlock, bool), ClientError> {
        validate_request(policy, request, limits)?;
        let response: PermissionResponse = self
            .rpc_call_bounded(
                "hub_getCurrentPermissionProof",
                serde_json::json!([policy, request, minimum_height]),
                hub_domain::LIGHT_BLOCK_RESPONSE_BYTES
                    .saturating_add(limits.proof_bytes)
                    .saturating_add(1024),
            )
            .await?;
        let allowed = response.verify(policy, request, minimum_height, trusted_key, limits)?;
        Ok((response.revision, allowed))
    }

    /// Verify permission evidence at the caller's selected finalized revision.
    ///
    /// The consensus key must come from authenticated configuration. The caller
    /// selects revision freshness; this method never falls back to an older revision.
    pub async fn verify_access_at(
        &self,
        policy: &str,
        request: &AccessRequest,
        revision: &LightBlock,
        trusted_key: &ConsensusPublicKey,
        limits: PermissionLimits,
    ) -> Result<bool, ClientError> {
        validate_request(policy, request, limits)?;
        let (_, root) = verify_light_block(revision, trusted_key)?;
        let proof: PermissionProof = self
            .rpc_call_bounded(
                "hub_getPermissionProof",
                serde_json::json!([policy, request, revision.height]),
                limits.proof_bytes.saturating_add(1024),
            )
            .await?;
        Ok(verify_permission_proof(
            root,
            revision.height,
            policy,
            request,
            &proof,
            limits,
        )?)
    }
}
