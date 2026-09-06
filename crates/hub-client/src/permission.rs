use crate::{ClientError, HubClient};
use hub_domain::{ConsensusPublicKey, LightBlock, verify_light_block};
use hub_permission::{
    AccessRequest, PermissionLimits, PermissionProof, validate_request, verify_permission_proof,
};

impl HubClient {
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
