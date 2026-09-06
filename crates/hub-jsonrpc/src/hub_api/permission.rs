use super::{HubApiImpl, HubApiServer};
use crate::error::codes;
use alloy_primitives::{B256, U64};
use hub_permission::{
    AccessRequest, PERMISSION_LIMITS, PermissionError, PermissionProof, PermissionRead, RecordRead,
    capture_reads, encoded_size, validate_request, verify_permission_proof,
};
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};

fn error(error: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(codes::RESOURCE_UNAVAILABLE, error.to_string(), None::<()>)
}

fn request_error(error: PermissionError) -> ErrorObjectOwned {
    let code = if matches!(error, PermissionError::Limit) {
        codes::LIMIT_EXCEEDED
    } else {
        codes::INVALID_PARAMS
    };
    ErrorObjectOwned::owned(code, error.to_string(), None::<()>)
}

impl HubApiImpl {
    pub(super) async fn permission_proof(
        &self,
        policy: &str,
        request: &AccessRequest,
        height: u64,
    ) -> RpcResult<PermissionProof> {
        validate_request(policy, request, PERMISSION_LIMITS).map_err(request_error)?;
        let light = self.get_light_block(U64::from(height)).await?;
        let root: B256 = light.module_state_root.parse().map_err(error)?;
        let modules = self
            .modules
            .as_ref()
            .ok_or_else(|| error("module records unavailable"))?;
        let snapshot = modules
            .read()
            .map_err(|_| error("module lock poisoned"))?
            .acp
            .store()
            .clone();
        let reads =
            capture_reads(snapshot.clone(), policy, request, PERMISSION_LIMITS).map_err(error)?;
        let mut proof = PermissionProof::default();
        let mut remaining = PERMISSION_LIMITS.proof_bytes
            - encoded_size(&proof, PERMISSION_LIMITS.proof_bytes).map_err(request_error)?;
        for read in reads {
            let read = match read {
                RecordRead::Key(key) => PermissionRead::Point {
                    proof: self
                        .get_state_proof("acp".into(), hex::encode(key), U64::from(height))
                        .await?,
                },
                RecordRead::Prefix(prefix) => PermissionRead::Prefix {
                    proof: Box::new(self.relation_proof_at(
                        &prefix,
                        height,
                        root,
                        snapshot.prefix_iter(&prefix),
                    )?),
                    prefix: prefix.into(),
                },
            };
            let size = encoded_size(&read, remaining).map_err(request_error)?;
            remaining = remaining
                .checked_sub(size + usize::from(!proof.reads.is_empty()))
                .ok_or_else(|| request_error(PermissionError::Limit))?;
            proof.reads.push(read);
        }
        verify_permission_proof(root, height, policy, request, &proof, PERMISSION_LIMITS)
            .map_err(error)?;
        Ok(proof)
    }
}
