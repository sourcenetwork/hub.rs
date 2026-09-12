use super::{HubApiImpl, HubApiServer};
use crate::error::codes;
use alloy_primitives::{B256, U64};
use hub_permission::{
    AccessRequest, PERMISSION_LIMITS, PERMISSION_RESPONSE_BYTES, PermissionError, PermissionProof,
    PermissionRead, PermissionResponse, RecordRead, capture_reads, encoded_size, validate_request,
    verify_permission_proof,
};
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use std::time::Duration;

pub(super) fn error(error: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(codes::RESOURCE_UNAVAILABLE, error.to_string(), None::<()>)
}

/// Evidence waits are transient: flag them for client retry like admission throttles.
pub(super) fn retryable(error: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        codes::RESOURCE_UNAVAILABLE,
        error.to_string(),
        Some(serde_json::json!({"retryable": true})),
    )
}

pub(super) fn request_error(error: PermissionError) -> ErrorObjectOwned {
    let code = if matches!(error, PermissionError::Limit) {
        codes::LIMIT_EXCEEDED
    } else {
        codes::INVALID_PARAMS
    };
    ErrorObjectOwned::owned(code, error.to_string(), None::<()>)
}

impl HubApiImpl {
    fn permission_snapshot(&self) -> RpcResult<hub_modules::kv_store::InMemoryKvStore> {
        Ok(self
            .modules
            .as_ref()
            .ok_or_else(|| error("module records unavailable"))?
            .read()
            .map_err(|_| error("module lock poisoned"))?
            .acp
            .store()
            .clone())
    }

    pub(super) async fn current_permission_proof(
        &self,
        policy: &str,
        request: &AccessRequest,
        minimum_height: u64,
    ) -> RpcResult<PermissionResponse> {
        validate_request(policy, request, PERMISSION_LIMITS).map_err(request_error)?;
        let databases = self
            .native_modules
            .as_ref()
            .ok_or_else(|| error("native module storage unavailable"))?;
        let index = self
            .index
            .as_ref()
            .ok_or_else(|| error("finalized revision index unavailable"))?;
        let mut updates = self.state.proof_updates();
        tokio::time::timeout(Duration::from_secs(2), async {
            let (selected, proof) = loop {
                let captured = {
                    let (a, b, h, n) = tokio::join!(
                        databases.0.read(),
                        databases.1.read(),
                        databases.2.read(),
                        databases.3.read(),
                    );
                    let selected = index
                        .latest_block()
                        .ok_or_else(|| error("finalized revision unavailable"))?;
                    if selected.number < minimum_height {
                        return Err(error("finalized revision precedes required minimum"));
                    }
                    let snapshot = self.permission_snapshot()?;
                    match hub_backend::native::permission_proof_at(
                        [&a, &b, &h, &n],
                        selected.module_state_root,
                        snapshot,
                        policy,
                        request,
                        PERMISSION_LIMITS,
                    )
                    .await
                    {
                        Ok(proof) => Some((selected, proof)),
                        Err(hub_backend::BackendError::Permission(PermissionError::Invalid(
                            "selected module root changed",
                        ))) => None,
                        Err(hub_backend::BackendError::Permission(PermissionError::Limit)) => {
                            return Err(request_error(PermissionError::Limit));
                        }
                        Err(cause) => return Err(error(cause)),
                    }
                };
                if let Some(captured) = captured {
                    break captured;
                }
                // Release every read guard so an in-flight finalization can publish its index.
                super::record::wait_for_proof_progress(&mut updates).await;
            };
            let revision = self.captured_revision(&selected).await?;
            let response = PermissionResponse { revision, proof };
            encoded_size(&response, PERMISSION_RESPONSE_BYTES - 1024).map_err(request_error)?;
            Ok(response)
        })
        .await
        .map_err(|_| retryable("current permission evidence deadline exceeded"))?
    }

    pub(super) async fn permission_proof(
        &self,
        policy: &str,
        request: &AccessRequest,
        height: u64,
    ) -> RpcResult<PermissionProof> {
        validate_request(policy, request, PERMISSION_LIMITS).map_err(request_error)?;
        let light = self.get_light_block(U64::from(height)).await?;
        let root: B256 = light.module_state_root.parse().map_err(error)?;
        let snapshot = self.permission_snapshot()?;
        if let Some(databases) = &self.native_modules {
            return hub_backend::native::permission_proof(
                databases,
                root,
                snapshot,
                policy,
                request,
                PERMISSION_LIMITS,
            )
            .await
            .map_err(error);
        }
        let reads =
            capture_reads(snapshot.clone(), policy, request, PERMISSION_LIMITS).map_err(error)?;
        let mut proof = PermissionProof::default();
        let mut remaining = PERMISSION_LIMITS.proof_bytes
            - encoded_size(&proof, PERMISSION_LIMITS.proof_bytes).map_err(request_error)?;
        for read in reads {
            let read = match read {
                RecordRead::Key(key) => PermissionRead::Point {
                    proof: self
                        .state_proof("acp".into(), hex::encode(key), U64::from(height))
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
