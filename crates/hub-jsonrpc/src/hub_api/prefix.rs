use hub_domain::ModuleId;
use hub_permission::{
    PermissionError, PrefixResponse, RECORD_RESPONSE_BYTES, current::MAX_KEY_BYTES, encoded_size,
};
use jsonrpsee::core::RpcResult;
use std::time::Duration;

use super::{
    HubApiImpl,
    permission::{error, request_error},
};

impl HubApiImpl {
    pub(super) async fn current_prefix_proof(
        &self,
        module: ModuleId,
        prefix: &[u8],
        minimum_height: u64,
    ) -> RpcResult<PrefixResponse> {
        if prefix.len() > MAX_KEY_BYTES {
            return Err(request_error(PermissionError::Limit));
        }
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
                    match hub_backend::native::prefix_proof_at(
                        [&a, &b, &h, &n],
                        selected.module_state_root,
                        module,
                        prefix,
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
                super::record::wait_for_proof_progress(&mut updates).await;
            };
            let revision = self.captured_revision(&selected).await?;
            let response = PrefixResponse {
                revision,
                prefix: proof,
            };
            encoded_size(&response, RECORD_RESPONSE_BYTES - 1024).map_err(request_error)?;
            Ok(response)
        })
        .await
        .map_err(|_| error("current prefix evidence deadline exceeded"))?
    }
}
