use hub_permission::{
    PAGE_RESPONSE_BYTES, PermissionError, PrefixPageRequest, PrefixPageResponse, encoded_size,
};
use jsonrpsee::core::RpcResult;
use std::time::Duration;

use super::{
    HubApiImpl,
    permission::{error, request_error},
};

impl HubApiImpl {
    pub(super) async fn current_prefix_page_proof(
        &self,
        request: &PrefixPageRequest,
        minimum_height: u64,
    ) -> RpcResult<PrefixPageResponse> {
        request.validate().map_err(request_error)?;
        let databases = self
            .native_modules
            .as_ref()
            .ok_or_else(|| error("native module storage unavailable"))?;
        let index = self
            .index
            .as_ref()
            .ok_or_else(|| error("finalized revision index unavailable"))?;
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
                        .get_block_by_number(index.head_block_number())
                        .ok_or_else(|| error("finalized revision unavailable"))?;
                    if selected.number < minimum_height {
                        return Err(error("finalized revision precedes required minimum"));
                    }
                    match hub_backend::native::prefix_page_at(
                        [&a, &b, &h, &n],
                        selected.module_state_root,
                        request,
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
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            let revision = self.captured_revision(&selected).await?;
            let response = PrefixPageResponse {
                revision,
                page: proof,
            };
            encoded_size(&response, PAGE_RESPONSE_BYTES - 1024).map_err(request_error)?;
            Ok(response)
        })
        .await
        .map_err(|_| error("current page evidence deadline exceeded"))?
    }
}
