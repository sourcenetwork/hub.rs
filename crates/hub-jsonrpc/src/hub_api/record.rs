use alloy_primitives::B256;
use hub_domain::{LightBlock, ModuleId};
use hub_indexer::IndexedBlock;
use hub_permission::{
    PermissionError, RECORD_RESPONSE_BYTES, RecordResponse, current::MAX_KEY_BYTES, encoded_size,
};
use jsonrpsee::core::RpcResult;
use std::time::Duration;

use super::{
    HubApiImpl, HubApiServer, U64,
    permission::{error, request_error},
};

impl HubApiImpl {
    pub(super) async fn current_record_proof(
        &self,
        module: ModuleId,
        key: &[u8],
        minimum_height: u64,
    ) -> RpcResult<RecordResponse> {
        if key.len() > MAX_KEY_BYTES {
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
        tokio::time::timeout(Duration::from_secs(2), async {
            let (selected, record) = loop {
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
                    match hub_backend::native::record_proof_at(
                        [&a, &b, &h, &n],
                        selected.module_state_root,
                        module,
                        key,
                    )
                    .await
                    {
                        Ok(record) => Some((selected, record)),
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
            let response = RecordResponse { revision, record };
            encoded_size(&response, RECORD_RESPONSE_BYTES - 1024).map_err(request_error)?;
            Ok(response)
        })
        .await
        .map_err(|_| error("current record evidence deadline exceeded"))?
    }

    // Called after releasing storage guards, under the enclosing request deadline.
    pub(super) async fn captured_revision(&self, selected: &IndexedBlock) -> RpcResult<LightBlock> {
        loop {
            if let Some(revision) = self.try_captured_revision(selected).await? {
                return Ok(revision);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    pub(super) async fn try_captured_revision(
        &self,
        selected: &IndexedBlock,
    ) -> RpcResult<Option<LightBlock>> {
        let revision = match self.get_light_block(U64::from(selected.number)).await {
            Ok(revision) => revision,
            Err(cause)
                if cause
                    .message()
                    .contains("finalization certificate not found") =>
            {
                return Ok(None);
            }
            Err(cause) => return Err(cause),
        };
        if revision.height != selected.number
            || revision.block_hash.parse::<B256>().map_err(error)? != selected.hash
            || revision.module_state_root.parse::<B256>().map_err(error)?
                != selected.module_state_root
        {
            return Err(error("finalization differs from captured revision"));
        }
        revision.check_artifact_limits().map_err(error)?;
        encoded_size(&revision, hub_domain::LIGHT_BLOCK_RESPONSE_BYTES).map_err(request_error)?;
        Ok(Some(revision))
    }
}
