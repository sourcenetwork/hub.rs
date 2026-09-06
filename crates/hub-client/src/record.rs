use hub_domain::{ConsensusPublicKey, ModuleId};
use hub_permission::{PermissionError, RECORD_PROOF_BYTES, RecordResponse, current::MAX_KEY_BYTES};

use crate::{ClientError, HubClient};

impl HubClient {
    /// Read a native record with verified finality, request binding and a minimum revision.
    /// The caller provides the trusted consensus key and any timestamp/age requirements.
    pub async fn read_current_record(
        &self,
        module: ModuleId,
        key: &[u8],
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
        maximum_bytes: usize,
    ) -> Result<RecordResponse, ClientError> {
        if key.len() > MAX_KEY_BYTES {
            return Err(PermissionError::Limit.into());
        }
        let maximum_bytes = maximum_bytes.min(RECORD_PROOF_BYTES);
        let response: RecordResponse = self
            .rpc_call_bounded(
                "hub_getCurrentRecordProof",
                serde_json::json!([
                    module,
                    alloy_primitives::Bytes::copy_from_slice(key),
                    minimum_height
                ]),
                hub_domain::LIGHT_BLOCK_RESPONSE_BYTES + maximum_bytes + 1024,
            )
            .await?;
        response.verify(module, key, minimum_height, trusted, maximum_bytes)?;
        Ok(response)
    }
}
