use alloy_primitives::B256;
use hub_domain::{ConsensusPublicKey, RECEIPT_RESPONSE_BYTES, ReceiptResponse};

use crate::{ClientError, HubClient};

impl HubClient {
    /// Fetch and verify execution results for an exact locally computed submission ID.
    /// `None` means no evidence is available; it does not authorize sequence reuse.
    pub async fn read_receipt(
        &self,
        submission: B256,
        trusted: &ConsensusPublicKey,
    ) -> Result<Option<ReceiptResponse>, ClientError> {
        let response: Option<ReceiptResponse> = self
            .rpc_call_bounded(
                "hub_getReceiptProof",
                serde_json::json!([submission]),
                RECEIPT_RESPONSE_BYTES,
            )
            .await?;
        if let Some(response) = &response {
            response.verify(submission, trusted)?;
        }
        Ok(response)
    }
}
