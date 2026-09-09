use alloy_primitives::{B256, Log};
use hub_domain::{ExecutionReceipt, RECEIPT_RESPONSE_BYTES, ReceiptResponse};
use hub_permission::encoded_size;
use jsonrpsee::core::RpcResult;

use super::{
    HubApiImpl,
    permission::{error, request_error},
};

impl HubApiImpl {
    pub(super) async fn receipt_proof(&self, hash: B256) -> RpcResult<Option<ReceiptResponse>> {
        let index = self
            .index
            .as_ref()
            .ok_or_else(|| error("receipt index unavailable"))?;
        let Some(requested) = index.get_receipt(&hash) else {
            return Ok(None);
        };
        let block = index
            .get_block_by_hash(&requested.block_hash)
            .ok_or_else(|| error("receipt revision unavailable"))?;
        let Some(revision) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            self.try_captured_revision(&block),
        )
        .await
        .map_err(|_| error("receipt finality deadline exceeded"))??
        else {
            return Ok(None);
        };
        let mut receipts = block
            .transaction_hashes
            .iter()
            .map(|id| {
                let receipt = index
                    .get_receipt(id)
                    .ok_or_else(|| error("incomplete receipt index"))?;
                if receipt.block_hash != block.hash || receipt.block_number != block.number {
                    return Err(error("receipt belongs to another revision"));
                }
                Ok(receipt)
            })
            .collect::<RpcResult<Vec<_>>>()?;
        // Execution groups native submissions first while preserving order within each group.
        receipts.sort_by_key(|receipt| receipt.signer_did.is_none());
        let receipts = receipts
            .into_iter()
            .map(|r| {
                ExecutionReceipt::new(
                    r.transaction_hash,
                    r.status,
                    r.gas_used,
                    r.cumulative_gas_used,
                    r.logs
                        .into_iter()
                        .map(|l| Log::new_unchecked(l.address, l.topics, l.data))
                        .collect(),
                    r.contract_address,
                )
            })
            .collect::<Vec<_>>();
        encoded_size(&receipts, 8 << 20).map_err(request_error)?;
        let response = ReceiptResponse {
            revision,
            gas_limit: block.gas_limit,
            receipts,
        };
        encoded_size(&response, RECEIPT_RESPONSE_BYTES - 1024).map_err(request_error)?;
        Ok(Some(response))
    }
}
