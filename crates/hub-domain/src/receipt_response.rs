use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

use crate::{ConsensusPublicKey, ExecutionReceipt, LightBlock, LightBlockError};

/// Transport budget for a finalized revision and its committed receipts.
pub const RECEIPT_RESPONSE_BYTES: usize = crate::LIGHT_BLOCK_RESPONSE_BYTES + (8 << 20);

/// Complete ordered receipt evidence for one finalized revision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptResponse {
    /// Finality evidence checked against independently configured consensus trust.
    pub revision: LightBlock,
    /// Execution limit included in the receipt commitment.
    pub gas_limit: u64,
    /// Receipts in the committed execution order.
    pub receipts: Vec<ExecutionReceipt>,
}

/// Receipt evidence failed verification.
#[derive(Debug, thiserror::Error)]
pub enum ReceiptResponseError {
    /// Finality evidence is invalid.
    #[error(transparent)]
    Finality(#[from] LightBlockError),
    /// Receipt fields do not satisfy the committed response contract.
    #[error("invalid receipt evidence: {0}")]
    Invalid(&'static str),
}

impl ReceiptResponse {
    /// Verify finality, the complete commitment and the requested submission ID.
    /// An absent response is not proof that a submission was rejected or never accepted.
    pub fn verify(
        &self,
        submission: B256,
        trusted: &ConsensusPublicKey,
    ) -> Result<&ExecutionReceipt, ReceiptResponseError> {
        let block = crate::verify_finalized_block(&self.revision, trusted)?;
        if self.receipts.len() != block.txs.len() {
            return Err(ReceiptResponseError::Invalid("receipt count"));
        }
        // The commitment encodes a boolean result, not legacy state-root statuses.
        if self
            .receipts
            .iter()
            .any(|r| !matches!(r.receipt.status, alloy_consensus::Eip658Value::Eip658(_)))
        {
            return Err(ReceiptResponseError::Invalid("receipt status"));
        }
        if block.receipt_commitment
            != Some(crate::receipt_commitment(self.gas_limit, &self.receipts))
        {
            return Err(ReceiptResponseError::Invalid("receipt commitment"));
        }
        let mut matches = self.receipts.iter().filter(|r| r.tx_hash == submission);
        let receipt = matches.next().ok_or(ReceiptResponseError::Invalid(
            "requested submission missing",
        ))?;
        if matches.next().is_some() {
            return Err(ReceiptResponseError::Invalid("duplicate submission"));
        }
        Ok(receipt)
    }
}
