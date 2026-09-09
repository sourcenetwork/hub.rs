//! Certified access decisions bound to the consumer's expected request.

use hub_domain::ConsensusPublicKey;
use hub_modules::{
    acp::{decision::DecisionRequest, keys, types::AccessDecision},
    types::Timestamp,
};
use hub_permission::{ModuleId, RECORD_PROOF_BYTES};

use crate::{ClientError, HubClient};

/// A decision valid at the selected revision, or certified absence.
#[derive(Clone, Debug)]
pub struct DecisionRecord {
    /// Finalized revision authenticating this record.
    pub revision: u64,
    /// Execution timestamp of the selected revision.
    pub timestamp: u64,
    /// Decision bound to the expected request; expired or invalid records are errors.
    pub value: Option<AccessDecision>,
}

impl HubClient {
    /// Verify a recorded decision's request, issuance and lifetime at certified state.
    /// This does not re-evaluate permission after subsequent policy changes.
    pub async fn read_access_decision(
        &self,
        expected: &DecisionRequest,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<DecisionRecord, ClientError> {
        let id = expected
            .id()
            .map_err(|_| ClientError::InvalidResponse("invalid access decision request"))?;
        let response = self
            .read_current_record(
                ModuleId::Acp,
                &keys::access_decision_key(&id),
                minimum,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await?;
        let value = response
            .record
            .value
            .as_ref()
            .map(|bytes| {
                expected
                    .verify_record(
                        bytes,
                        &Timestamp {
                            seconds: response.revision.timestamp,
                            block_height: response.revision.height,
                        },
                    )
                    .map_err(|_| ClientError::InvalidResponse("invalid or expired access decision"))
            })
            .transpose()?;
        Ok(DecisionRecord {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            value,
        })
    }
}
