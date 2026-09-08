//! Durable command encoding and certified reads for threshold-service rings.

use alloy_primitives::Bytes;
use alloy_sol_types::SolCall as _;
use hub_domain::ConsensusPublicKey;
use hub_modules::hub::abi::IHub;
pub use hub_modules::hub::rings::reports::{
    CommitteeScope, NodeDemerits, NodeOffline, ReportEnvelope, ReportOutcome, SignedReport,
};
pub use hub_modules::hub::rings::{
    ReportingConfig, ReshareTarget, RingCommand, RingConfig, RingParticipantCommand,
    RingParticipantRequest, RingRecord, RingReshareRequest, RingSettings, RingState, RingUpdate,
    ScheduledUpgrade, SignedRingParticipantRequest, ThresholdScheme, ring_deployment_label,
};
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _};

use crate::{ClientError, HubClient, ModuleId, RECORD_PROOF_BYTES};

/// Encode a delegated command for `NativeWorker::prepare(HUB_ADDRESS, calldata)`.
pub fn encode_ring_command(command: &RingCommand, token: &str) -> Result<Bytes, ClientError> {
    Ok(IHub::applyRingCommandCall {
        request: request_bytes(command)?,
        bearerToken: token.into(),
    }
    .abi_encode()
    .into())
}

/// Sign with the participating node's key, independent of its submission worker.
pub fn sign_ring_participant_request(
    request: RingParticipantRequest,
    key: &SigningKey,
) -> Result<SignedRingParticipantRequest, ClientError> {
    if request.node_key != hex::encode(key.verifying_key().to_sec1_bytes()) {
        return Err(ClientError::Signing("ring participant key mismatch".into()));
    }
    let digest = request
        .signing_digest()
        .map_err(|e| ClientError::Signing(e.to_string()))?;
    let signature: Signature = key
        .sign_prehash(&digest)
        .map_err(|e| ClientError::Signing(e.to_string()))?;
    Ok(SignedRingParticipantRequest {
        request,
        signature: hex::encode(signature.to_bytes()),
    })
}

/// Encode a participant request for durable preparation before submission.
pub fn encode_ring_participant_request(
    signed: &SignedRingParticipantRequest,
) -> Result<Bytes, ClientError> {
    Ok(IHub::applyRingParticipantRequestCall {
        request: request_bytes(signed)?,
    }
    .abi_encode()
    .into())
}

/// Encode a threshold-signed reshare for durable worker preparation.
pub fn encode_ring_reshare(request: &RingReshareRequest) -> Result<Bytes, ClientError> {
    Ok(IHub::finalizeRingReshareCall {
        request: request_bytes(request)?,
    }
    .abi_encode()
    .into())
}

/// Encode an aggregate-signed fault report for durable worker preparation.
pub fn encode_ring_report(report: &SignedReport) -> Result<Bytes, ClientError> {
    let bytes = serde_json::to_vec(report)?;
    if bytes.len() > hub_modules::hub::rings::reports::MAX_REPORT_REQUEST_BYTES {
        return Err(ClientError::Signing("report exceeds byte limit".into()));
    }
    Ok(IHub::submitRingReportCall {
        request: bytes.into(),
    }
    .abi_encode()
    .into())
}

fn request_bytes(request: &impl serde::Serialize) -> Result<Bytes, ClientError> {
    let bytes = serde_json::to_vec(request)?;
    if bytes.len() > hub_modules::hub::rings::MAX_RING_REQUEST_BYTES {
        return Err(ClientError::Signing(
            "ring request exceeds byte limit".into(),
        ));
    }
    Ok(bytes.into())
}

/// A certified ring state, including cancellation/conflict, or certified absence.
#[derive(Clone, Debug)]
pub struct RingRead {
    /// Finalized revision covering this read.
    pub revision: u64,
    /// Finalized revision's Unix timestamp.
    pub timestamp: u64,
    /// Authenticated and validated ring record.
    pub record: Option<RingRecord>,
}

impl HubClient {
    /// Read ring metadata against caller-provisioned consensus trust and minimum revision.
    pub async fn read_threshold_ring(
        &self,
        id: &str,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<RingRead, ClientError> {
        let key = hub_modules::hub::rings::ring_key(id)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        let response = self
            .read_current_record(ModuleId::Hub, &key, minimum, trusted, RECORD_PROOF_BYTES)
            .await?;
        let record = response
            .record
            .value
            .map(|bytes| {
                if bytes.len() > hub_modules::hub::rings::MAX_RING_RECORD_BYTES {
                    return Err(ClientError::InvalidResponse(
                        "ring record exceeds byte limit",
                    ));
                }
                let record: RingRecord = serde_json::from_slice(&bytes)?;
                record
                    .validate(id)
                    .map_err(|_| ClientError::InvalidResponse("invalid ring record"))?;
                Ok::<_, ClientError>(record)
            })
            .transpose()?;
        Ok(RingRead {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            record,
        })
    }
}
