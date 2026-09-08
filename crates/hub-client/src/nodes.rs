//! Threshold-service node commands with authority independent of the submission worker.

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use hub_domain::ConsensusPublicKey;
use hub_modules::hub::abi::IHub;
pub use hub_modules::hub::nodes::{
    NodeCommand, NodeInfo, NodeRecord, NodeRequest, NodeTarget, SignedNodeRequest,
};
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _};

use crate::{BlsSigner, ClientError, HUB_ADDRESS, HubClient, ModuleId, RECORD_PROOF_BYTES};

/// A certified node record or absence at one revision.
#[derive(Clone, Debug)]
pub struct NodeRead {
    /// Captured finalized revision.
    pub revision: u64,
    /// Captured revision's Unix timestamp.
    pub timestamp: u64,
    /// Validated service metadata, or certified absence.
    pub record: Option<NodeRecord>,
}

/// Sign the complete node request using the node key or current controller.
pub fn sign_node_request(
    request: NodeRequest,
    key: &SigningKey,
) -> Result<SignedNodeRequest, ClientError> {
    let digest = request
        .signing_digest()
        .map_err(|e| ClientError::Signing(e.to_string()))?;
    let signature: Signature = key
        .sign_prehash(&digest)
        .map_err(|e| ClientError::Signing(e.to_string()))?;
    Ok(SignedNodeRequest {
        request,
        signer_key: hex::encode(key.verifying_key().to_sec1_bytes()),
        signature: hex::encode(signature.to_bytes()),
    })
}

/// Encode a node command for `NativeWorker::prepare` before network submission.
pub fn encode_node_request(
    signed: &SignedNodeRequest,
) -> Result<alloy_primitives::Bytes, ClientError> {
    let request = serde_json::to_vec(signed)?;
    if request.len() > hub_modules::hub::nodes::MAX_NODE_BYTES {
        return Err(ClientError::Signing(
            "node request exceeds byte limit".into(),
        ));
    }
    Ok(IHub::applyNodeRequestCall {
        request: request.into(),
    }
    .abi_encode()
    .into())
}

impl HubClient {
    /// Submit an authorized node command. Retain the returned ID for certified receipt recovery.
    pub async fn submit_node_request(
        &self,
        submitter: &BlsSigner,
        signed: &SignedNodeRequest,
    ) -> Result<B256, ClientError> {
        let wire = submitter.sign_native_tx(HUB_ADDRESS, encode_node_request(signed)?)?;
        let expected: B256 = hub_domain::NativeTx::decode_wire(&wire)
            .map_err(|e| ClientError::Signing(e.to_string()))?
            .tx_id()
            .0;
        let submitted = self.send_native_tx(&wire).await?;
        if submitted != expected {
            return Err(ClientError::InvalidResponse(
                "node submission identifier mismatch",
            ));
        }
        Ok(submitted)
    }

    /// Read node metadata with caller-provided consensus trust and minimum revision.
    pub async fn read_threshold_node(
        &self,
        node_key: &str,
        minimum: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<NodeRead, ClientError> {
        let key = hub_modules::hub::nodes::node_key(node_key)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        let response = self
            .read_current_record(ModuleId::Hub, &key, minimum, trusted, RECORD_PROOF_BYTES)
            .await?;
        let record = response
            .record
            .value
            .map(|bytes| {
                if bytes.len() > hub_modules::hub::nodes::MAX_NODE_BYTES {
                    return Err(ClientError::InvalidResponse(
                        "node record exceeds byte limit",
                    ));
                }
                let record: NodeRecord = serde_json::from_slice(&bytes)?;
                record
                    .validate(node_key)
                    .map_err(|_| ClientError::InvalidResponse("invalid node record"))?;
                Ok::<_, ClientError>(record)
            })
            .transpose()?;
        Ok(NodeRead {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            record,
        })
    }
}
