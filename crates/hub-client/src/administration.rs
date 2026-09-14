//! Operator approvals and administrative submission.

use alloy_sol_types::SolCall;
use hub_modules::hub::abi::IHub;
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _};

pub use hub_modules::hub::administration::{
    AdministrationState, AdministrativeCommand, AdministrativeRequest, OperatorApproval,
    OperatorPolicy, SignedAdministrativeRequest,
};

use crate::{BlsSigner, ClientError, EvmSigner, HUB_ADDRESS, HubClient, TransactionReceipt};

/// Sign an explicit request using this key's index in the current operator policy.
pub fn approve_administration(
    request: &AdministrativeRequest,
    signer: u16,
    key: &SigningKey,
) -> Result<OperatorApproval, ClientError> {
    let digest = request
        .signing_digest()
        .map_err(|error| ClientError::Signing(error.to_string()))?;
    let signature: Signature = key
        .sign_prehash(&digest)
        .map_err(|error| ClientError::Signing(error.to_string()))?;
    Ok(OperatorApproval {
        signer,
        signature: hex::encode(signature.to_bytes()),
    })
}

/// Operator configuration or certified absence at a finalized revision.
#[derive(Clone, Debug)]
pub struct AdministrationRecord {
    /// Revision authenticating this configuration.
    pub revision: u64,
    /// Execution timestamp of that revision.
    pub timestamp: u64,
    /// Current operator policy and next administrative sequence.
    pub value: Option<AdministrationState>,
}

fn decode_state(bytes: &[u8]) -> Result<AdministrationState, ClientError> {
    let state: AdministrationState = borsh::from_slice(bytes)
        .map_err(|_| ClientError::InvalidResponse("invalid administration encoding"))?;
    state
        .policy
        .validate()
        .map_err(|_| ClientError::InvalidResponse("invalid operator policy"))?;
    Ok(state)
}

/// ACP configuration or certified absence at a finalized revision.
#[derive(Clone, Debug)]
pub struct AcpParameterRecord {
    /// Revision authenticating this configuration.
    pub revision: u64,
    /// Execution timestamp of that revision.
    pub timestamp: u64,
    /// Stored parameters; absence selects `AcpParams::default()` during execution.
    pub value: Option<hub_modules::acp::types::AcpParams>,
}

impl HubClient {
    /// Read ACP parameters from certified native state, distinguishing absence from corruption.
    pub async fn read_acp_parameters(
        &self,
        minimum: u64,
        trusted: &hub_domain::ConsensusPublicKey,
    ) -> Result<AcpParameterRecord, ClientError> {
        let response = self
            .read_current_record(
                hub_permission::ModuleId::Acp,
                hub_modules::acp::keys::PARAMS_KEY,
                minimum,
                trusted,
                hub_permission::RECORD_PROOF_BYTES,
            )
            .await?;
        let value = response
            .record
            .value
            .as_ref()
            .map(|bytes| {
                borsh::from_slice(bytes)
                    .map_err(|_| ClientError::InvalidResponse("invalid ACP parameter encoding"))
            })
            .transpose()?;
        Ok(AcpParameterRecord {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            value,
        })
    }

    /// Verify the current operator policy and sequence using independently configured consensus trust.
    pub async fn read_administration(
        &self,
        minimum: u64,
        trusted: &hub_domain::ConsensusPublicKey,
    ) -> Result<AdministrationRecord, ClientError> {
        let response = self
            .read_current_record(
                hub_permission::ModuleId::Hub,
                hub_modules::hub::administration::STATE_KEY,
                minimum,
                trusted,
                hub_permission::RECORD_PROOF_BYTES,
            )
            .await?;
        let value = response
            .record
            .value
            .as_ref()
            .map(|bytes| decode_state(bytes))
            .transpose()?;
        Ok(AdministrationRecord {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            value,
        })
    }

    /// Fetch the current operator policy and next administrative sequence.
    pub async fn administration(&self) -> Result<Option<AdministrationState>, ClientError> {
        let result = self
            .eth_call(
                HUB_ADDRESS,
                IHub::getAdministrationCall {}.abi_encode().into(),
            )
            .await?;
        let bytes = IHub::getAdministrationCall::abi_decode_returns(&result)
            .map_err(|error| ClientError::AbiDecode(error.to_string()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Submit operator approvals through an independent BLS submitter.
    pub async fn native_apply_administration(
        &self,
        submitter: &BlsSigner,
        signed: &SignedAdministrativeRequest,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IHub::applyAdministrationCall {
            request: serde_json::to_vec(signed)?.into(),
        }
        .abi_encode();
        self.send_native_precompile_tx(submitter, HUB_ADDRESS, calldata.into())
            .await
    }

    /// Submit operator approvals through an independent secp256k1 submitter.
    pub async fn apply_administration(
        &self,
        submitter: &EvmSigner,
        signed: &SignedAdministrativeRequest,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IHub::applyAdministrationCall {
            request: serde_json::to_vec(signed)?.into(),
        }
        .abi_encode();
        self.send_precompile_tx(submitter, HUB_ADDRESS, calldata.into())
            .await
    }
}

#[cfg(test)]
mod certified_tests {
    use super::*;

    #[test]
    fn certified_administration_rejects_malformed_policy_and_encoding() {
        let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let mut state = AdministrationState {
            policy: OperatorPolicy {
                threshold: 1,
                keys: vec![hex::encode(key.verifying_key().to_sec1_bytes())],
            },
            sequence: 7,
            membership_policy: Some([3; 32]),
        };
        let bytes = borsh::to_vec(&state).unwrap();
        assert_eq!(decode_state(&bytes).unwrap(), state);
        assert!(decode_state(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_state(&trailing).is_err());
        state.policy.threshold = 0;
        assert!(decode_state(&borsh::to_vec(&state).unwrap()).is_err());
        state.policy.threshold = 1;
        state.policy.keys.push(state.policy.keys[0].clone());
        assert!(decode_state(&borsh::to_vec(&state).unwrap()).is_err());
    }
}
