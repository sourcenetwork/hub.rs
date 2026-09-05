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

impl HubClient {
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
