use vera_crypto::bls;

use super::*;

pub(super) struct AuthenticatedNativeTx {
    pub(super) native_tx: NativeTx,
    pub(super) signer_did: String,
}

impl VeraExecutor {
    pub(super) fn authenticate_native_tx(
        &self,
        tx_bytes: &[u8],
    ) -> Result<AuthenticatedNativeTx, ExecutionError> {
        let native_tx = NativeTx::decode_wire(tx_bytes)
            .map_err(|e| ExecutionError::TxDecode(format!("native tx: {e}")))?;
        if native_tx.chain_id != self.config.chain_id {
            return Err(ExecutionError::ChainIdMismatch {
                expected: self.config.chain_id,
                got: native_tx.chain_id,
            });
        }
        let signer_did = bls::verify_and_identify(
            native_tx.bls_pubkey.as_slice(),
            &native_tx.signing_data(),
            native_tx.signature.as_slice(),
        )
        .map_err(|e| ExecutionError::BlsVerification(format!("signature: {e}")))?;
        if native_tx.target != ACP_ADDRESS
            && native_tx.target != BULLETIN_ADDRESS
            && native_tx.target != VERA_ADDRESS
            && native_tx.target != VALIDATOR_REGISTRY_ADDRESS
        {
            return Err(ExecutionError::UnknownNativeTarget(native_tx.target));
        }
        Ok(AuthenticatedNativeTx {
            native_tx,
            signer_did,
        })
    }
}
