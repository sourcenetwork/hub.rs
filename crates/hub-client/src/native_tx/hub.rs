//! Hub native BLS transactions via `hub_sendNativeTx` to precompile `0x0812`.

use alloy_sol_types::SolCall;
use hub_modules::hub::abi::IHub;

use crate::bls_signer::BlsSigner;
use crate::client::{HUB_ADDRESS, HubClient};
use crate::error::ClientError;
use crate::types::TransactionReceipt;

impl HubClient {
    /// Invalidate a JWS token by its hash via native BLS transaction.
    pub async fn native_invalidate_jws(
        &self,
        signer: &BlsSigner,
        token_hash: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IHub::invalidateJWSCall {
            tokenHash: token_hash.into(),
        }
        .abi_encode();
        self.send_native_precompile_tx(signer, HUB_ADDRESS, calldata.into())
            .await
    }
}

#[cfg(test)]
mod tests {
    use alloy_sol_types::SolCall;
    use hub_modules::hub::abi::IHub;

    #[test]
    fn native_invalidate_jws_calldata_roundtrip() {
        let call = IHub::invalidateJWSCall {
            tokenHash: "abc123".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IHub::invalidateJWSCall as SolCall>::SELECTOR
        );
        let decoded = IHub::invalidateJWSCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.tokenHash, "abc123");
    }
}
