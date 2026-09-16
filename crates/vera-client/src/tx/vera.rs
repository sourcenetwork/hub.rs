//! Vera state-changing transactions via `eth_sendRawTransaction` to precompile `0x0812`.

use alloy_sol_types::SolCall;
use vera_modules::vera::abi::IVera;

use crate::client::{VERA_ADDRESS, VeraClient};
use crate::error::ClientError;
use crate::signer::EvmSigner;
use crate::types::TransactionReceipt;

impl VeraClient {
    /// Revoke a signed delegation, including one that has never been used.
    pub async fn revoke_delegation(
        &self,
        signer: &EvmSigner,
        token: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IVera::revokeDelegationCall {
            token: token.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, VERA_ADDRESS, calldata.into())
            .await
    }

    /// Invalidate a JWS token by its hash.
    pub async fn invalidate_jws(
        &self,
        signer: &EvmSigner,
        token_hash: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IVera::invalidateJWSCall {
            tokenHash: token_hash.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, VERA_ADDRESS, calldata.into())
            .await
    }
}

#[cfg(test)]
mod tests {
    use alloy_sol_types::SolCall;
    use vera_modules::vera::abi::IVera;

    #[test]
    fn invalidate_jws_calldata_roundtrip() {
        let call = IVera::invalidateJWSCall {
            tokenHash: "abc123".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IVera::invalidateJWSCall as SolCall>::SELECTOR
        );
        let decoded = IVera::invalidateJWSCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.tokenHash, "abc123");
    }
}
