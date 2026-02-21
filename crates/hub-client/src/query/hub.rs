//! Hub read-only queries via `eth_call` to precompile `0x0812`.

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::SolCall;
use hub_modules::hub::abi::IHub;

use crate::client::{HUB_ADDRESS, HubClient};
use crate::error::ClientError;

impl HubClient {
    /// Look up a JWS token record by hash.
    pub async fn get_jws_token(&self, token_hash: &str) -> Result<(bool, Bytes), ClientError> {
        let calldata = IHub::getJWSTokenCall {
            tokenHash: token_hash.into(),
        }
        .abi_encode();
        let result = self.eth_call(HUB_ADDRESS, calldata.into()).await?;
        let decoded = IHub::getJWSTokenCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok((decoded.found, decoded.record))
    }

    /// Look up all JWS tokens issued by a DID.
    pub async fn get_jws_tokens_by_did(&self, did: &str) -> Result<Bytes, ClientError> {
        let calldata = IHub::getJWSTokensByDidCall { did: did.into() }.abi_encode();
        let result = self.eth_call(HUB_ADDRESS, calldata.into()).await?;
        let decoded = IHub::getJWSTokensByDidCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// Look up all JWS tokens authorized for an account.
    pub async fn get_jws_tokens_by_account(&self, account: Address) -> Result<Bytes, ClientError> {
        let calldata = IHub::getJWSTokensByAccountCall { account }.abi_encode();
        let result = self.eth_call(HUB_ADDRESS, calldata.into()).await?;
        let decoded = IHub::getJWSTokensByAccountCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// Fetch the chain configuration.
    pub async fn get_chain_config(&self) -> Result<Bytes, ClientError> {
        let calldata = IHub::getChainConfigCall {}.abi_encode();
        let result = self.eth_call(HUB_ADDRESS, calldata.into()).await?;
        let decoded = IHub::getChainConfigCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }

    /// Fetch current Hub module parameters.
    pub async fn get_hub_params(&self) -> Result<Bytes, ClientError> {
        let calldata = IHub::getParamsCall {}.abi_encode();
        let result = self.eth_call(HUB_ADDRESS, calldata.into()).await?;
        let decoded = IHub::getParamsCall::abi_decode_returns(&result)
            .map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_jws_token_calldata_roundtrip() {
        let call = IHub::getJWSTokenCall {
            tokenHash: "abc123def456".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(&encoded[..4], <IHub::getJWSTokenCall as SolCall>::SELECTOR);
        let decoded = IHub::getJWSTokenCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.tokenHash, "abc123def456");
    }

    #[test]
    fn get_jws_tokens_by_did_calldata_roundtrip() {
        let call = IHub::getJWSTokensByDidCall {
            did: "did:key:z6Mk...".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IHub::getJWSTokensByDidCall as SolCall>::SELECTOR
        );
        let decoded = IHub::getJWSTokensByDidCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.did, "did:key:z6Mk...");
    }

    #[test]
    fn get_jws_tokens_by_account_calldata_roundtrip() {
        let account = Address::repeat_byte(0x42);
        let call = IHub::getJWSTokensByAccountCall { account };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IHub::getJWSTokensByAccountCall as SolCall>::SELECTOR
        );
        let decoded = IHub::getJWSTokensByAccountCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.account, account);
    }

    #[test]
    fn get_chain_config_calldata_selector() {
        let calldata = IHub::getChainConfigCall {}.abi_encode();
        assert_eq!(calldata.len(), 4);
        assert_eq!(
            &calldata[..4],
            <IHub::getChainConfigCall as SolCall>::SELECTOR
        );
    }

    #[test]
    fn get_params_calldata_selector() {
        let calldata = IHub::getParamsCall {}.abi_encode();
        assert_eq!(calldata.len(), 4);
        assert_eq!(&calldata[..4], <IHub::getParamsCall as SolCall>::SELECTOR);
    }
}
