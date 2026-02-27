//! Bulletin state-changing transactions via `eth_sendRawTransaction` to precompile `0x0811`.

use alloy_sol_types::SolCall;
use hub_modules::bulletin::abi::IBulletin;

use crate::client::{BULLETIN_ADDRESS, HubClient};
use crate::error::ClientError;
use crate::signer::EvmSigner;
use crate::types::TransactionReceipt;

impl HubClient {
    /// Register a new bulletin namespace.
    pub async fn register_namespace(
        &self,
        signer: &EvmSigner,
        namespace: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IBulletin::registerNamespaceCall {
            namespace: namespace.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, BULLETIN_ADDRESS, calldata.into())
            .await
    }

    /// Create a post in a bulletin namespace.
    pub async fn create_post(
        &self,
        signer: &EvmSigner,
        namespace: &str,
        payload: &[u8],
        proof: &[u8],
        artifact: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IBulletin::createPostCall {
            namespace: namespace.into(),
            payload: payload.to_vec().into(),
            proof: proof.to_vec().into(),
            artifact: artifact.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, BULLETIN_ADDRESS, calldata.into())
            .await
    }

    /// Add a collaborator to a bulletin namespace.
    pub async fn add_collaborator(
        &self,
        signer: &EvmSigner,
        namespace: &str,
        collaborator_did: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IBulletin::addCollaboratorCall {
            namespace: namespace.into(),
            collaboratorDid: collaborator_did.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, BULLETIN_ADDRESS, calldata.into())
            .await
    }

    /// Remove a collaborator from a bulletin namespace.
    pub async fn remove_collaborator(
        &self,
        signer: &EvmSigner,
        namespace: &str,
        collaborator_did: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IBulletin::removeCollaboratorCall {
            namespace: namespace.into(),
            collaboratorDid: collaborator_did.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, BULLETIN_ADDRESS, calldata.into())
            .await
    }
}

#[cfg(test)]
mod tests {
    use alloy_sol_types::SolCall;
    use hub_modules::bulletin::abi::IBulletin;

    #[test]
    fn register_namespace_calldata_roundtrip() {
        let call = IBulletin::registerNamespaceCall {
            namespace: "my-ns".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IBulletin::registerNamespaceCall as SolCall>::SELECTOR
        );
        let decoded = IBulletin::registerNamespaceCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.namespace, "my-ns");
    }

    #[test]
    fn create_post_calldata_roundtrip() {
        let call = IBulletin::createPostCall {
            namespace: "ns".into(),
            payload: b"hello".to_vec().into(),
            proof: b"proof".to_vec().into(),
            artifact: "art".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IBulletin::createPostCall as SolCall>::SELECTOR
        );
        let decoded = IBulletin::createPostCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.namespace, "ns");
        assert_eq!(decoded.artifact, "art");
    }

    #[test]
    fn add_collaborator_calldata_roundtrip() {
        let did = "did:key:zQ3shunBKsXmCvYMBEaFbqqGMGb4PHQX4yLbPRjNSTbhnQhEd";
        let call = IBulletin::addCollaboratorCall {
            namespace: "ns".into(),
            collaboratorDid: did.into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IBulletin::addCollaboratorCall as SolCall>::SELECTOR
        );
        let decoded = IBulletin::addCollaboratorCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.collaboratorDid, did);
    }

    #[test]
    fn remove_collaborator_calldata_roundtrip() {
        let did = "did:key:zQ3shunBKsXmCvYMBEaFbqqGMGb4PHQX4yLbPRjNSTbhnQhEd";
        let call = IBulletin::removeCollaboratorCall {
            namespace: "ns".into(),
            collaboratorDid: did.into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IBulletin::removeCollaboratorCall as SolCall>::SELECTOR
        );
        let decoded = IBulletin::removeCollaboratorCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.collaboratorDid, did);
    }
}
