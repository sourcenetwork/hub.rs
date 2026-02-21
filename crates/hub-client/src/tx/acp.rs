//! ACP state-changing transactions via `eth_sendRawTransaction` to precompile `0x0810`.

use alloy_primitives::FixedBytes;
use alloy_sol_types::SolCall;
use hub_modules::acp::abi::IAcp;

use crate::client::{ACP_ADDRESS, HubClient};
use crate::error::ClientError;
use crate::signer::EvmSigner;
use crate::types::TransactionReceipt;

impl HubClient {
    /// Create a new ACP policy.
    pub async fn create_policy(
        &self,
        signer: &EvmSigner,
        policy: &[u8],
        marshal_type: u8,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IAcp::createPolicyCall {
            policy: policy.to_vec().into(),
            marshalType: marshal_type,
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }

    /// Set a relationship in an ACP policy.
    pub async fn set_relationship(
        &self,
        signer: &EvmSigner,
        policy_id: FixedBytes<32>,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IAcp::setRelationshipCall {
            policyId: policy_id,
            resource: resource.into(),
            objectId: object_id.into(),
            relation: relation.into(),
            actor: actor.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }

    /// Delete a relationship from an ACP policy.
    pub async fn delete_relationship(
        &self,
        signer: &EvmSigner,
        policy_id: FixedBytes<32>,
        resource: &str,
        object_id: &str,
        relation: &str,
        actor: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IAcp::deleteRelationshipCall {
            policyId: policy_id,
            resource: resource.into(),
            objectId: object_id.into(),
            relation: relation.into(),
            actor: actor.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }

    /// Register an object in an ACP policy.
    pub async fn register_object(
        &self,
        signer: &EvmSigner,
        policy_id: FixedBytes<32>,
        object_id: &str,
        resource: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IAcp::registerObjectCall {
            policyId: policy_id,
            objectId: object_id.into(),
            resource: resource.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }

    /// Archive an object in an ACP policy.
    pub async fn archive_object(
        &self,
        signer: &EvmSigner,
        policy_id: FixedBytes<32>,
        object_id: &str,
        resource: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IAcp::archiveObjectCall {
            policyId: policy_id,
            objectId: object_id.into(),
            resource: resource.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }

    /// Check access (persists a decision record on-chain).
    pub async fn check_access(
        &self,
        signer: &EvmSigner,
        policy_id: FixedBytes<32>,
        resources: Vec<String>,
        object_ids: Vec<String>,
        permissions: Vec<String>,
        actor: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        let calldata = IAcp::checkAccessCall {
            policyId: policy_id,
            resources,
            objectIds: object_ids,
            permissions,
            actor: actor.into(),
        }
        .abi_encode();
        self.send_precompile_tx(signer, ACP_ADDRESS, calldata.into())
            .await
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::FixedBytes;
    use alloy_sol_types::SolCall;
    use hub_modules::acp::abi::IAcp;

    #[test]
    fn create_policy_calldata_roundtrip() {
        let call = IAcp::createPolicyCall {
            policy: b"name: test".to_vec().into(),
            marshalType: 1,
        };
        let encoded = call.abi_encode();
        assert_eq!(&encoded[..4], <IAcp::createPolicyCall as SolCall>::SELECTOR);
        let decoded = IAcp::createPolicyCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.marshalType, 1);
    }

    #[test]
    fn set_relationship_calldata_roundtrip() {
        let call = IAcp::setRelationshipCall {
            policyId: FixedBytes::ZERO,
            resource: "namespace".into(),
            objectId: "obj1".into(),
            relation: "collaborator".into(),
            actor: "did:key:z123".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IAcp::setRelationshipCall as SolCall>::SELECTOR
        );
        let decoded = IAcp::setRelationshipCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.resource, "namespace");
        assert_eq!(decoded.relation, "collaborator");
    }

    #[test]
    fn delete_relationship_calldata_roundtrip() {
        let call = IAcp::deleteRelationshipCall {
            policyId: FixedBytes::ZERO,
            resource: "namespace".into(),
            objectId: "obj1".into(),
            relation: "collaborator".into(),
            actor: "did:key:z123".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IAcp::deleteRelationshipCall as SolCall>::SELECTOR
        );
        let decoded = IAcp::deleteRelationshipCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.objectId, "obj1");
    }

    #[test]
    fn register_object_calldata_roundtrip() {
        let call = IAcp::registerObjectCall {
            policyId: FixedBytes::ZERO,
            objectId: "obj1".into(),
            resource: "namespace".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IAcp::registerObjectCall as SolCall>::SELECTOR
        );
        let decoded = IAcp::registerObjectCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.objectId, "obj1");
        assert_eq!(decoded.resource, "namespace");
    }

    #[test]
    fn archive_object_calldata_roundtrip() {
        let call = IAcp::archiveObjectCall {
            policyId: FixedBytes::ZERO,
            objectId: "obj1".into(),
            resource: "namespace".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            <IAcp::archiveObjectCall as SolCall>::SELECTOR
        );
        let decoded = IAcp::archiveObjectCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.objectId, "obj1");
    }

    #[test]
    fn check_access_calldata_roundtrip() {
        let call = IAcp::checkAccessCall {
            policyId: FixedBytes::ZERO,
            resources: vec!["namespace".into()],
            objectIds: vec!["obj1".into()],
            permissions: vec!["create_post".into()],
            actor: "did:key:z123".into(),
        };
        let encoded = call.abi_encode();
        assert_eq!(&encoded[..4], <IAcp::checkAccessCall as SolCall>::SELECTOR);
        let decoded = IAcp::checkAccessCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.resources, vec!["namespace"]);
        assert_eq!(decoded.permissions, vec!["create_post"]);
    }
}
