//! DocumentACP implementation backed by hub-client.

use async_trait::async_trait;
use identity::Did;

use acp::{DocumentACP, DocumentPermission, Identity, Result};

use crate::client::{HubClient, parse_policy_id};
use crate::error::ClientError;
use crate::signer::EvmSigner;
use crate::types::TransactionReceipt;

/// DocumentACP backed by hub's on-chain ACP precompile.
///
/// Delegates write operations through [`EvmSigner`] and read operations
/// through [`HubClient`] to the ACP precompile at `0x0810`.
#[derive(Debug)]
pub struct HubDocumentACP {
    client: HubClient,
    signer: EvmSigner,
}

impl HubDocumentACP {
    /// Create a new `HubDocumentACP`.
    pub const fn new(client: HubClient, signer: EvmSigner) -> Self {
        Self { client, signer }
    }

    /// Create a policy on-chain via the ACP precompile.
    pub async fn add_policy(
        &self,
        policy: &[u8],
        marshal_type: u8,
    ) -> std::result::Result<TransactionReceipt, ClientError> {
        self.client
            .create_policy(&self.signer, policy, marshal_type)
            .await
    }
}

fn client_err(e: ClientError) -> acp::Error {
    acp::Error::Storage(format!("hub: {e}"))
}

#[async_trait]
impl DocumentACP for HubDocumentACP {
    async fn register_doc_object(
        &self,
        _identity: &Did,
        policy_id: &str,
        resource_name: &str,
        doc_id: &str,
    ) -> Result<()> {
        let pid = parse_policy_id(policy_id).map_err(client_err)?;
        self.client
            .register_object(&self.signer, pid, doc_id, resource_name)
            .await
            .map_err(client_err)?;
        Ok(())
    }

    async fn is_doc_registered(
        &self,
        policy_id: &str,
        resource_name: &str,
        doc_id: &str,
    ) -> Result<bool> {
        let pid = parse_policy_id(policy_id).map_err(client_err)?;
        let (registered, _owner) = self
            .client
            .get_object_owner(pid, resource_name, doc_id)
            .await
            .map_err(client_err)?;
        Ok(registered)
    }

    async fn check_doc_access(
        &self,
        identity: &Identity,
        permission: DocumentPermission,
        policy_id: &str,
        resource_name: &str,
        doc_id: &str,
    ) -> Result<bool> {
        let pid = parse_policy_id(policy_id).map_err(client_err)?;

        let (registered, _owner) = self
            .client
            .get_object_owner(pid, resource_name, doc_id)
            .await
            .map_err(client_err)?;

        if !registered {
            return Ok(true);
        }

        let actor_did = identity.did().map_or_else(
            || "did:key:anonymous".to_string(),
            |did| did.as_str().to_string(),
        );

        let permissions_to_check = if permission == DocumentPermission::Read {
            vec![
                DocumentPermission::Read,
                DocumentPermission::Update,
                DocumentPermission::Delete,
            ]
        } else {
            vec![permission]
        };

        for perm in permissions_to_check {
            let has_access = self
                .client
                .verify_access_request(
                    pid,
                    vec![resource_name.to_string()],
                    vec![doc_id.to_string()],
                    vec![perm.as_str().to_string()],
                    &actor_did,
                )
                .await
                .map_err(client_err)?;

            if has_access {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn add_actor_relationship(
        &self,
        _requestor: &Did,
        target: &Did,
        policy_id: &str,
        collection_id: &str,
        doc_id: &str,
        relation: &str,
        _managing_relations: &[String],
    ) -> Result<bool> {
        let pid = parse_policy_id(policy_id).map_err(client_err)?;
        self.client
            .set_relationship(
                &self.signer,
                pid,
                collection_id,
                doc_id,
                relation,
                target.as_str(),
            )
            .await
            .map_err(client_err)?;
        Ok(true)
    }

    async fn delete_actor_relationship(
        &self,
        _requestor: &Did,
        target: &Did,
        policy_id: &str,
        collection_id: &str,
        doc_id: &str,
        relation: &str,
        _managing_relations: &[String],
    ) -> Result<bool> {
        let pid = parse_policy_id(policy_id).map_err(client_err)?;
        self.client
            .delete_relationship(
                &self.signer,
                pid,
                collection_id,
                doc_id,
                relation,
                target.as_str(),
            )
            .await
            .map_err(client_err)?;
        Ok(true)
    }

    async fn unregister_doc_object(
        &self,
        policy_id: &str,
        resource_name: &str,
        doc_id: &str,
    ) -> Result<()> {
        let pid = parse_policy_id(policy_id).map_err(client_err)?;
        self.client
            .archive_object(&self.signer, pid, doc_id, resource_name)
            .await
            .map_err(client_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_document_acp_construction() {
        let client = HubClient::new("http://localhost:8545");
        let signer = EvmSigner::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
            1337,
        )
        .unwrap();
        let _dac = HubDocumentACP::new(client, signer);
    }
}
