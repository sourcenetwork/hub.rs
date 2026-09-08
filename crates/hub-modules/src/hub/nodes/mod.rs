//! Authenticated threshold-service node registration and controller management.

mod types;
pub use types::*;

use super::{HubError, HubModule, Result};
use crate::{kv_store::ModuleKvStore as _, types::BlockExecCtx};

/// Storage key for one canonical service node identity.
pub fn node_key(key: &str) -> Result<Vec<u8>> {
    types::validate_key(key)?;
    Ok(format!("orbis/node/v1/{key}").into_bytes())
}

pub(super) fn invalid(error: impl std::fmt::Display) -> HubError {
    HubError::InvalidNodeRequest {
        reason: error.to_string(),
    }
}

impl HubModule {
    /// Read a service node, rejecting corrupt metadata instead of treating it as absent.
    pub fn threshold_node(&self, key: &str) -> Result<Option<NodeRecord>> {
        self.store
            .get(&node_key(key)?)
            .map(|bytes| {
                if bytes.len() > MAX_NODE_BYTES {
                    return Err(invalid("node record exceeds byte limit"));
                }
                let record: NodeRecord = serde_json::from_slice(&bytes).map_err(invalid)?;
                record.validate(key)?;
                Ok(record)
            })
            .transpose()
    }

    /// Authenticate and apply one node command; failures leave the record and sequence unchanged.
    pub fn apply_node_request(
        &mut self,
        context: &BlockExecCtx,
        signed: &SignedNodeRequest,
    ) -> Result<NodeRecord> {
        if serde_json::to_vec(signed).map_err(invalid)?.len() > MAX_NODE_BYTES {
            return Err(invalid("node request exceeds byte limit"));
        }
        let request = &signed.request;
        if request.deployment_root != context.genesis_id
            || request.deployment_id != context.deployment_id
            || request.expires_at < context.timestamp.seconds
        {
            return Err(invalid("node request deployment or expiry"));
        }
        let storage_key = node_key(&request.node_key)?;
        let current = self.threshold_node(&request.node_key)?;
        let (expected, authority) = match (&request.command, &current) {
            (NodeCommand::Register(_), None) => (0, &request.node_key),
            (NodeCommand::Register(_), Some(_)) => return Err(invalid("node already registered")),
            (_, Some(record)) => (record.sequence, &record.info.controller_key),
            (_, None) => return Err(invalid("node not registered")),
        };
        if request.sequence != expected || &signed.signer_key != authority {
            return Err(invalid("node sequence or controller mismatch"));
        }
        let public_key = types::validate_key(&signed.signer_key)?;
        if signed.signature.len() != 128 {
            return Err(invalid("invalid node signature length"));
        }
        let signature = hex::decode(&signed.signature).map_err(invalid)?;
        if hex::encode(&signature) != signed.signature {
            return Err(invalid("noncanonical node signature"));
        }
        hub_crypto::secp256k1::verify_digest(&public_key, &request.signing_digest()?, &signature)
            .map_err(invalid)?;
        let next_sequence = expected
            .checked_add(1)
            .ok_or_else(|| invalid("node sequence exhausted"))?;
        let mut info = match &request.command {
            NodeCommand::Register(info) => info.clone(),
            _ => current.ok_or_else(|| invalid("node not registered"))?.info,
        };
        match &request.command {
            NodeCommand::Register(_) => {}
            NodeCommand::SetPeer(peer) => {
                if info.peer_id == *peer {
                    return Err(invalid("node peer unchanged"));
                }
                info.peer_id.clone_from(peer);
            }
            NodeCommand::TransferController(controller) => {
                if info.controller_key == *controller {
                    return Err(invalid("node controller unchanged"));
                }
                info.controller_key.clone_from(controller);
            }
            NodeCommand::Allow(target) | NodeCommand::Disallow(target) => {
                let (entries, id) = match target {
                    NodeTarget::Policy(id) => (&mut info.allowed_policy_ids, id),
                    NodeTarget::Ring(id) => (&mut info.allowed_ring_ids, id),
                };
                types::identifier(id, 128)?;
                match (entries.binary_search(id), &request.command) {
                    (Err(index), NodeCommand::Allow(_)) => entries.insert(index, id.clone()),
                    (Ok(index), NodeCommand::Disallow(_)) => {
                        entries.remove(index);
                    }
                    _ => return Err(invalid("node target already present or absent")),
                }
            }
        }
        info.validate()?;
        let record = NodeRecord {
            node_key: request.node_key.clone(),
            info,
            sequence: next_sequence,
        };
        let bytes = serde_json::to_vec(&record).map_err(invalid)?;
        if bytes.len() > MAX_NODE_BYTES {
            return Err(invalid("node record exceeds byte limit"));
        }
        self.store.put(&storage_key, bytes);
        Ok(record)
    }
}

#[cfg(test)]
mod tests;
