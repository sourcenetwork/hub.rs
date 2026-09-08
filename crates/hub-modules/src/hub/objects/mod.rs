//! Immutable encrypted documents and signing derivations used by threshold services.
#![allow(missing_docs)]

mod types;
pub use types::*;

#[cfg(test)]
mod tests;

use super::{HubError, HubModule, Result, rings::RingState};
use crate::kv_store::ModuleKvStore;
use crate::{
    acp::{AcpModule, delegated_operation::DelegatedOperation},
    types::{BlockExecCtx, TxExecCtx},
};

fn invalid(error: impl std::fmt::Display) -> HubError {
    HubError::InvalidThresholdObject {
        reason: error.to_string(),
    }
}

impl HubModule {
    pub fn threshold_object(&self, kind: ObjectKind, id: &str) -> Result<Option<ObjectRecord>> {
        self.store
            .get(&object_key(kind, id)?)
            .map(|bytes| {
                if bytes.len() > MAX_OBJECT_RECORD_BYTES {
                    return Err(invalid("object record exceeds byte limit"));
                }
                let record: ObjectRecord = serde_json::from_slice(&bytes).map_err(invalid)?;
                record.validate(kind, id)?;
                Ok(record)
            })
            .transpose()
    }

    /// Registration records a binding; it does not grant access or verify encryption proofs.
    pub fn store_threshold_object(
        &mut self,
        acp: &mut AcpModule,
        context: &BlockExecCtx,
        submission: &TxExecCtx,
        token: &str,
        object: &ThresholdObject,
    ) -> Result<StoredObject> {
        object.validate()?;
        let operation = DelegatedOperation::StoreThresholdObject(object);
        acp.with_delegation(
            self,
            context,
            submission,
            token,
            (operation.scope(), operation.digest().map_err(invalid)?),
            |_, hub, actor| {
                let store = || -> Result<(Vec<u8>, Vec<u8>, StoredObject)> {
                    let ring = hub
                        .threshold_ring(object.ring_id())?
                        .ok_or_else(|| invalid("ring not found"))?;
                    if ring.deployment_root != context.genesis_id
                        || !matches!(ring.state, RingState::Active { .. })
                    {
                        return Err(invalid("ring is not active in this deployment"));
                    }
                    let id = object.id()?;
                    let kind = object.kind();
                    let key = object_key(kind, &id)?;
                    if hub.store.get_ref(&key).is_some() {
                        return Err(invalid("object identity already registered"));
                    }
                    let record = ObjectRecord {
                        id: id.clone(),
                        deployment_root: context.genesis_id,
                        creator: actor.to_string(),
                        revision: context.timestamp.clone(),
                        object: object.clone(),
                    };
                    record.validate(kind, &id)?;
                    let bytes = serde_json::to_vec(&record).map_err(invalid)?;
                    if bytes.len() > MAX_OBJECT_RECORD_BYTES {
                        return Err(invalid("object record exceeds byte limit"));
                    }
                    Ok((
                        key,
                        bytes,
                        StoredObject {
                            id,
                            kind,
                            revision: context.timestamp.clone(),
                        },
                    ))
                };
                let (key, bytes, result) =
                    store().map_err(|e| crate::acp::error::AcpError::State(e.to_string()))?;
                hub.store.put(&key, bytes);
                Ok(result)
            },
        )
        .map_err(invalid)
    }
}
