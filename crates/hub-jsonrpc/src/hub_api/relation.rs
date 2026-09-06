use super::*;
use crate::error::codes;
use hub_domain::{
    RelationProofLimits,
    relation_index::{RELATION_INDEX_VERSION_KEY, is_relation_prefix, relation_count_key},
    verify_relation_prefix_proof,
};
use jsonrpsee::types::ErrorObjectOwned;

const MAX_RECORDS: usize = 1024;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_PREFIX_BYTES: usize = 4096;

fn unavailable(message: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(codes::RESOURCE_UNAVAILABLE, message.to_string(), None::<()>)
}

fn limit() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        codes::LIMIT_EXCEEDED,
        "relationship proof exceeds service limits",
        None::<()>,
    )
}

impl HubApiImpl {
    pub(super) async fn relation_proof(
        &self,
        prefix: &[u8],
        height: u64,
    ) -> RpcResult<RelationPrefixProof> {
        if prefix.len() > MAX_PREFIX_BYTES {
            return Err(limit());
        }
        if !is_relation_prefix(prefix) {
            return Err(ErrorObjectOwned::owned(
                codes::INVALID_PARAMS,
                "unsupported relationship prefix",
                None::<()>,
            ));
        }
        let light = self.get_light_block(U64::from(height)).await?;
        let root: B256 = light.module_state_root.parse().map_err(unavailable)?;
        let modules = self
            .modules
            .as_ref()
            .ok_or_else(|| unavailable("module records unavailable"))?;
        let snapshot = modules
            .read()
            .map_err(|_| unavailable("module lock poisoned"))?
            .acp
            .store()
            .clone();
        let mut keys = Vec::new();
        let mut remaining = MAX_BYTES;
        for (key, value) in snapshot.prefix_iter(prefix) {
            if keys.len() == MAX_RECORDS {
                return Err(limit());
            }
            remaining = remaining
                .checked_sub(key.len())
                .and_then(|n| n.checked_sub(value.len()))
                .ok_or_else(limit)?;
            keys.push(key.to_vec());
        }
        let trees = self
            .module_trees
            .as_ref()
            .ok_or_else(|| unavailable("module trees unavailable"))?;
        let mut roots = [[0; 32]; 4];
        for (slot, tree) in roots.iter_mut().zip(trees) {
            *slot = tree
                .lock()
                .map_err(|_| unavailable("tree lock poisoned"))?
                .root_at_height(height)
                .map_err(unavailable)?
                .0;
        }
        let tree = trees[ModuleId::Acp.index()]
            .lock()
            .map_err(|_| unavailable("tree lock poisoned"))?;
        let prove = |key: &[u8]| {
            let (value, proof, acp_root) =
                tree.prove_at_height(key, height).map_err(unavailable)?;
            Ok::<_, ErrorObjectOwned>(ModuleStateProof::new(
                ModuleId::Acp,
                height,
                key,
                value.as_deref(),
                &proof,
                acp_root.0,
                roots,
            ))
        };
        let mut proof = RelationPrefixProof {
            version: prove(RELATION_INDEX_VERSION_KEY)?,
            count: prove(&relation_count_key(prefix))?,
            records: Vec::new(),
        };
        remaining = MAX_BYTES;
        for record in [&proof.version, &proof.count] {
            remaining = remaining
                .checked_sub(serde_json::to_vec(record).map_err(unavailable)?.len())
                .ok_or_else(limit)?;
        }
        for key in keys {
            let record = prove(&key)?;
            remaining = remaining
                .checked_sub(serde_json::to_vec(&record).map_err(unavailable)?.len())
                .ok_or_else(limit)?;
            proof.records.push(record);
        }
        drop(tree);
        // Current keys are only enumeration candidates; the historical count and
        // inclusion proofs must establish completeness at the requested revision.
        verify_relation_prefix_proof(
            root,
            height,
            prefix,
            &proof,
            RelationProofLimits {
                records: MAX_RECORDS,
                bytes: MAX_BYTES,
            },
        )
        .map_err(unavailable)?;
        if serde_json::to_vec(&proof).map_err(unavailable)?.len() > MAX_BYTES {
            return Err(limit());
        }
        Ok(proof)
    }
}
