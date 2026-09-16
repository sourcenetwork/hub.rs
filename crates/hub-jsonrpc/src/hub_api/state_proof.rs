use super::*;

impl HubApiImpl {
    pub(super) async fn state_proof(
        &self,
        module: String,
        key: String,
        height: U64,
    ) -> RpcResult<ModuleStateProof> {
        let Some(ref trees) = self.module_trees else {
            return Err(RpcError::Internal("module state trees not available".into()).into());
        };

        let module_id = ModuleId::from_str_name(&module).ok_or_else(|| {
            RpcError::InvalidTransaction(format!(
                "unknown module: {module} (expected acp, bulletin, hub, or native_nonce)"
            ))
        })?;

        let key_bytes = hex::decode(key.strip_prefix("0x").unwrap_or(&key))
            .map_err(|e| RpcError::InvalidTransaction(format!("invalid key hex: {e}")))?;

        let height_val: u64 = height.to();

        let mut all_roots = [[0u8; 32]; 4];
        for (i, tree_mutex) in trees.iter().enumerate() {
            let tree = tree_mutex
                .lock()
                .map_err(|_| RpcError::Internal("tree lock poisoned".into()))?;
            let root = tree
                .root_at_height(height_val)
                .map_err(|e| RpcError::Internal(format!("root at height: {e}")))?;
            all_roots[i] = root.0;
        }

        let target_tree = trees[module_id.index()]
            .lock()
            .map_err(|_| RpcError::Internal("tree lock poisoned".into()))?;

        let (value, jmt_proof, root_hash) = target_tree
            .prove_at_height(&key_bytes, height_val)
            .map_err(|e| RpcError::Internal(format!("proof generation: {e}")))?;

        all_roots[module_id.index()] = root_hash.0;

        let proof = ModuleStateProof::new(
            module_id,
            height_val,
            &key_bytes,
            value.as_deref(),
            &jmt_proof,
            root_hash.0,
            all_roots,
        );

        Ok(proof)
    }
}
