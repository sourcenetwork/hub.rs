//! Hub-specific JSON-RPC API implementation.

use std::sync::Arc;

use alloy_primitives::{B256, Bytes, U64};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use commonware_cryptography::Hasher as _;
use hub_domain::{LightBlock, ModuleId, ModuleStateProof, RelationPrefixProof};

mod permission;
mod receipt;
mod record;
mod relation;
use hub_executor::{ModuleTrees, SharedModuleState};
use hub_indexer::{BlockIndex, LightBlockIndex};
use hub_permission::{AccessRequest, PermissionProof, PermissionResponse, RecordResponse};

use crate::{
    error::RpcError,
    eth::TxSubmitCallback,
    state::{NodeState, NodeStatus},
    types::{RpcLog, RpcNativeReceipt},
};

/// Durable light-block lookup, executed outside the asynchronous RPC worker.
pub type LightBlockLookup = Arc<dyn Fn(u64) -> Result<LightBlock, String> + Send + Sync>;

/// Hub-specific JSON-RPC API trait.
///
/// Provides methods specific to hub node operations.
#[rpc(server, namespace = "hub")]
pub trait HubApi {
    /// Returns the current node status including consensus information.
    #[method(name = "nodeStatus")]
    async fn node_status(&self) -> RpcResult<NodeStatus>;

    /// Submits a BLS-signed native transaction.
    ///
    /// Accepts wire-format bytes (`0x45 || RLP(NativeTx)`), validates the
    /// format prefix, decodes the transaction, and returns the tx_id.
    /// Rejects bytes that do not start with the native tx type byte.
    #[method(name = "sendNativeTx")]
    async fn send_native_tx(&self, data: Bytes) -> RpcResult<B256>;

    /// Returns an extended transaction receipt with BLS signer identity info.
    ///
    /// For native BLS transactions, includes `signer_did` and `native_nonce`.
    /// For EVM transactions, these fields are `None`.
    #[method(name = "getTransactionReceipt")]
    async fn get_transaction_receipt(&self, hash: B256) -> RpcResult<Option<RpcNativeReceipt>>;

    /// Return the complete receipt commitment and finality evidence for a submission.
    /// A missing response does not prove that the submission was never accepted.
    #[method(name = "getReceiptProof")]
    async fn get_receipt_proof(&self, hash: B256)
    -> RpcResult<Option<hub_domain::ReceiptResponse>>;

    /// Returns the on-chain native nonce for a BLS identity.
    #[method(name = "getNativeNonce")]
    async fn get_native_nonce(&self, did: String) -> RpcResult<U64>;

    /// Returns a Merkle inclusion/exclusion proof for a key in a module's state.
    ///
    /// The proof is verifiable against the `module_state_root` in the block header
    /// at the given height. Supports both existence and non-existence proofs.
    #[method(name = "getStateProof")]
    async fn get_state_proof(
        &self,
        module: String,
        key: String,
        height: U64,
    ) -> RpcResult<ModuleStateProof>;

    /// Prove a complete ACP relationship prefix at a retained finalized height.
    /// Returns unavailable if the current record index cannot enumerate that revision.
    #[method(name = "getRelationProof")]
    async fn get_relation_proof(
        &self,
        prefix: Bytes,
        height: U64,
    ) -> RpcResult<RelationPrefixProof>;

    /// Return bounded evidence for evaluating this request at a finalized revision.
    #[method(name = "getPermissionProof")]
    async fn get_permission_proof(
        &self,
        policy: String,
        request: AccessRequest,
        height: U64,
    ) -> RpcResult<PermissionProof>;

    /// Capture current native evidence and return its matching finalized revision.
    #[method(name = "getCurrentPermissionProof")]
    async fn get_current_permission_proof(
        &self,
        policy: String,
        request: AccessRequest,
        minimum_height: U64,
    ) -> RpcResult<PermissionResponse>;

    /// Capture a native record and its finalized revision, including proven absence.
    #[method(name = "getCurrentRecordProof")]
    async fn get_current_record_proof(
        &self,
        module: ModuleId,
        key: Bytes,
        minimum_height: U64,
    ) -> RpcResult<RecordResponse>;

    /// Returns a light block at the given height.
    ///
    /// Verify it with `hub_domain::verify_light_block` and a consensus key from
    /// the deployment's authenticated bootstrap configuration.
    #[method(name = "getLightBlock")]
    async fn get_light_block(&self, height: U64) -> RpcResult<LightBlock>;
}

/// Implementation of the hub RPC API.
pub struct HubApiImpl {
    state: Arc<NodeState>,
    tx_submit: Option<TxSubmitCallback>,
    index: Option<Arc<BlockIndex>>,
    modules: Option<SharedModuleState>,
    module_trees: Option<ModuleTrees>,
    native_modules: Option<hub_backend::native::NativeStateSet>,
    light_block_index: Option<Arc<LightBlockIndex>>,
    light_block_lookup: Option<LightBlockLookup>,
}

impl std::fmt::Debug for HubApiImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubApiImpl")
            .field("state", &self.state)
            .field("tx_submit", &self.tx_submit.is_some())
            .field("index", &self.index.is_some())
            .field("modules", &self.modules.is_some())
            .field("module_trees", &self.module_trees.is_some())
            .field("native_modules", &self.native_modules.is_some())
            .field("light_block_index", &self.light_block_index.is_some())
            .field("light_block_lookup", &self.light_block_lookup.is_some())
            .finish()
    }
}

impl HubApiImpl {
    /// Create a new hub API implementation.
    #[must_use]
    pub fn new(state: Arc<NodeState>, tx_submit: Option<TxSubmitCallback>) -> Self {
        Self {
            state,
            tx_submit,
            index: None,
            modules: None,
            module_trees: None,
            native_modules: None,
            light_block_index: None,
            light_block_lookup: None,
        }
    }

    /// Set the block index and shared module state for receipt/nonce queries.
    #[must_use]
    pub fn with_index_and_modules(
        mut self,
        index: Arc<BlockIndex>,
        modules: SharedModuleState,
    ) -> Self {
        self.index = Some(index);
        self.modules = Some(modules);
        self
    }

    /// Set the JMT-backed module state trees for proof generation.
    #[must_use]
    pub fn with_module_trees(mut self, trees: ModuleTrees) -> Self {
        self.module_trees = Some(trees);
        self
    }

    /// Serve permission evidence from the selected ordered module databases.
    #[must_use]
    pub fn with_native_modules(
        mut self,
        databases: hub_backend::native::NativeStateSet,
        modules: SharedModuleState,
    ) -> Self {
        self.native_modules = Some(databases);
        self.modules = Some(modules);
        self
    }

    /// Set the light block index for `getLightBlock` queries.
    #[must_use]
    pub fn with_light_block_index(mut self, index: Arc<LightBlockIndex>) -> Self {
        self.light_block_index = Some(index);
        self
    }

    /// Serve direct and indirect finality proofs from durable history.
    #[must_use]
    pub fn with_light_block_lookup(mut self, lookup: LightBlockLookup) -> Self {
        self.light_block_lookup = Some(lookup);
        self
    }
}

#[jsonrpsee::core::async_trait]
impl HubApiServer for HubApiImpl {
    async fn node_status(&self) -> RpcResult<NodeStatus> {
        Ok(self.state.status())
    }

    async fn send_native_tx(&self, data: Bytes) -> RpcResult<B256> {
        let first = data
            .first()
            .ok_or_else(|| RpcError::InvalidTransaction("empty transaction".into()))?;

        if !hub_domain::NativeTx::is_native_tx(*first) {
            return Err(RpcError::InvalidTransaction(
                "not a native transaction (expected 0x45 prefix)".into(),
            )
            .into());
        }

        let ntx = hub_domain::NativeTx::decode_wire(&data)
            .map_err(|e| RpcError::InvalidTransaction(format!("native tx decode: {e}")))?;
        let tx_hash = ntx.tx_id().0;

        if let Some(ref submit) = self.tx_submit {
            match submit(data).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(RpcError::InvalidTransaction("duplicate transaction".into()).into());
                }
                Err(msg) => {
                    return Err(RpcError::InvalidTransaction(msg).into());
                }
            }
        }

        Ok(tx_hash)
    }

    async fn get_transaction_receipt(&self, hash: B256) -> RpcResult<Option<RpcNativeReceipt>> {
        let Some(ref index) = self.index else {
            return Err(RpcError::Internal("block index not available".into()).into());
        };

        let Some(receipt) = index.get_receipt(&hash) else {
            return Ok(None);
        };

        let tx = index.get_transaction(&hash);
        let native_nonce = tx.as_ref().and_then(|t| {
            if receipt.signer_did.is_some() {
                Some(U64::from(t.nonce))
            } else {
                None
            }
        });

        let logs = receipt
            .logs
            .into_iter()
            .map(|log| RpcLog {
                address: log.address,
                topics: log.topics,
                data: log.data,
                block_number: U64::from(receipt.block_number),
                transaction_hash: receipt.transaction_hash,
                transaction_index: U64::from(receipt.transaction_index),
                block_hash: receipt.block_hash,
                log_index: U64::from(log.log_index),
                removed: false,
            })
            .collect();

        Ok(Some(RpcNativeReceipt {
            transaction_hash: receipt.transaction_hash,
            transaction_index: U64::from(receipt.transaction_index),
            block_hash: receipt.block_hash,
            block_number: U64::from(receipt.block_number),
            from: receipt.from,
            to: receipt.to,
            cumulative_gas_used: U64::from(receipt.cumulative_gas_used),
            gas_used: U64::from(receipt.gas_used),
            contract_address: receipt.contract_address,
            logs,
            logs_bloom: Bytes::new(),
            tx_type: U64::ZERO,
            status: if receipt.status {
                U64::from(1)
            } else {
                U64::ZERO
            },
            effective_gas_price: alloy_primitives::U256::ZERO,
            signer_did: receipt.signer_did,
            native_nonce,
        }))
    }

    async fn get_receipt_proof(
        &self,
        hash: B256,
    ) -> RpcResult<Option<hub_domain::ReceiptResponse>> {
        self.receipt_proof(hash).await
    }

    async fn get_native_nonce(&self, did: String) -> RpcResult<U64> {
        let Some(ref modules) = self.modules else {
            return Err(RpcError::Internal("module state not available".into()).into());
        };

        let guard = modules
            .read()
            .map_err(|_| RpcError::Internal("lock poisoned".into()))?;
        let nonce = guard.nonces.get_nonce(&did);
        Ok(U64::from(nonce))
    }

    async fn get_state_proof(
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

    async fn get_relation_proof(
        &self,
        prefix: Bytes,
        height: U64,
    ) -> RpcResult<RelationPrefixProof> {
        self.relation_proof(&prefix, height.to()).await
    }

    async fn get_permission_proof(
        &self,
        policy: String,
        request: AccessRequest,
        height: U64,
    ) -> RpcResult<PermissionProof> {
        self.permission_proof(&policy, &request, height.to()).await
    }

    async fn get_current_permission_proof(
        &self,
        policy: String,
        request: AccessRequest,
        minimum_height: U64,
    ) -> RpcResult<PermissionResponse> {
        self.current_permission_proof(&policy, &request, minimum_height.to())
            .await
    }

    async fn get_current_record_proof(
        &self,
        module: ModuleId,
        key: Bytes,
        minimum_height: U64,
    ) -> RpcResult<RecordResponse> {
        self.current_record_proof(module, &key, minimum_height.to())
            .await
    }

    async fn get_light_block(&self, height: U64) -> RpcResult<LightBlock> {
        let height: u64 = height.to();
        if let Some(light_index) = &self.light_block_index {
            let finalization = self
                .index
                .as_ref()
                .and_then(|index| index.get_block_by_number(height))
                .and_then(|block| {
                    let digest = commonware_cryptography::Sha256::hash(&[block.hash.as_slice()]).0;
                    light_index.get_finalization(&digest)
                });
            if let Some(finalization) = finalization {
                let material = light_index
                    .get_epoch_material(finalization.epoch)
                    .ok_or_else(|| {
                        RpcError::Internal(format!(
                            "epoch material not found for epoch {}",
                            finalization.epoch
                        ))
                    })?;
                return LightBlock::from_encoded_block(
                    &finalization.block,
                    &finalization.bytes,
                    &material.bytes,
                )
                .map_err(|error| {
                    RpcError::Internal(format!("light block assembly failed: {error}")).into()
                });
            }
        }
        if let Some(lookup) = &self.light_block_lookup {
            let lookup = lookup.clone();
            return tokio::task::spawn_blocking(move || lookup(height))
                .await
                .map_err(|error| RpcError::Internal(format!("light block lookup failed: {error}")))?
                .map_err(|error| RpcError::Internal(error).into());
        }
        Err(RpcError::Internal(format!(
            "finalization certificate not found for height {height}"
        ))
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, FixedBytes};
    use hub_domain::NativeTx;

    fn sample_native_tx() -> NativeTx {
        NativeTx {
            chain_id: 1,
            nonce: 42,
            bls_pubkey: FixedBytes::from([0xAA; 48]),
            target: Address::from([
                0x08, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            calldata: Bytes::from(vec![0xDE, 0xAD]),
            signature: FixedBytes::from([0xBB; 96]),
        }
    }

    #[tokio::test]
    async fn send_native_tx_returns_correct_tx_id() {
        let ntx = sample_native_tx();
        let wire = Bytes::from(ntx.encode_wire());
        let expected = ntx.tx_id().0;

        let submitted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let submitted_clone = submitted.clone();
        let callback: TxSubmitCallback = Arc::new(move |_| {
            submitted_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            Box::pin(async { Ok(true) })
        });

        let state = Arc::new(NodeState::new(1, 0, 1));
        let api = HubApiImpl::new(state, Some(callback));
        let result = HubApiServer::send_native_tx(&api, wire).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
        assert!(submitted.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[tokio::test]
    async fn send_native_tx_rejects_evm_bytes() {
        let state = Arc::new(NodeState::new(1, 0, 1));
        let api = HubApiImpl::new(state, None);
        let evm_data = Bytes::from(vec![0x02, 0xAA, 0xBB]);
        let result = HubApiServer::send_native_tx(&api, evm_data).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message().contains("not a native transaction"));
    }

    #[tokio::test]
    async fn send_native_tx_rejects_empty() {
        let state = Arc::new(NodeState::new(1, 0, 1));
        let api = HubApiImpl::new(state, None);
        let result = HubApiServer::send_native_tx(&api, Bytes::new()).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message().contains("empty transaction"));
    }
}
