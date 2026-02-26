//! Hub-specific JSON-RPC API implementation.

use std::sync::Arc;

use alloy_primitives::{B256, Bytes, U64};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use commonware_cryptography::{Hasher as _, Sha256};
use hub_domain::{LightBlock, ModuleId, ModuleStateProof};
use hub_executor::{ModuleTrees, SharedModuleState};
use hub_indexer::{BlockIndex, LightBlockIndex};

use crate::{
    error::RpcError,
    eth::TxSubmitCallback,
    state::{NodeState, NodeStatus},
    types::{RpcLog, RpcNativeReceipt},
};

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

    /// Returns a self-contained light block at the given height.
    ///
    /// Includes the block header, finalization certificate, and validator set —
    /// everything needed to verify the block's authenticity via
    /// `hub_domain::verify_light_block`.
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
    light_block_index: Option<Arc<LightBlockIndex>>,
}

impl std::fmt::Debug for HubApiImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubApiImpl")
            .field("state", &self.state)
            .field("tx_submit", &self.tx_submit.is_some())
            .field("index", &self.index.is_some())
            .field("modules", &self.modules.is_some())
            .field("module_trees", &self.module_trees.is_some())
            .field("light_block_index", &self.light_block_index.is_some())
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
            light_block_index: None,
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

    /// Set the light block index for `getLightBlock` queries.
    #[must_use]
    pub fn with_light_block_index(mut self, index: Arc<LightBlockIndex>) -> Self {
        self.light_block_index = Some(index);
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

    async fn get_light_block(&self, height: U64) -> RpcResult<LightBlock> {
        let Some(ref block_index) = self.index else {
            return Err(RpcError::Internal("block index not available".into()).into());
        };
        let Some(ref light_index) = self.light_block_index else {
            return Err(RpcError::Internal("light block index not available".into()).into());
        };

        let height_val: u64 = height.to();
        let block = block_index
            .get_block_by_number(height_val)
            .ok_or_else(|| RpcError::Internal(format!("block not found at height {height_val}")))?;

        let mut hasher = Sha256::default();
        hasher.update(block.hash.as_slice());
        let consensus_digest = hasher.finalize().0;

        let cert = light_index
            .get_certificate(&consensus_digest)
            .ok_or_else(|| {
                RpcError::Internal(format!(
                    "finalization certificate not found for height {height_val}"
                ))
            })?;

        let validators = light_index.get_validators(cert.epoch).ok_or_else(|| {
            RpcError::Internal(format!("validator set not found for epoch {}", cert.epoch))
        })?;

        Ok(LightBlock::from_parts(
            block.hash,
            block.parent_hash,
            block.number,
            block.timestamp,
            block.state_root,
            block.module_state_root,
            cert.epoch,
            cert.view,
            cert.parent_view,
            cert.payload,
            cert.signer_indices,
            cert.signatures,
            validators.pubkeys,
        ))
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
