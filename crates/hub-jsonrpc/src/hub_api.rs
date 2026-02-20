//! Hub-specific JSON-RPC API implementation.

use std::sync::Arc;

use alloy_primitives::{B256, Bytes};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use crate::{
    error::RpcError,
    eth::TxSubmitCallback,
    state::{NodeState, NodeStatus},
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
}

/// Implementation of the hub RPC API.
pub struct HubApiImpl {
    state: Arc<NodeState>,
    tx_submit: Option<TxSubmitCallback>,
}

impl std::fmt::Debug for HubApiImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubApiImpl")
            .field("state", &self.state)
            .field("tx_submit", &self.tx_submit.is_some())
            .finish()
    }
}

impl HubApiImpl {
    /// Create a new hub API implementation.
    #[must_use]
    pub fn new(state: Arc<NodeState>, tx_submit: Option<TxSubmitCallback>) -> Self {
        Self { state, tx_submit }
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
            return Err(
                RpcError::InvalidTransaction("not a native transaction (expected 0x45 prefix)".into()).into(),
            );
        }

        let ntx = hub_domain::NativeTx::decode_wire(&data)
            .map_err(|e| RpcError::InvalidTransaction(format!("native tx decode: {e}")))?;
        let tx_hash = ntx.tx_id().0;

        if let Some(ref submit) = self.tx_submit
            && !submit(data)
        {
            return Err(RpcError::InvalidTransaction("transaction rejected".into()).into());
        }

        Ok(tx_hash)
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
            true
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
