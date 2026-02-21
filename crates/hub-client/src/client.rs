//! Core [`HubClient`] struct with JSON-RPC transport.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes, U256};
use serde::de::DeserializeOwned;
use tracing::debug;

use crate::error::ClientError;
use crate::types::{NodeStatus, TransactionReceipt};

/// ACP precompile address (`0x0810`).
pub const ACP_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x10);

/// Bulletin precompile address (`0x0811`).
pub const BULLETIN_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x11);

/// Hub precompile address (`0x0812`).
pub const HUB_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x12);

const fn address_from_last_two_bytes(hi: u8, lo: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[18] = hi;
    bytes[19] = lo;
    Address::new(bytes)
}

/// Client for interacting with a hub node via JSON-RPC.
///
/// Provides Ethereum-compatible RPC methods (`eth_*`), hub-specific
/// methods (`hub_*`), and typed query helpers for each precompile module.
#[derive(Debug)]
pub struct HubClient {
    rpc_url: String,
    http: reqwest::Client,
    id: AtomicU64,
}

impl HubClient {
    /// Create a new client targeting the given JSON-RPC endpoint.
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            http: reqwest::Client::new(),
            id: AtomicU64::new(1),
        }
    }

    fn next_id(&self) -> u64 {
        self.id.fetch_add(1, Ordering::Relaxed)
    }

    // ── Low-level transport ─────────────────────────────────────────

    /// Send a raw JSON-RPC request and return the `result` field.
    async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.next_id(),
        });

        debug!(method, "JSON-RPC request");

        let resp: serde_json::Value = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if let Some(error) = resp.get("error") {
            let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let message = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Err(ClientError::Rpc { code, message });
        }

        resp.get("result")
            .cloned()
            .ok_or(ClientError::MissingResult)
    }

    /// Send a JSON-RPC request and deserialize the `result` into `T`.
    async fn rpc_call_typed<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, ClientError> {
        let value = self.rpc_call(method, params).await?;
        Ok(serde_json::from_value(value)?)
    }

    // ── Ethereum RPC wrappers ───────────────────────────────────────

    /// Return the chain ID (`eth_chainId`).
    pub async fn chain_id(&self) -> Result<u64, ClientError> {
        let hex: String = self
            .rpc_call_typed("eth_chainId", serde_json::json!([]))
            .await?;
        parse_hex_u64(&hex)
    }

    /// Return the latest block number (`eth_blockNumber`).
    pub async fn block_number(&self) -> Result<u64, ClientError> {
        let hex: String = self
            .rpc_call_typed("eth_blockNumber", serde_json::json!([]))
            .await?;
        parse_hex_u64(&hex)
    }

    /// Return the balance of an address (`eth_getBalance`).
    pub async fn get_balance(&self, address: Address) -> Result<U256, ClientError> {
        let hex: String = self
            .rpc_call_typed(
                "eth_getBalance",
                serde_json::json!([format!("{address:?}"), "latest"]),
            )
            .await?;
        parse_hex_u256(&hex)
    }

    /// Return the nonce of an address (`eth_getTransactionCount`).
    pub async fn get_nonce(&self, address: Address) -> Result<u64, ClientError> {
        let hex: String = self
            .rpc_call_typed(
                "eth_getTransactionCount",
                serde_json::json!([format!("{address:?}"), "latest"]),
            )
            .await?;
        parse_hex_u64(&hex)
    }

    /// Execute a read-only call against a contract (`eth_call`).
    pub async fn eth_call(&self, to: Address, data: Bytes) -> Result<Bytes, ClientError> {
        let call_obj = serde_json::json!({
            "to": format!("{to:?}"),
            "data": format!("0x{}", hex::encode(&data)),
        });
        let hex: String = self
            .rpc_call_typed("eth_call", serde_json::json!([call_obj, "latest"]))
            .await?;
        let hex = hex.strip_prefix("0x").unwrap_or(&hex);
        let bytes = hex::decode(hex).map_err(|e| ClientError::AbiDecode(e.to_string()))?;
        Ok(Bytes::from(bytes))
    }

    /// Submit a signed EVM transaction (`eth_sendRawTransaction`).
    pub async fn send_raw_transaction(&self, raw_tx: &[u8]) -> Result<B256, ClientError> {
        let hex: String = self
            .rpc_call_typed(
                "eth_sendRawTransaction",
                serde_json::json!([format!("0x{}", hex::encode(raw_tx))]),
            )
            .await?;
        parse_hex_b256(&hex)
    }

    /// Fetch a transaction receipt (`eth_getTransactionReceipt`).
    ///
    /// Returns `None` if the transaction has not yet been included.
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: B256,
    ) -> Result<Option<TransactionReceipt>, ClientError> {
        let result = self
            .rpc_call(
                "eth_getTransactionReceipt",
                serde_json::json!([format!("{tx_hash:?}")]),
            )
            .await?;

        if result.is_null() {
            return Ok(None);
        }

        Ok(Some(serde_json::from_value(result)?))
    }

    /// Return the current gas price (`eth_gasPrice`).
    pub async fn gas_price(&self) -> Result<U256, ClientError> {
        let hex: String = self
            .rpc_call_typed("eth_gasPrice", serde_json::json!([]))
            .await?;
        parse_hex_u256(&hex)
    }

    // ── Hub RPC wrappers ────────────────────────────────────────────

    /// Submit a BLS-signed native transaction (`hub_sendNativeTx`).
    pub async fn send_native_tx(&self, raw_tx: &[u8]) -> Result<B256, ClientError> {
        let hex: String = self
            .rpc_call_typed(
                "hub_sendNativeTx",
                serde_json::json!([format!("0x{}", hex::encode(raw_tx))]),
            )
            .await?;
        parse_hex_b256(&hex)
    }

    /// Fetch the current node status (`hub_nodeStatus`).
    pub async fn node_status(&self) -> Result<NodeStatus, ClientError> {
        self.rpc_call_typed("hub_nodeStatus", serde_json::json!([]))
            .await
    }

    // ── Receipt polling ─────────────────────────────────────────────

    /// Poll for a transaction receipt until it appears or attempts are exhausted.
    pub async fn wait_for_receipt(
        &self,
        tx_hash: B256,
        interval: Duration,
        max_attempts: u32,
    ) -> Result<TransactionReceipt, ClientError> {
        for _ in 0..max_attempts {
            if let Some(receipt) = self.get_transaction_receipt(tx_hash).await? {
                return Ok(receipt);
            }
            tokio::time::sleep(interval).await;
        }
        Err(ClientError::ReceiptTimeout {
            attempts: max_attempts,
        })
    }
}

fn parse_hex_u64(hex: &str) -> Result<u64, ClientError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    u64::from_str_radix(hex, 16)
        .map_err(|e| ClientError::AbiDecode(format!("invalid hex u64: {e}")))
}

fn parse_hex_u256(hex: &str) -> Result<U256, ClientError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let padded = if !hex.len().is_multiple_of(2) {
        format!("0{hex}")
    } else {
        hex.to_string()
    };
    let bytes =
        hex::decode(&padded).map_err(|e| ClientError::AbiDecode(format!("invalid hex: {e}")))?;
    Ok(U256::from_be_slice(&bytes))
}

fn parse_hex_b256(hex: &str) -> Result<B256, ClientError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes =
        hex::decode(hex).map_err(|e| ClientError::AbiDecode(format!("invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(ClientError::AbiDecode(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(B256::from_slice(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precompile_addresses() {
        assert_eq!(
            format!("{ACP_ADDRESS:?}"),
            "0x0000000000000000000000000000000000000810"
        );
        assert_eq!(
            format!("{BULLETIN_ADDRESS:?}"),
            "0x0000000000000000000000000000000000000811"
        );
        assert_eq!(
            format!("{HUB_ADDRESS:?}"),
            "0x0000000000000000000000000000000000000812"
        );
    }

    #[test]
    fn parse_hex_u64_ok() {
        assert_eq!(parse_hex_u64("0xa").unwrap(), 10);
        assert_eq!(parse_hex_u64("0x0").unwrap(), 0);
        assert_eq!(parse_hex_u64("ff").unwrap(), 255);
    }

    #[test]
    fn parse_hex_u256_ok() {
        let val = parse_hex_u256("0x3b9aca00").unwrap();
        assert_eq!(val, U256::from(1_000_000_000u64));
    }

    #[test]
    fn parse_hex_b256_ok() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let b = parse_hex_b256(hex).unwrap();
        assert_eq!(b, B256::from(U256::from(1)));
    }

    #[test]
    fn parse_hex_b256_wrong_length() {
        let err = parse_hex_b256("0xaabb").unwrap_err();
        assert!(err.to_string().contains("expected 32 bytes"));
    }

    #[test]
    fn client_new() {
        let client = HubClient::new("http://localhost:8545");
        assert_eq!(client.rpc_url, "http://localhost:8545");
    }
}
