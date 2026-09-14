//! Transaction subcommands (receipt, send-raw, send-native).

use alloy_primitives::B256;
use clap::Subcommand;

use super::context::ClientContext;

#[derive(Subcommand, Debug)]
pub(crate) enum TxCommand {
    /// Fetch an EVM transaction receipt.
    Receipt {
        /// Transaction hash (hex, 0x-prefixed).
        hash: String,
    },
    /// Fetch a native (BLS) transaction receipt.
    NativeReceipt {
        /// Transaction hash (hex, 0x-prefixed).
        hash: String,
    },
    /// Submit a raw signed EVM transaction.
    SendRaw {
        /// Hex-encoded signed transaction bytes.
        raw_tx: String,
    },
    /// Submit a raw signed native BLS transaction.
    SendNative {
        /// Hex-encoded signed native transaction bytes.
        raw_tx: String,
    },
}

impl TxCommand {
    pub(super) async fn run(self, ctx: &ClientContext) -> eyre::Result<()> {
        match self {
            Self::Receipt { hash } => {
                let tx_hash = parse_b256(&hash)?;
                let receipt = ctx.client.get_transaction_receipt(tx_hash).await?;
                ctx.print_json(&receipt)?;
            }
            Self::NativeReceipt { hash } => {
                let tx_hash = parse_b256(&hash)?;
                let receipt = ctx.client.get_native_receipt(tx_hash).await?;
                ctx.print_json(&receipt)?;
            }
            Self::SendRaw { raw_tx } => {
                let bytes = parse_hex_bytes(&raw_tx)?;
                let tx_hash = ctx.client.send_raw_transaction(&bytes).await?;
                ctx.print_json(&serde_json::json!({ "tx_hash": format!("{tx_hash:?}") }))?;
            }
            Self::SendNative { raw_tx } => {
                let bytes = parse_hex_bytes(&raw_tx)?;
                let tx_hash = ctx.client.send_native_tx(&bytes).await?;
                ctx.print_json(&serde_json::json!({ "tx_hash": format!("{tx_hash:?}") }))?;
            }
        }
        Ok(())
    }
}

fn parse_b256(hex: &str) -> eyre::Result<B256> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex).map_err(|e| eyre::eyre!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(eyre::eyre!("expected 32 bytes, got {}", bytes.len()));
    }
    Ok(B256::from_slice(&bytes))
}

fn parse_hex_bytes(hex: &str) -> eyre::Result<Vec<u8>> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    hex::decode(hex).map_err(|e| eyre::eyre!("invalid hex: {e}"))
}
