//! Status and chain info subcommands.

use alloy_primitives::Address;
use clap::Subcommand;

use super::context::ClientContext;

#[derive(Subcommand, Debug)]
pub(crate) enum StatusCommand {
    /// Query node status (hub_nodeStatus).
    Status,
    /// Query chain ID (eth_chainId).
    ChainId,
    /// Query latest block number (eth_blockNumber).
    BlockNumber,
    /// Query balance of an address (eth_getBalance).
    Balance {
        /// Ethereum address (hex, 0x-prefixed).
        address: String,
    },
}

impl StatusCommand {
    pub(super) async fn run(self, ctx: &ClientContext) -> eyre::Result<()> {
        match self {
            Self::Status => {
                let status = ctx.client.node_status().await?;
                ctx.print_json(&status)?;
            }
            Self::ChainId => {
                let id = ctx.client.chain_id().await?;
                ctx.print_json(&serde_json::json!({ "chain_id": id }))?;
            }
            Self::BlockNumber => {
                let num = ctx.client.block_number().await?;
                ctx.print_json(&serde_json::json!({ "block_number": num }))?;
            }
            Self::Balance { address } => {
                let addr: Address = address
                    .parse()
                    .map_err(|e| eyre::eyre!("invalid address: {e}"))?;
                let balance = ctx.client.get_balance(addr).await?;
                ctx.print_json(&serde_json::json!({
                    "address": format!("{addr:?}"),
                    "balance": balance.to_string(),
                }))?;
            }
        }
        Ok(())
    }
}
