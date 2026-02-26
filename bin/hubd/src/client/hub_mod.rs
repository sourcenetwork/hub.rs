//! Hub module subcommands (chain config, params, JWS tokens).

use alloy_primitives::Address;
use clap::Subcommand;

use super::context::ClientContext;

#[derive(Subcommand, Debug)]
pub(crate) enum HubCommand {
    /// Fetch chain configuration.
    ChainConfig,
    /// Fetch current Hub module parameters.
    Params,
    /// Look up a JWS token by hash.
    GetToken {
        /// Token hash string.
        token_hash: String,
    },
    /// List JWS tokens issued by a DID.
    ListTokensByDid {
        /// DID string (e.g. did:key:z...).
        did: String,
    },
    /// List JWS tokens authorized for an account.
    ListTokensByAccount {
        /// Ethereum address (hex, 0x-prefixed).
        address: String,
    },
    /// Invalidate a JWS token by its hash.
    InvalidateToken {
        /// Token hash string.
        token_hash: String,
    },
}

impl HubCommand {
    pub(super) async fn run(self, ctx: &ClientContext) -> eyre::Result<()> {
        match self {
            Self::ChainConfig => {
                let data = ctx.client.get_chain_config().await?;
                let json = bytes_to_json(&data);
                ctx.print_json(&json)?;
            }
            Self::Params => {
                let data = ctx.client.get_hub_params().await?;
                let json = bytes_to_json(&data);
                ctx.print_json(&json)?;
            }
            Self::GetToken { token_hash } => {
                let (found, record) = ctx.client.get_jws_token(&token_hash).await?;
                let record_json = bytes_to_json(&record);
                ctx.print_json(&serde_json::json!({ "found": found, "record": record_json }))?;
            }
            Self::ListTokensByDid { did } => {
                let data = ctx.client.get_jws_tokens_by_did(&did).await?;
                let json = bytes_to_json(&data);
                ctx.print_json(&json)?;
            }
            Self::ListTokensByAccount { address } => {
                let addr: Address = address
                    .parse()
                    .map_err(|e| eyre::eyre!("invalid address: {e}"))?;
                let data = ctx.client.get_jws_tokens_by_account(addr).await?;
                let json = bytes_to_json(&data);
                ctx.print_json(&json)?;
            }
            Self::InvalidateToken { token_hash } => {
                let receipt = if let Some(bls) = ctx.bls_signer.as_ref() {
                    ctx.client.native_invalidate_jws(bls, &token_hash).await?
                } else {
                    let signer = ctx.require_evm_signer()?;
                    ctx.client.invalidate_jws(signer, &token_hash).await?
                };
                ctx.print_json(&receipt)?;
            }
        }
        Ok(())
    }
}

fn bytes_to_json(data: &[u8]) -> serde_json::Value {
    serde_json::from_slice(data)
        .unwrap_or_else(|_| serde_json::Value::String(format!("0x{}", hex::encode(data))))
}
