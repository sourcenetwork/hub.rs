//! Client context wrapping `HubClient` with optional signers.

use hub_client::{BlsSigner, EvmSigner, HubClient};

/// Shared context for all client subcommands.
#[derive(Debug)]
pub(crate) struct ClientContext {
    pub client: HubClient,
    pub evm_signer: Option<EvmSigner>,
    pub bls_signer: Option<BlsSigner>,
    /// Raw hex key for operations that need the signing key directly (e.g. bearer tokens).
    pub evm_key_hex: Option<String>,
    pub compact: bool,
}

impl ClientContext {
    /// Build a context from CLI global flags.
    pub(super) fn new(
        url: &str,
        key: Option<&str>,
        bls_key: Option<&str>,
        chain_id: u64,
        compact: bool,
    ) -> eyre::Result<Self> {
        let client = HubClient::new(url);

        let evm_signer = key
            .map(|k| EvmSigner::from_hex(k, chain_id))
            .transpose()
            .map_err(|e| eyre::eyre!("invalid --key: {e}"))?;

        let bls_signer = bls_key.map(|k| parse_bls_signer(k, chain_id)).transpose()?;

        let evm_key_hex = key.map(|k| k.strip_prefix("0x").unwrap_or(k).to_string());

        Ok(Self {
            client,
            evm_signer,
            bls_signer,
            evm_key_hex,
            compact,
        })
    }

    /// Require an EVM signer, returning an error if `--key` was not provided.
    pub(super) fn require_evm_signer(&self) -> eyre::Result<&EvmSigner> {
        self.evm_signer
            .as_ref()
            .ok_or_else(|| eyre::eyre!("--key is required for write commands"))
    }

    /// Print a serializable value as JSON to stdout.
    pub(super) fn print_json(&self, value: &impl serde::Serialize) -> eyre::Result<()> {
        let output = if self.compact {
            serde_json::to_string(value)?
        } else {
            serde_json::to_string_pretty(value)?
        };
        println!("{output}");
        Ok(())
    }
}

fn parse_bls_signer(hex_key: &str, chain_id: u64) -> eyre::Result<BlsSigner> {
    let hex_key = hex_key.strip_prefix("0x").unwrap_or(hex_key);
    let bytes = hex::decode(hex_key).map_err(|e| eyre::eyre!("invalid --bls-key hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(eyre::eyre!(
            "BLS secret key must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let fr = <ark_bls12_381::Fr as ark_ff::PrimeField>::from_le_bytes_mod_order(&arr);
    BlsSigner::new(fr, chain_id).map_err(|e| eyre::eyre!("BLS signer init: {e}"))
}
