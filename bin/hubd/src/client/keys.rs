//! Key generation and display subcommands.

use clap::Subcommand;
use hub_client::{BlsSigner, EvmSigner, create_bearer_token};
use k256::ecdsa::SigningKey;

use super::context::ClientContext;

#[derive(Subcommand, Debug)]
pub(crate) enum KeysCommand {
    /// Generate a random secp256k1 keypair.
    GenerateEvm,
    /// Generate a random BLS12-381 keypair.
    GenerateBls,
    /// Show address and DID for a secp256k1 private key.
    ShowEvm {
        /// Hex-encoded private key.
        key: String,
    },
    /// Show DID and public key for a BLS12-381 private key.
    ShowBls {
        /// Hex-encoded private key (32 bytes).
        key: String,
    },
    /// Create a JWT ES256K bearer token from --key.
    BearerToken {
        /// Subject claim for the JWT.
        subject: String,
        /// Expiry as a Unix timestamp (seconds).
        #[arg(long, default_value = "9999999999")]
        expiry: u64,
    },
}

impl KeysCommand {
    pub(super) async fn run(self, ctx: &ClientContext) -> eyre::Result<()> {
        match self {
            Self::GenerateEvm => {
                let key = SigningKey::random(&mut rand::thread_rng());
                let signer = EvmSigner::new(key.clone(), 0);
                let hex_key = hex::encode(key.to_bytes());
                ctx.print_json(&serde_json::json!({
                    "private_key": hex_key,
                    "address": format!("{:?}", signer.address()),
                    "did": signer.did(),
                }))?;
            }
            Self::GenerateBls => {
                let signer = BlsSigner::random(0)
                    .map_err(|e| eyre::eyre!("BLS key generation failed: {e}"))?;
                ctx.print_json(&serde_json::json!({
                    "did": signer.did(),
                    "pubkey": format!("0x{}", hex::encode(signer.pubkey_bytes())),
                }))?;
            }
            Self::ShowEvm { key } => {
                let key_hex = key.strip_prefix("0x").unwrap_or(&key);
                let signer =
                    EvmSigner::from_hex(key_hex, 0).map_err(|e| eyre::eyre!("invalid key: {e}"))?;
                ctx.print_json(&serde_json::json!({
                    "address": format!("{:?}", signer.address()),
                    "did": signer.did(),
                }))?;
            }
            Self::ShowBls { key } => {
                let hex_key = key.strip_prefix("0x").unwrap_or(&key);
                let bytes = hex::decode(hex_key).map_err(|e| eyre::eyre!("invalid hex: {e}"))?;
                if bytes.len() != 32 {
                    return Err(eyre::eyre!(
                        "BLS secret key must be 32 bytes, got {}",
                        bytes.len()
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                let fr = <ark_bls12_381::Fr as ark_ff::PrimeField>::from_le_bytes_mod_order(&arr);
                let signer =
                    BlsSigner::new(fr, 0).map_err(|e| eyre::eyre!("BLS signer init: {e}"))?;
                ctx.print_json(&serde_json::json!({
                    "did": signer.did(),
                    "pubkey": format!("0x{}", hex::encode(signer.pubkey_bytes())),
                }))?;
            }
            Self::BearerToken { subject, expiry } => {
                let key_hex = ctx
                    .evm_key_hex
                    .as_ref()
                    .ok_or_else(|| eyre::eyre!("--key is required for bearer-token"))?;
                let signing_key = parse_signing_key(key_hex)?;
                let token = create_bearer_token(&signing_key, &subject, expiry)
                    .map_err(|e| eyre::eyre!("bearer token creation failed: {e}"))?;
                ctx.print_json(&serde_json::json!({ "token": token }))?;
            }
        }
        Ok(())
    }
}

fn parse_signing_key(hex_key: &str) -> eyre::Result<SigningKey> {
    let bytes = hex::decode(hex_key).map_err(|e| eyre::eyre!("invalid key hex: {e}"))?;
    SigningKey::from_bytes(bytes.as_slice().into())
        .map_err(|e| eyre::eyre!("invalid secp256k1 key: {e}"))
}
