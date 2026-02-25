//! JWT ES256K bearer token creation for client-side signing.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

use crate::error::ClientError;

/// Create a JWT bearer token signed with ES256K.
///
/// The issuer (`iss`) is derived from the signing key's secp256k1 `did:key:`.
/// The `subject` and `expiry_secs` are embedded as `sub` and `exp` claims.
pub fn create_bearer_token(
    signing_key: &SigningKey,
    subject: &str,
    expiry_secs: u64,
) -> Result<String, ClientError> {
    let compressed = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let iss = hub_crypto::secp256k1::did_from_secp256k1_pubkey(&compressed)
        .map_err(|e| ClientError::Signing(format!("DID derivation: {e}")))?;

    let header = r#"{"alg":"ES256K","typ":"JWT"}"#;
    let payload = format!(r#"{{"iss":"{iss}","sub":"{subject}","exp":{expiry_secs}}}"#);

    let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());

    let signing_input = format!("{header_b64}.{payload_b64}");
    let digest = Sha256::digest(signing_input.as_bytes());

    let (sig, _) = signing_key
        .sign_prehash_recoverable(digest.as_ref())
        .map_err(|e| ClientError::Signing(format!("ES256K sign: {e}")))?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes((&[42u8; 32]).into()).unwrap()
    }

    #[test]
    fn create_and_verify_roundtrip() {
        let key = test_key();
        let token = create_bearer_token(&key, "test-subject", 9_999_999_999).unwrap();

        let claims = hub_crypto::jwt::verify_bearer_token(&token).unwrap();
        assert_eq!(claims.sub, "test-subject");
        assert_eq!(claims.exp, 9_999_999_999);
        assert!(claims.iss.starts_with("did:key:"));
    }

    #[test]
    fn token_has_three_segments() {
        let key = test_key();
        let token = create_bearer_token(&key, "s", 0).unwrap();
        assert_eq!(token.split('.').count(), 3);
    }
}
