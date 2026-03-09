//! JWT ES256K verification for bearer token authentication.
//!
//! Verifies JWTs signed with the ES256K algorithm (secp256k1 + SHA-256).
//! The issuer (`iss`) claim must be a secp256k1 `did:key:` identifier;
//! the public key is extracted from the DID and used to verify the signature.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// secp256k1 multicodec prefix (`0xe7`).
const SECP256K1_PUB_MULTICODEC: u64 = 0xe7;

/// Verified claims extracted from a JWT bearer token.
#[derive(Debug, Clone)]
pub struct JwtClaims {
    /// Issuer — a `did:key:z...` (secp256k1) identifier.
    pub iss: String,
    /// Subject — policy context.
    pub sub: String,
    /// Expiry (unix timestamp). Present for completeness; not enforced.
    pub exp: u64,
}

/// Errors from JWT verification.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// Token does not have exactly three `.`-separated segments.
    #[error("malformed token: {0}")]
    MalformedToken(String),
    /// Header specifies an algorithm other than ES256K.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// ECDSA signature verification failed.
    #[error("invalid signature")]
    InvalidSignature,
    /// The `iss` claim is not a valid secp256k1 `did:key:`.
    #[error("invalid issuer: {0}")]
    InvalidIssuer(String),
    /// Payload decoding or deserialization failed.
    #[error("payload decode: {0}")]
    PayloadDecode(String),
}

/// Verify a JWT bearer token signed with ES256K (secp256k1 + SHA-256).
///
/// Returns the verified claims on success. The `iss` field must be a
/// secp256k1 `did:key:` — the public key is extracted from the DID and
/// used to verify the ECDSA signature.
pub fn verify_bearer_token(token: &str) -> Result<JwtClaims, JwtError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::MalformedToken(format!(
            "expected 3 segments, got {}",
            parts.len()
        )));
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| JwtError::MalformedToken(format!("header base64: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| JwtError::MalformedToken(format!("header JSON: {e}")))?;

    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if alg != "ES256K" {
        return Err(JwtError::UnsupportedAlgorithm(alg.to_string()));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| JwtError::PayloadDecode(format!("payload base64: {e}")))?;

    #[derive(serde::Deserialize)]
    struct RawClaims {
        iss: String,
        #[serde(default)]
        sub: String,
        #[serde(default)]
        exp: u64,
    }

    let raw: RawClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| JwtError::PayloadDecode(format!("payload JSON: {e}")))?;

    let compressed_pubkey = compressed_pubkey_from_did(&raw.iss)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&compressed_pubkey)
        .map_err(|e| JwtError::InvalidIssuer(format!("invalid secp256k1 key: {e}")))?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| JwtError::MalformedToken(format!("signature base64: {e}")))?;
    let signature =
        Signature::from_bytes((&sig_bytes[..]).into()).map_err(|_| JwtError::InvalidSignature)?;

    let signing_input = format!("{header_b64}.{payload_b64}");
    let digest = Sha256::digest(signing_input.as_bytes());

    verifying_key
        .verify_prehash(&digest, &signature)
        .map_err(|_| JwtError::InvalidSignature)?;

    Ok(JwtClaims {
        iss: raw.iss,
        sub: raw.sub,
        exp: raw.exp,
    })
}

/// Extract a compressed secp256k1 public key (33 bytes) from a `did:key:` string.
fn compressed_pubkey_from_did(did: &str) -> Result<Vec<u8>, JwtError> {
    let multibase_part = did
        .strip_prefix("did:key:")
        .ok_or_else(|| JwtError::InvalidIssuer("not a did:key: string".into()))?;

    let (_base, decoded) = multibase::decode(multibase_part)
        .map_err(|e| JwtError::InvalidIssuer(format!("multibase decode: {e}")))?;

    let mut varint_buf = [0u8; 10];
    let prefix = unsigned_varint::encode::u64(SECP256K1_PUB_MULTICODEC, &mut varint_buf);
    if !decoded.starts_with(prefix) {
        return Err(JwtError::InvalidIssuer("not a secp256k1 did:key".into()));
    }

    let key_bytes = &decoded[prefix.len()..];
    let compressed = match key_bytes.len() {
        33 => key_bytes.to_vec(),
        65 => {
            // Uncompressed secp256k1 key — compress it.
            // DefraDB uses uncompressed keys in did:key (matching Go's SerializeUncompressed).
            let vk = VerifyingKey::from_sec1_bytes(key_bytes)
                .map_err(|e| JwtError::InvalidIssuer(format!("invalid uncompressed key: {e}")))?;
            vk.to_encoded_point(true).as_bytes().to_vec()
        }
        n => {
            return Err(JwtError::InvalidIssuer(format!(
                "expected 33 or 65 byte pubkey, got {n}",
            )));
        }
    };

    Ok(compressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn create_jwt(signing_key: &SigningKey, claims_json: &str) -> String {
        let header = r#"{"alg":"ES256K","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

        let signing_input = format!("{header_b64}.{payload_b64}");
        let digest = Sha256::digest(signing_input.as_bytes());

        let (sig, _): (Signature, _) = signing_key
            .sign_prehash_recoverable(digest.as_ref())
            .expect("signing should succeed");
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        format!("{header_b64}.{payload_b64}.{sig_b64}")
    }

    fn test_key_and_did() -> (SigningKey, String) {
        let secret = [42u8; 32];
        let signing_key = SigningKey::from_bytes((&secret).into()).unwrap();
        let compressed = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let did = crate::secp256k1::did_from_secp256k1_pubkey(&compressed).unwrap();
        (signing_key, did)
    }

    #[test]
    fn verify_valid_token() {
        let (sk, did) = test_key_and_did();
        let claims = format!(r#"{{"iss":"{did}","sub":"policy-ctx","exp":9999999999}}"#);
        let token = create_jwt(&sk, &claims);

        let result = verify_bearer_token(&token).unwrap();
        assert_eq!(result.iss, did);
        assert_eq!(result.sub, "policy-ctx");
        assert_eq!(result.exp, 9_999_999_999);
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (sk, did) = test_key_and_did();
        let claims = format!(r#"{{"iss":"{did}","sub":"original","exp":0}}"#);
        let token = create_jwt(&sk, &claims);

        let parts: Vec<&str> = token.split('.').collect();
        let tampered_claims = format!(r#"{{"iss":"{did}","sub":"tampered","exp":0}}"#);
        let tampered_payload = URL_SAFE_NO_PAD.encode(tampered_claims.as_bytes());
        let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        assert!(matches!(
            verify_bearer_token(&tampered_token),
            Err(JwtError::InvalidSignature)
        ));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (_sk_a, did_a) = test_key_and_did();
        let sk_b = SigningKey::from_bytes((&[99u8; 32]).into()).unwrap();

        let claims = format!(r#"{{"iss":"{did_a}","sub":"test","exp":0}}"#);
        let token = create_jwt(&sk_b, &claims);

        assert!(matches!(
            verify_bearer_token(&token),
            Err(JwtError::InvalidSignature)
        ));
    }

    #[test]
    fn verify_rejects_non_es256k() {
        let (sk, did) = test_key_and_did();
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        let claims = format!(r#"{{"iss":"{did}","sub":"test","exp":0}}"#);

        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let digest = Sha256::digest(signing_input.as_bytes());
        let (sig, _): (Signature, _) = sk.sign_prehash_recoverable(digest.as_ref()).unwrap();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{header_b64}.{payload_b64}.{sig_b64}");

        assert!(matches!(
            verify_bearer_token(&token),
            Err(JwtError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn verify_rejects_malformed() {
        assert!(matches!(
            verify_bearer_token(""),
            Err(JwtError::MalformedToken(_))
        ));
        assert!(matches!(
            verify_bearer_token("a.b"),
            Err(JwtError::MalformedToken(_))
        ));
        assert!(matches!(
            verify_bearer_token("a.b.c.d"),
            Err(JwtError::MalformedToken(_))
        ));
    }
}
