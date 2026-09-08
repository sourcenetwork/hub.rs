use super::*;

#[test]
fn decaf_signatures_match_orbis_interoperability_vectors() {
    // Shared with decaf377-go v0.2.0 testdata/orbis_vectors.json.
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("orbis_vectors.json")).unwrap();
    for vector in vectors["vectors"].as_array().unwrap() {
        let decode = |name: &str| hex::decode(vector[name].as_str().unwrap()).unwrap();
        assert_eq!(
            verify(
                ThresholdScheme::Decaf377Frost,
                &decode("public_key_hex"),
                &decode("message_hex"),
                &decode("signature_hex")
            )
            .is_ok(),
            vector["expect_valid"].as_bool().unwrap(),
            "{}",
            vector["name"]
        );
    }
    let vector = &vectors["vectors"][0];
    let key = hex::decode(vector["public_key_hex"].as_str().unwrap()).unwrap();
    let message = hex::decode(vector["message_hex"].as_str().unwrap()).unwrap();
    let signature = hex::decode(vector["signature_hex"].as_str().unwrap()).unwrap();
    assert!(
        verify(
            ThresholdScheme::Decaf377Frost,
            &[0; 32],
            &message,
            &signature
        )
        .is_err()
    );
    assert!(
        verify(
            ThresholdScheme::Decaf377Frost,
            &[255; 32],
            &message,
            &signature
        )
        .is_err()
    );
    let mut noncanonical = signature.clone();
    noncanonical[32..].fill(255);
    assert!(
        verify(
            ThresholdScheme::Decaf377Frost,
            &key,
            &message,
            &noncanonical
        )
        .is_err()
    );
    let mut trailing = signature;
    trailing.push(0);
    assert!(verify(ThresholdScheme::Decaf377Frost, &key, &message, &trailing).is_err());
}

#[test]
fn bls_signatures_bind_key_message_and_orbis_suite() {
    let key = blst::min_pk::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let public = key.sk_to_pk().to_bytes();
    let message = b"ring reshare";
    let signature = key
        .sign(message, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_", &[])
        .to_bytes();
    verify(ThresholdScheme::Bls12381, &public, message, &signature).unwrap();
    assert!(
        verify(
            ThresholdScheme::Bls12381,
            &public,
            b"other reshare",
            &signature
        )
        .is_err()
    );
    let wrong_suite = key.sign(message, b"other suite", &[]).to_bytes();
    assert!(verify(ThresholdScheme::Bls12381, &public, message, &wrong_suite).is_err());
    let other = blst::min_pk::SecretKey::key_gen(&[43; 32], &[])
        .unwrap()
        .sk_to_pk()
        .to_bytes();
    assert!(verify(ThresholdScheme::Bls12381, &other, message, &signature).is_err());
    let mut identity = [0; 48];
    identity[0] = 0xc0;
    assert!(verify(ThresholdScheme::Bls12381, &identity, message, &signature).is_err());
    assert!(
        verify(
            ThresholdScheme::Bls12381,
            &public,
            message,
            &signature[..95]
        )
        .is_err()
    );
    assert!(verify(ThresholdScheme::Decaf377Frost, &public, message, &signature).is_err());
}
