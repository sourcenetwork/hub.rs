use commonware_consensus::simplex::scheme::ed25519::Scheme;
use commonware_cryptography::{Signer as _, ed25519};
use commonware_utils::{TryCollect as _, ordered::Set};
use hub_domain::PublicKey;

/// Ed25519 multisig signing scheme for testing.
pub type Ed25519Scheme = Scheme;

const SIMPLEX_NAMESPACE: &[u8] = b"_COMMONWARE_REVM_SIMPLEX";

/// Generate deterministic ed25519 signing schemes for testing.
pub fn ed25519_schemes(
    seed: u64,
    n: usize,
) -> anyhow::Result<(Vec<PublicKey>, Vec<Ed25519Scheme>)> {
    let private_keys: Vec<ed25519::PrivateKey> = (0..n)
        .map(|i| ed25519::PrivateKey::from_seed(seed.wrapping_add(i as u64)))
        .collect();

    let participants: Set<PublicKey> = private_keys
        .iter()
        .map(|k| k.public_key())
        .try_collect()
        .expect("participant public keys are unique");

    let ordered_pks: Vec<PublicKey> = participants.iter().cloned().collect();

    let mut schemes = Vec::with_capacity(n);
    for pk in participants.iter() {
        let private_key = private_keys
            .iter()
            .find(|k| k.public_key() == *pk)
            .expect("private key exists for participant")
            .clone();
        let scheme = Scheme::signer(SIMPLEX_NAMESPACE, participants.clone(), private_key)
            .ok_or_else(|| anyhow::anyhow!("failed to create signer"))?;
        schemes.push(scheme);
    }

    Ok((ordered_pks, schemes))
}
