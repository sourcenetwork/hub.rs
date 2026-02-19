//! Key management for e2e test clusters.
//!
//! Encapsulates ed25519 identity key generation and deterministic threshold
//! scheme generation into a single `KeySet` builder that produces everything
//! needed to start a multi-node validator cluster.

use std::{collections::BTreeMap, path::Path};

use commonware_codec::Encode;
use commonware_cryptography::{Signer as _, ed25519};
use hub_runner::ThresholdScheme;

/// Complete key material for a test cluster.
#[derive(Debug)]
pub struct KeySet {
    identity_keys: Vec<ed25519::PrivateKey>,
    participants: Vec<ed25519::PublicKey>,
    threshold: u32,
    schemes: Vec<ThresholdScheme>,
    seed: u64,
}

impl KeySet {
    /// Create a new builder.
    pub fn builder() -> KeySetBuilder {
        KeySetBuilder::default()
    }

    /// Number of nodes in this key set.
    pub const fn node_count(&self) -> usize {
        self.identity_keys.len()
    }

    /// BFT threshold for this key set.
    pub const fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Seed used to generate this key set.
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Identity key for a specific node.
    pub fn identity_key(&self, index: usize) -> &ed25519::PrivateKey {
        &self.identity_keys[index]
    }

    /// All participant public keys.
    pub fn participants(&self) -> &[ed25519::PublicKey] {
        &self.participants
    }

    /// Get the threshold scheme for a node.
    pub fn scheme(&self, index: usize) -> &ThresholdScheme {
        &self.schemes[index]
    }

    /// Serialized BLS12-381 group public key (G2, 96 bytes compressed).
    pub fn group_public_key(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        commonware_codec::Write::write(self.schemes[0].identity(), &mut buf);
        buf
    }

    /// Write all key material to node directories.
    ///
    /// For each node, writes `validator.key` (raw 32-byte ed25519 private key).
    pub fn write_to(&self, node_dirs: &[impl AsRef<Path>]) -> eyre::Result<()> {
        assert_eq!(
            node_dirs.len(),
            self.node_count(),
            "expected {} dirs, got {}",
            self.node_count(),
            node_dirs.len()
        );

        for (i, dir) in node_dirs.iter().enumerate() {
            let dir = dir.as_ref();
            std::fs::create_dir_all(dir)?;

            let key_bytes = Encode::encode(&self.identity_keys[i]);
            std::fs::write(dir.join("validator.key"), key_bytes.as_ref())?;
        }

        Ok(())
    }

    /// Write a peers.json file for use by validator processes.
    pub fn write_peers(&self, path: &Path, p2p_ports: &[u16]) -> eyre::Result<()> {
        let participants_hex: Vec<String> = self
            .participants
            .iter()
            .map(|pk| hex::encode(Encode::encode(pk)))
            .collect();

        let bootstrappers: BTreeMap<String, String> = self
            .participants
            .iter()
            .enumerate()
            .map(|(i, pk)| {
                let pk_hex = hex::encode(Encode::encode(pk));
                let addr = format!("127.0.0.1:{}", p2p_ports[i]);
                (pk_hex, addr)
            })
            .collect();

        let peers_json = serde_json::json!({
            "validators": self.node_count(),
            "threshold": self.threshold,
            "participants": participants_hex,
            "bootstrappers": bootstrappers,
        });

        std::fs::write(path, serde_json::to_string_pretty(&peers_json)?)?;
        Ok(())
    }

    /// Whether this is a single-node key set.
    pub const fn is_single_node(&self) -> bool {
        self.schemes.len() == 1
    }
}

/// Builder for `KeySet`.
#[derive(Debug)]
pub struct KeySetBuilder {
    nodes: usize,
    threshold: Option<u32>,
    seed: Option<u64>,
}

impl Default for KeySetBuilder {
    fn default() -> Self {
        Self {
            nodes: 4,
            threshold: None,
            seed: None,
        }
    }
}

impl KeySetBuilder {
    /// Set the number of nodes (1 or >=4).
    #[must_use]
    pub const fn nodes(mut self, n: usize) -> Self {
        self.nodes = n;
        self
    }

    /// Set the BFT threshold. Default: `n - (n-1)/3`.
    #[must_use]
    pub const fn threshold(mut self, t: u32) -> Self {
        self.threshold = Some(t);
        self
    }

    /// Use a deterministic seed for reproducible key generation.
    #[must_use]
    pub const fn seed(mut self, s: u64) -> Self {
        self.seed = Some(s);
        self
    }

    /// Build the key set.
    pub fn build(self) -> eyre::Result<KeySet> {
        let n = self.nodes;
        if n == 0 {
            return Err(eyre::eyre!("need at least 1 node"));
        }
        if n > 1 && n < 4 {
            return Err(eyre::eyre!(
                "multi-node clusters need at least 4 nodes for BFT quorum (got {})",
                n
            ));
        }

        let seed = self.seed.unwrap_or_else(rand::random);
        let f = if n > 1 { (n - 1) / 3 } else { 0 };
        let threshold = self
            .threshold
            .unwrap_or(if n == 1 { 1 } else { (n - f) as u32 });

        let (participants, schemes) = hub_runner::generate_threshold_schemes(seed, n)
            .map_err(|e| eyre::eyre!("failed to generate threshold schemes: {}", e))?;

        // Generate identity keys and reorder to match Set-sorted participant order
        // from generate_threshold_schemes.
        let seed_keys: Vec<_> = (0..n)
            .map(|i| {
                let key = ed25519::PrivateKey::from_seed(seed.wrapping_add(i as u64));
                (key.public_key(), key)
            })
            .collect();

        let identity_keys: Vec<ed25519::PrivateKey> = participants
            .iter()
            .map(|pk| {
                seed_keys
                    .iter()
                    .find(|(p, _)| p == pk)
                    .expect("all participants derived from seed")
                    .1
                    .clone()
            })
            .collect();

        Ok(KeySet {
            identity_keys,
            participants,
            threshold,
            schemes,
            seed,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn single_node_keyset() {
        let keys = KeySet::builder().nodes(1).seed(42).build().unwrap();
        assert_eq!(keys.node_count(), 1);
        assert_eq!(keys.threshold(), 1);
        assert!(keys.is_single_node());
    }

    #[test]
    fn four_node_keyset() {
        let keys = KeySet::builder().nodes(4).seed(42).build().unwrap();
        assert_eq!(keys.node_count(), 4);
        assert_eq!(keys.threshold(), 3);
        assert!(!keys.is_single_node());

        let gk = keys.group_public_key();
        assert!(!gk.is_empty());
    }

    #[test]
    fn deterministic_identity_keys() {
        let a = KeySet::builder().nodes(4).seed(42).build().unwrap();
        let b = KeySet::builder().nodes(4).seed(42).build().unwrap();

        for i in 0..4 {
            assert_eq!(
                Encode::encode(a.identity_key(i)),
                Encode::encode(b.identity_key(i)),
            );
        }

        // Threshold schemes are also deterministic with trusted-dealer mode.
        assert_eq!(a.group_public_key(), b.group_public_key());
    }

    #[test]
    fn reject_two_or_three_nodes() {
        assert!(KeySet::builder().nodes(2).seed(1).build().is_err());
        assert!(KeySet::builder().nodes(3).seed(1).build().is_err());
    }

    #[test]
    fn write_multi_node_creates_key_files() {
        let keys = KeySet::builder().nodes(4).seed(42).build().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let dirs: Vec<PathBuf> = (0..4)
            .map(|i| dir.path().join(format!("node{}", i)))
            .collect();

        keys.write_to(&dirs).unwrap();

        for d in &dirs {
            assert!(d.join("validator.key").exists());
            // No DKG output files.
            assert!(!d.join("output.json").exists());
            assert!(!d.join("share.key").exists());
        }
    }

    #[test]
    fn write_single_node_creates_key_only() {
        let keys = KeySet::builder().nodes(1).seed(42).build().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let node_dir = dir.path().join("node0");

        keys.write_to(&[node_dir.clone()]).unwrap();

        assert!(node_dir.join("validator.key").exists());
        assert!(!node_dir.join("output.json").exists());
    }

    #[test]
    fn scheme_multi_node() {
        let keys = KeySet::builder().nodes(4).seed(42).build().unwrap();

        for i in 0..4 {
            let scheme = keys.scheme(i);
            assert_eq!(scheme.participants().len(), 4);
        }
    }

    #[test]
    fn scheme_single_node() {
        let keys = KeySet::builder().nodes(1).seed(42).build().unwrap();
        let scheme = keys.scheme(0);
        assert_eq!(scheme.participants().len(), 1);
    }

    #[test]
    fn write_peers_creates_file() {
        let keys = KeySet::builder().nodes(4).seed(42).build().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let peers_path = dir.path().join("peers.json");
        let ports = vec![30300, 30301, 30302, 30303];

        keys.write_peers(&peers_path, &ports).unwrap();
        assert!(peers_path.exists());

        let content: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&peers_path).unwrap()).unwrap();
        assert_eq!(content["validators"], 4);
        assert_eq!(content["threshold"], 3);
    }
}
