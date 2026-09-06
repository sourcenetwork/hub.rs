use std::{collections::hash_map::RandomState, hash::BuildHasher};

use commonware_storage::translator::Translator;

// Covers a 32-byte relation prefix and a 32-byte subject identifier.
#[derive(Clone, Debug, Default)]
pub(super) struct KeyPrefix(RandomState);

impl Translator for KeyPrefix {
    type Key = [u8; 64];

    fn transform(&self, key: &[u8]) -> Self::Key {
        let mut prefix = [0; 64];
        let len = key.len().min(prefix.len());
        prefix[..len].copy_from_slice(&key[..len]);
        prefix
    }
}

impl BuildHasher for KeyPrefix {
    type Hasher = <RandomState as BuildHasher>::Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        self.0.build_hasher()
    }
}
