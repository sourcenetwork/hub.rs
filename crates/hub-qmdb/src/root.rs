//! State root computation.

use alloy_primitives::{B256, keccak256};

const HUB_ROOT_NAMESPACE: &[u8] = b"_HUB_QMDB_ROOT";

/// State root computation utility.
#[derive(Debug, Clone, Copy)]
pub struct StateRoot;

impl StateRoot {
    /// Compute state root from three partition roots.
    pub fn compute(accounts_root: B256, storage_root: B256, code_root: B256) -> B256 {
        let mut buf = Vec::with_capacity(HUB_ROOT_NAMESPACE.len() + 96);
        buf.extend_from_slice(HUB_ROOT_NAMESPACE);
        buf.extend_from_slice(accounts_root.as_slice());
        buf.extend_from_slice(storage_root.as_slice());
        buf.extend_from_slice(code_root.as_slice());
        keccak256(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_root() {
        let a = B256::repeat_byte(0x11);
        let s = B256::repeat_byte(0x22);
        let c = B256::repeat_byte(0x33);

        let root1 = StateRoot::compute(a, s, c);
        let root2 = StateRoot::compute(a, s, c);
        assert_eq!(root1, root2);
    }

    #[test]
    fn different_inputs_different_root() {
        let root1 = StateRoot::compute(B256::ZERO, B256::ZERO, B256::ZERO);
        let root2 = StateRoot::compute(B256::repeat_byte(1), B256::ZERO, B256::ZERO);
        assert_ne!(root1, root2);
    }
}
