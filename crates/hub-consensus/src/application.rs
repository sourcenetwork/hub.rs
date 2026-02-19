//! Consensus application trait for block proposal and verification.

use alloy_primitives::B256;
use hub_domain::Block;

use crate::{ConsensusError, Digest};

/// Application interface for consensus integration.
///
/// This trait defines the hooks that a consensus engine calls during
/// the block lifecycle. Implementations handle block proposal during
/// leadership and block verification for blocks from other validators.
///
/// # Block Lifecycle
///
/// 1. **Proposal**: When this validator is elected leader, [`propose`](Self::propose)
///    is called to build a new block from pending transactions.
///
/// 2. **Verification**: When receiving a block from another validator,
///    [`verify`](Self::verify) re-executes the block to validate the state root.
///
/// 3. **Finalization**: When consensus finalizes a block, [`finalize`](Self::finalize)
///    persists the state changes and prunes the mempool.
///
/// 4. **Seed Updates**: The [`on_seed`](Self::on_seed) callback delivers threshold
///    VRF outputs for use in subsequent block prevrandao fields.
pub trait ConsensusApplication: Clone + Send + Sync + 'static {
    /// Propose a new block during leadership.
    ///
    /// Called when this validator is the leader for a slot. The implementation
    /// should:
    ///
    /// 1. Fetch pending transactions from the mempool
    /// 2. Execute transactions against the parent state
    /// 3. Compute the resulting state root
    /// 4. Construct and return a complete block
    ///
    /// # Arguments
    ///
    /// * `parent` - The digest of the parent block to build upon
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The parent snapshot is not found
    /// - Transaction execution fails
    /// - Block construction fails
    fn propose(&self, parent: Digest) -> Result<Block, ConsensusError>;

    /// Verify a block proposed by another validator.
    ///
    /// Re-executes the block's transactions against the parent state and
    /// validates that the computed state root matches the block header.
    /// This ensures all validators agree on the resulting state.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to verify
    ///
    /// # Returns
    ///
    /// The block's digest on successful verification.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The parent snapshot is not found
    /// - Transaction execution fails
    /// - The computed state root does not match the block's state root
    fn verify(&self, block: &Block) -> Result<Digest, ConsensusError>;

    /// Handle block finalization.
    ///
    /// Called when a block is finalized by consensus. Implementations should:
    ///
    /// 1. Persist pending state changes to durable storage
    /// 2. Remove finalized transactions from the mempool
    /// 3. Clean up any temporary execution state
    ///
    /// # Arguments
    ///
    /// * `digest` - The digest of the finalized block
    ///
    /// # Errors
    ///
    /// Returns an error if state persistence fails.
    fn finalize(&self, digest: Digest) -> Result<(), ConsensusError>;

    /// Handle a new seed from consensus.
    ///
    /// Seeds are derived from threshold VRF signatures during the consensus
    /// protocol. These seeds are used to populate the `prevrandao` field in
    /// subsequent blocks, providing a source of on-chain randomness.
    ///
    /// # Arguments
    ///
    /// * `digest` - The block digest this seed is associated with
    /// * `seed` - The VRF-derived seed value
    fn on_seed(&self, digest: Digest, seed: B256);
}

/// Extension trait for applications that support verification with custom context.
///
/// This trait allows implementations to provide additional verification
/// capabilities beyond the base [`ConsensusApplication`] trait.
pub trait ConsensusApplicationExt: ConsensusApplication {
    /// Verify a block with additional context.
    ///
    /// Some verification scenarios may require additional context beyond
    /// what is available in the block itself. This method allows passing
    /// an optional seed for prevrandao validation.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to verify
    /// * `seed` - Optional seed for prevrandao validation
    ///
    /// # Returns
    ///
    /// The block's digest on successful verification.
    fn verify_with_seed(&self, block: &Block, seed: Option<B256>)
    -> Result<Digest, ConsensusError>;
}

#[cfg(test)]
mod tests {
    use commonware_cryptography::Committable as _;

    use super::*;

    /// Mock application for testing trait bounds.
    #[derive(Clone)]
    struct MockApp;

    impl ConsensusApplication for MockApp {
        fn propose(&self, _parent: Digest) -> Result<Block, ConsensusError> {
            Ok(Block {
                context: Block::genesis_context(),
                parent: hub_domain::BlockId(alloy_primitives::B256::ZERO),
                height: 0,
                timestamp: 1_700_000_000,
                prevrandao: alloy_primitives::B256::ZERO,
                state_root: hub_domain::StateRoot(alloy_primitives::B256::ZERO),
                ibc_root: alloy_primitives::B256::ZERO,
                txs: Vec::new(),
            })
        }

        fn verify(&self, block: &Block) -> Result<Digest, ConsensusError> {
            Ok(block.commitment())
        }

        fn finalize(&self, _digest: Digest) -> Result<(), ConsensusError> {
            Ok(())
        }

        fn on_seed(&self, _digest: Digest, _seed: B256) {}
    }

    #[test]
    fn mock_app_propose() {
        let app = MockApp;
        let block = app.propose(Digest::from([0u8; 32])).unwrap();
        assert_eq!(block.height, 0);
    }

    #[test]
    fn mock_app_verify() {
        let app = MockApp;
        let block = Block {
            context: Block::genesis_context(),
            parent: hub_domain::BlockId(alloy_primitives::B256::ZERO),
            height: 0,
            timestamp: 1_700_000_000,
            prevrandao: alloy_primitives::B256::ZERO,
            state_root: hub_domain::StateRoot(alloy_primitives::B256::ZERO),
            ibc_root: alloy_primitives::B256::ZERO,
            txs: Vec::new(),
        };
        let digest = app.verify(&block).unwrap();
        assert_eq!(digest, block.commitment());
    }

    #[test]
    fn mock_app_finalize() {
        let app = MockApp;
        let result = app.finalize(Digest::from([0u8; 32]));
        assert!(result.is_ok());
    }

    #[test]
    fn mock_app_on_seed() {
        let app = MockApp;
        app.on_seed(Digest::from([0u8; 32]), B256::ZERO);
        // No panic means success for this simple test
    }
}
