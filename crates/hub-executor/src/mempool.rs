//! Mempool transaction validator — CheckTx equivalent with branched state.
//!
//! Validates both EVM (secp256k1) and BLS native transactions, maintaining
//! branched state across calls so sequential validations from the same sender
//! see each other's nonce increments.

use std::collections::BTreeMap;

use alloy_primitives::{Bytes, U256};
use hub_crypto::bls;
use hub_domain::NativeTx;
use hub_modules::native_account::NativeNonceStore;
use hub_overlay::OverlayState;
use hub_qmdb::{AccountUpdate, ChangeSet};
use hub_traits::StateDb;

use crate::precompiles::{ACP_ADDRESS, BULLETIN_ADDRESS, HUB_ADDRESS};
use crate::{ExecutionConfig, ExecutionError, TxValidator};

/// Result of validating a transaction for mempool admission.
#[derive(Clone, Debug)]
pub struct TxValidationResult {
    /// Sender identity — Ethereum address (hex) for EVM txs, `did:key:` for BLS native txs.
    pub sender: String,
    /// Transaction nonce.
    pub nonce: u64,
    /// Whether this is a native BLS transaction.
    pub is_native: bool,
}

/// Stateful transaction validator — mempool admission gate.
///
/// Maintains branched state across calls so sequential validations
/// from the same sender see each other's nonce increments.
/// Call [`MempoolValidator::reset`] after each block finalization.
#[derive(Clone, Debug)]
pub struct MempoolValidator<S> {
    config: ExecutionConfig,
    base: S,
    evm_changes: ChangeSet,
    native_nonces: NativeNonceStore,
    base_fee: u64,
}

impl<S: StateDb> MempoolValidator<S> {
    /// Create a new mempool validator against the given base state.
    pub fn new(base: S, config: ExecutionConfig, base_fee: u64) -> Self {
        Self {
            config,
            base,
            evm_changes: ChangeSet::new(),
            native_nonces: NativeNonceStore::default(),
            base_fee,
        }
    }

    /// Reset branched state after block finalization.
    pub fn reset(&mut self, base: S) {
        self.base = base;
        self.evm_changes = ChangeSet::new();
        self.native_nonces = NativeNonceStore::default();
    }

    /// Stateless recheck against committed base state.
    ///
    /// EVM txs: decode + recover signer + check nonce/balance (no branch mutation).
    /// BLS native txs: decode + check chain_id/target (skip sig verification).
    /// Native nonces are in-memory only, so native txs always pass recheck.
    pub async fn recheck_tx_stateless(&self, tx_bytes: &[u8]) -> Result<(), ExecutionError> {
        if tx_bytes.is_empty() {
            return Err(ExecutionError::TxDecode("empty transaction".to_string()));
        }
        if NativeTx::is_native_tx(tx_bytes[0]) {
            self.recheck_native_tx(tx_bytes)
        } else {
            self.recheck_evm_tx(tx_bytes).await
        }
    }

    async fn recheck_evm_tx(&self, tx_bytes: &[u8]) -> Result<(), ExecutionError> {
        let validator = TxValidator::new(&self.config, self.base_fee);
        let bytes = Bytes::from(tx_bytes.to_vec());
        validator.validate(&bytes, &self.base).await?;
        Ok(())
    }

    fn recheck_native_tx(&self, tx_bytes: &[u8]) -> Result<(), ExecutionError> {
        let native_tx = NativeTx::decode_wire(tx_bytes)
            .map_err(|e| ExecutionError::TxDecode(format!("native tx: {e}")))?;

        if native_tx.chain_id != self.config.chain_id {
            return Err(ExecutionError::ChainIdMismatch {
                expected: self.config.chain_id,
                got: native_tx.chain_id,
            });
        }

        if native_tx.target != ACP_ADDRESS
            && native_tx.target != BULLETIN_ADDRESS
            && native_tx.target != HUB_ADDRESS
        {
            return Err(ExecutionError::UnknownNativeTarget(native_tx.target));
        }

        Ok(())
    }

    /// Validate a transaction for mempool admission.
    ///
    /// Detects format by first byte (`0x45` = BLS native, else EVM).
    /// On success, increments the sender's nonce in the branched state.
    pub async fn validate_tx(
        &mut self,
        tx_bytes: &[u8],
    ) -> Result<TxValidationResult, ExecutionError> {
        if tx_bytes.is_empty() {
            return Err(ExecutionError::TxDecode("empty transaction".to_string()));
        }
        if NativeTx::is_native_tx(tx_bytes[0]) {
            self.validate_native_tx(tx_bytes)
        } else {
            self.validate_evm_tx(tx_bytes).await
        }
    }

    async fn validate_evm_tx(
        &mut self,
        tx_bytes: &[u8],
    ) -> Result<TxValidationResult, ExecutionError> {
        let overlay = OverlayState::new(self.base.clone(), self.evm_changes.clone());
        let validator = TxValidator::new(&self.config, self.base_fee);
        let bytes = Bytes::from(tx_bytes.to_vec());
        let validated = validator.validate(&bytes, &overlay).await?;

        let new_nonce = validated.nonce.checked_add(1).ok_or_else(|| {
            ExecutionError::InvalidTx(format!("nonce overflow for {:?}", validated.sender))
        })?;

        // Reserve balance for gas + value (matches Cosmos SDK AnteHandler behavior:
        // fees are deducted from branched checkState during CheckTx).
        let reserved =
            U256::from(validated.gas_limit) * U256::from(validated.max_fee) + validated.value;

        if let Some(account) = self.evm_changes.accounts.get_mut(&validated.sender) {
            account.nonce = new_nonce;
            account.balance = account.balance.saturating_sub(reserved);
        } else {
            let balance = self.base.balance(&validated.sender).await?;
            let code_hash = self.base.code_hash(&validated.sender).await?;
            self.evm_changes.accounts.insert(
                validated.sender,
                AccountUpdate {
                    created: false,
                    selfdestructed: false,
                    nonce: new_nonce,
                    balance: balance.saturating_sub(reserved),
                    code_hash,
                    code: None,
                    storage: BTreeMap::new(),
                },
            );
        }

        Ok(TxValidationResult {
            sender: format!("{:?}", validated.sender),
            nonce: validated.nonce,
            is_native: false,
        })
    }

    fn validate_native_tx(
        &mut self,
        tx_bytes: &[u8],
    ) -> Result<TxValidationResult, ExecutionError> {
        let native_tx = NativeTx::decode_wire(tx_bytes)
            .map_err(|e| ExecutionError::TxDecode(format!("native tx: {e}")))?;

        if native_tx.chain_id != self.config.chain_id {
            return Err(ExecutionError::ChainIdMismatch {
                expected: self.config.chain_id,
                got: native_tx.chain_id,
            });
        }

        if native_tx.target != ACP_ADDRESS
            && native_tx.target != BULLETIN_ADDRESS
            && native_tx.target != HUB_ADDRESS
        {
            return Err(ExecutionError::UnknownNativeTarget(native_tx.target));
        }

        let pubkey = bls::deserialize_pubkey(native_tx.bls_pubkey.as_slice())
            .map_err(|e| ExecutionError::BlsVerification(format!("pubkey: {e}")))?;

        let signing_data = native_tx.signing_data();
        bls::verify(&pubkey, &signing_data, native_tx.signature.as_slice())
            .map_err(|e| ExecutionError::BlsVerification(format!("signature: {e}")))?;

        let signer_did = bls::did_from_bls_pubkey(&pubkey)
            .map_err(|e| ExecutionError::BlsVerification(format!("DID: {e}")))?;

        self.native_nonces
            .check_and_increment(&signer_did, native_tx.nonce)
            .map_err(|e| match e {
                hub_modules::native_account::NonceError::Mismatch { did, expected, got } => {
                    ExecutionError::NonceMismatch { did, expected, got }
                }
                hub_modules::native_account::NonceError::Overflow(did) => {
                    ExecutionError::InvalidTx(format!("nonce overflow for {did}"))
                }
            })?;

        Ok(TxValidationResult {
            sender: signer_did,
            nonce: native_tx.nonce,
            is_native: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
    use alloy_primitives::{Address, B256, FixedBytes, KECCAK256_EMPTY, TxKind, U256};
    use alloy_rlp::Encodable;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use hub_qmdb::ChangeSet;
    use hub_traits::{StateDb, StateDbError, StateDbRead, StateDbWrite};

    use super::*;

    #[derive(Clone, Debug)]
    struct MockStateDb {
        accounts: BTreeMap<Address, (u64, U256)>,
    }

    impl MockStateDb {
        fn new() -> Self {
            Self {
                accounts: BTreeMap::new(),
            }
        }

        fn with_account(mut self, address: Address, nonce: u64, balance: U256) -> Self {
            self.accounts.insert(address, (nonce, balance));
            self
        }
    }

    impl StateDbRead for MockStateDb {
        async fn nonce(&self, address: &Address) -> Result<u64, StateDbError> {
            Ok(self.accounts.get(address).map(|(n, _)| *n).unwrap_or(0))
        }
        async fn balance(&self, address: &Address) -> Result<U256, StateDbError> {
            Ok(self
                .accounts
                .get(address)
                .map(|(_, b)| *b)
                .unwrap_or(U256::ZERO))
        }
        async fn code_hash(&self, _address: &Address) -> Result<B256, StateDbError> {
            Ok(KECCAK256_EMPTY)
        }
        async fn code(&self, _code_hash: &B256) -> Result<Bytes, StateDbError> {
            Ok(Bytes::new())
        }
        async fn storage(&self, _address: &Address, _slot: &U256) -> Result<U256, StateDbError> {
            Ok(U256::ZERO)
        }
    }

    impl StateDbWrite for MockStateDb {
        async fn commit(&self, _changes: ChangeSet) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
        async fn compute_root(&self, _changes: &ChangeSet) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
        fn merge_changes(&self, _older: ChangeSet, newer: ChangeSet) -> ChangeSet {
            newer
        }
    }

    impl StateDb for MockStateDb {
        async fn state_root(&self) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
    }

    const CHAIN_ID: u64 = 9001;

    fn test_config() -> ExecutionConfig {
        ExecutionConfig::new(CHAIN_ID)
    }

    fn signed_evm_tx(signer: &PrivateKeySigner, nonce: u64) -> Vec<u8> {
        let tx = TxEip1559 {
            chain_id: CHAIN_ID,
            nonce,
            gas_limit: 21000,
            max_fee_per_gas: 1000,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Bytes::new(),
            access_list: Default::default(),
        };
        let sig_hash = tx.signature_hash();
        let signature = signer.sign_hash_sync(&sig_hash).expect("sign");
        let signed = tx.into_signed(signature);
        let envelope = TxEnvelope::Eip1559(signed);
        let mut buf = Vec::new();
        envelope.encode(&mut buf);
        buf
    }

    fn test_bls_keypair() -> (ark_bls12_381::Fr, Vec<u8>) {
        use ark_bls12_381::{Fr, G1Affine, G1Projective};
        use ark_ec::{AffineRepr, CurveGroup};
        use ark_ff::UniformRand;
        use ark_serialize::CanonicalSerialize;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::from(G1Affine::generator()) * sk).into_affine();
        let mut pk_bytes = Vec::with_capacity(48);
        pk.serialize_compressed(&mut pk_bytes).unwrap();
        (sk, pk_bytes)
    }

    fn signed_native_tx(sk: &ark_bls12_381::Fr, pk_bytes: &[u8], nonce: u64) -> Vec<u8> {
        let mut tx = NativeTx {
            chain_id: CHAIN_ID,
            nonce,
            bls_pubkey: FixedBytes::from_slice(pk_bytes),
            target: Address::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x10,
            ]),
            calldata: Bytes::new(),
            signature: FixedBytes::from([0x00; 96]),
        };
        let signing_data = tx.signing_data();
        let sig = bls::sign(sk, &signing_data).unwrap();
        tx.signature = FixedBytes::from_slice(&sig);
        tx.encode_wire()
    }

    // -- EVM validation tests --

    #[tokio::test]
    async fn evm_valid_tx() {
        let signer = PrivateKeySigner::random();
        let sender = signer.address();
        let balance = U256::from(21000u64 * 1000 + 1);
        let state = MockStateDb::new().with_account(sender, 0, balance);
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx_bytes = signed_evm_tx(&signer, 0);
        let result = validator.validate_tx(&tx_bytes).await.unwrap();
        assert!(!result.is_native);
        assert_eq!(result.nonce, 0);
    }

    #[tokio::test]
    async fn evm_sequential_nonces() {
        let signer = PrivateKeySigner::random();
        let sender = signer.address();
        let balance = U256::from(21000u64 * 1000 * 10);
        let state = MockStateDb::new().with_account(sender, 0, balance);
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx0 = signed_evm_tx(&signer, 0);
        let r0 = validator.validate_tx(&tx0).await.unwrap();
        assert_eq!(r0.nonce, 0);

        let tx1 = signed_evm_tx(&signer, 1);
        let r1 = validator.validate_tx(&tx1).await.unwrap();
        assert_eq!(r1.nonce, 1);
    }

    #[tokio::test]
    async fn evm_nonce_replay_rejected() {
        let signer = PrivateKeySigner::random();
        let sender = signer.address();
        let balance = U256::from(21000u64 * 1000 * 10);
        let state = MockStateDb::new().with_account(sender, 0, balance);
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx0 = signed_evm_tx(&signer, 0);
        validator.validate_tx(&tx0).await.unwrap();

        let tx0_replay = signed_evm_tx(&signer, 0);
        let err = validator.validate_tx(&tx0_replay).await.unwrap_err();
        assert!(matches!(err, ExecutionError::InvalidTx(_)));
    }

    #[tokio::test]
    async fn evm_garbage_bytes_rejected() {
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let err = validator.validate_tx(&[0xFF, 0xFF]).await.unwrap_err();
        assert!(matches!(err, ExecutionError::TxDecode(_)));
    }

    // -- BLS native validation tests --

    #[tokio::test]
    async fn native_valid_tx() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx_bytes = signed_native_tx(&sk, &pk_bytes, 0);
        let result = validator.validate_tx(&tx_bytes).await.unwrap();
        assert!(result.is_native);
        assert_eq!(result.nonce, 0);
        assert!(result.sender.starts_with("did:key:"));
    }

    #[tokio::test]
    async fn native_sequential_nonces() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx0 = signed_native_tx(&sk, &pk_bytes, 0);
        let r0 = validator.validate_tx(&tx0).await.unwrap();
        assert_eq!(r0.nonce, 0);

        let tx1 = signed_native_tx(&sk, &pk_bytes, 1);
        let r1 = validator.validate_tx(&tx1).await.unwrap();
        assert_eq!(r1.nonce, 1);
    }

    #[tokio::test]
    async fn native_nonce_replay_rejected() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx0 = signed_native_tx(&sk, &pk_bytes, 0);
        validator.validate_tx(&tx0).await.unwrap();

        let tx0_replay = signed_native_tx(&sk, &pk_bytes, 0);
        let err = validator.validate_tx(&tx0_replay).await.unwrap_err();
        assert!(matches!(err, ExecutionError::NonceMismatch { .. }));
    }

    #[tokio::test]
    async fn native_wrong_chain_id() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let mut tx = NativeTx {
            chain_id: 999,
            nonce: 0,
            bls_pubkey: FixedBytes::from_slice(&pk_bytes),
            target: Address::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x10,
            ]),
            calldata: Bytes::new(),
            signature: FixedBytes::from([0x00; 96]),
        };
        let signing_data = tx.signing_data();
        let sig = bls::sign(&sk, &signing_data).unwrap();
        tx.signature = FixedBytes::from_slice(&sig);
        let wire = tx.encode_wire();

        let err = validator.validate_tx(&wire).await.unwrap_err();
        assert!(matches!(
            err,
            ExecutionError::ChainIdMismatch {
                expected: CHAIN_ID,
                got: 999,
            }
        ));
    }

    #[tokio::test]
    async fn native_invalid_bls_sig() {
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx = NativeTx {
            chain_id: CHAIN_ID,
            nonce: 0,
            bls_pubkey: FixedBytes::from([0xFF; 48]),
            target: Address::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x10,
            ]),
            calldata: Bytes::new(),
            signature: FixedBytes::from([0xBB; 96]),
        };
        let wire = tx.encode_wire();

        let err = validator.validate_tx(&wire).await.unwrap_err();
        assert!(matches!(err, ExecutionError::BlsVerification(_)));
    }

    #[tokio::test]
    async fn native_garbage_bytes() {
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let err = validator
            .validate_tx(&[0x45, 0xFF, 0xFF])
            .await
            .unwrap_err();
        assert!(matches!(err, ExecutionError::TxDecode(_)));
    }

    // -- Balance reservation tests --

    #[tokio::test]
    async fn evm_balance_exhaustion_rejects_second_tx() {
        let signer = PrivateKeySigner::random();
        let sender = signer.address();
        // Enough for exactly one tx: gas_limit(21000) * max_fee(1000) = 21_000_000
        let balance = U256::from(21_000_000u64);
        let state = MockStateDb::new().with_account(sender, 0, balance);
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx0 = signed_evm_tx(&signer, 0);
        validator.validate_tx(&tx0).await.unwrap();

        // Second tx should fail: reserved balance leaves 0 remaining.
        let tx1 = signed_evm_tx(&signer, 1);
        let err = validator.validate_tx(&tx1).await.unwrap_err();
        assert!(matches!(err, ExecutionError::InvalidTx(_)));
    }

    // -- Native target check tests --

    #[tokio::test]
    async fn native_unknown_target_rejected() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let bad_target = Address::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09, 0x99,
        ]);

        let mut tx = NativeTx {
            chain_id: CHAIN_ID,
            nonce: 0,
            bls_pubkey: FixedBytes::from_slice(&pk_bytes),
            target: bad_target,
            calldata: Bytes::new(),
            signature: FixedBytes::from([0x00; 96]),
        };
        let signing_data = tx.signing_data();
        let sig = bls::sign(&sk, &signing_data).unwrap();
        tx.signature = FixedBytes::from_slice(&sig);
        let wire = tx.encode_wire();

        let err = validator.validate_tx(&wire).await.unwrap_err();
        assert!(matches!(err, ExecutionError::UnknownNativeTarget(_)));
    }

    // -- Empty tx tests --

    #[tokio::test]
    async fn empty_tx_rejected() {
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let err = validator.validate_tx(&[]).await.unwrap_err();
        assert!(matches!(err, ExecutionError::TxDecode(_)));
    }

    // -- Reset tests --

    #[tokio::test]
    async fn reset_clears_nonce_state() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state.clone(), test_config(), 0);

        let tx0 = signed_native_tx(&sk, &pk_bytes, 0);
        validator.validate_tx(&tx0).await.unwrap();

        // After reset, nonce 0 should be accepted again (fresh state).
        validator.reset(state);

        let tx0_again = signed_native_tx(&sk, &pk_bytes, 0);
        let result = validator.validate_tx(&tx0_again).await.unwrap();
        assert_eq!(result.nonce, 0);
    }

    #[tokio::test]
    async fn reset_clears_evm_nonce_state() {
        let signer = PrivateKeySigner::random();
        let sender = signer.address();
        let balance = U256::from(21000u64 * 1000 * 10);
        let state = MockStateDb::new().with_account(sender, 0, balance);
        let mut validator = MempoolValidator::new(state.clone(), test_config(), 0);

        let tx0 = signed_evm_tx(&signer, 0);
        validator.validate_tx(&tx0).await.unwrap();

        // After reset, nonce 0 should be accepted again.
        validator.reset(state);

        let tx0_again = signed_evm_tx(&signer, 0);
        let result = validator.validate_tx(&tx0_again).await.unwrap();
        assert_eq!(result.nonce, 0);
    }

    // -- Format detection --

    #[tokio::test]
    async fn format_detection_native() {
        let (sk, pk_bytes) = test_bls_keypair();
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        let tx = signed_native_tx(&sk, &pk_bytes, 0);
        assert_eq!(tx[0], 0x45);
        let result = validator.validate_tx(&tx).await.unwrap();
        assert!(result.is_native);
    }

    #[tokio::test]
    async fn format_detection_evm() {
        let state = MockStateDb::new();
        let mut validator = MempoolValidator::new(state, test_config(), 0);

        // 0x02 is EIP-1559 type prefix, but garbage RLP → TxDecode.
        // This still proves format detection routes to EVM path.
        let err = validator.validate_tx(&[0x02, 0xFF]).await.unwrap_err();
        assert!(matches!(err, ExecutionError::TxDecode(_)));
    }
}
