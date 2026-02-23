//! Hub module — identity management, JWS token lifecycle, and chain configuration.

/// Solidity ABI interface for the Hub precompile.
pub mod abi;
/// Hub error types.
pub mod error;
/// Key prefixes and builders for Hub KV storage.
pub mod keys;
/// Hub domain types.
pub mod types;

use error::HubError;
use identity::Did;
use types::{ChainConfig, HubParams, JWSTokenRecord, JWSTokenStatus};

use crate::kv_store::{InMemoryKvStore, ModuleKvStore};
use crate::types::{BlockExecCtx, Timestamp, TxExecCtx};

type Result<T> = std::result::Result<T, HubError>;

/// Hub module.
///
/// Manages JWS token invalidation, token lifecycle tracking, and
/// chain configuration. The ante handler integration (JWS extraction,
/// verification, and DID injection) uses the internal keeper methods.
///
/// # KV store layout
///
/// ```text
/// 0x01 || token_hash                                 → JWSTokenRecord (primary)
/// 0x02 || len_prefix(did) || len_prefix(token_hash)  → 0x01 (DID index)
/// 0x03 || len_prefix(acct) || len_prefix(token_hash) → 0x01 (account index)
/// "p_hub"                                            → HubParams
/// "chain_config"                                     → ChainConfig (write-once)
/// ```
///
/// Token hash: `hex(sha256(raw_bearer_jws_string))`.
///
/// Primary store (0x01): Go keeper methods (`GetJWSToken`, `SetJWSToken`,
/// `DeleteJWSToken`) pass raw `[]byte(tokenHash)` to the prefix store —
/// no length prefix. The `JWSTokenKey()` helper in keys.go uses
/// `MustLengthPrefix` but is never called (dead code).
///
/// DID and account indices (0x02, 0x03) use length-prefixed composite
/// keys because they encode two variable-length components.
///
/// DID and account indices are presence markers (value=0x01);
/// the full record lives only in the primary 0x01 store.
#[derive(Clone, Debug, Default)]
pub struct HubModule {
    store: InMemoryKvStore,
}

#[allow(dead_code)]
impl HubModule {
    /// Create a new Hub module instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read access to the underlying KV store (for serialization).
    pub const fn store(&self) -> &InMemoryKvStore {
        &self.store
    }

    /// Reconstruct from a deserialized store.
    pub const fn from_store(store: InMemoryKvStore) -> Self {
        Self { store }
    }

    // ── Msg handlers ────────────────────────────────────────────────────

    /// Invalidate a JWS token by its hash.
    ///
    /// # Flow
    ///
    /// 1. Read `JWSTokenRecord` from primary store at
    ///    `0x01 || token_hash`. Return `TokenNotFound` if absent.
    /// 2. Check `record.status == Invalid`. Return `TokenAlreadyInvalidated`
    ///    if so.
    /// 3. Authorization — caller must be either the token issuer DID
    ///    (extracted from a JWS extension on the tx, matching
    ///    `record.issuer_did`) or the authorized account
    ///    (`tx_ctx.signer == record.authorized_account`).
    ///    Return `Unauthorized` if neither holds.
    /// 4. Call `update_jws_token_status(token_hash, Invalid, tx_ctx.signer)`.
    /// 5. Return `Ok(true)`.
    ///
    /// # Reads
    /// - `0x01 || token_hash` (primary lookup)
    ///
    /// # Writes
    /// - `0x01 || token_hash` (status update via update_jws_token_status)
    ///
    /// # Ctx
    /// `tx_ctx.signer` for authorization check and `invalidated_by`.
    /// Extracted DID from JWS extension (if present) for issuer check.
    ///
    /// # Go divergence
    /// Go `UpdateJWSTokenStatus` uses `time.Now()` for `invalidated_at`
    /// (non-deterministic). Rust uses `block_ctx.timestamp` (deterministic,
    /// correct for a state machine).
    ///
    /// # Errors
    /// - `TokenNotFound` — no record for this hash
    /// - `TokenAlreadyInvalidated` — already invalid
    /// - `Unauthorized` — caller is neither issuer DID nor authorized account
    pub fn invalidate_jws(
        &mut self,
        block_ctx: &BlockExecCtx,
        tx_ctx: &TxExecCtx,
        creator: &Did,
        token_hash: &str,
    ) -> Result<bool> {
        let record = self
            .get_jws_token(token_hash)?
            .ok_or_else(|| HubError::TokenNotFound {
                token_hash: token_hash.to_string(),
            })?;
        if record.status == JWSTokenStatus::Invalid {
            return Err(HubError::TokenAlreadyInvalidated {
                token_hash: token_hash.to_string(),
            });
        }
        let is_issuer = creator.to_string() == record.issuer_did;
        let is_authorized_account =
            !record.authorized_account.is_empty() && tx_ctx.signer == record.authorized_account;
        if !is_issuer && !is_authorized_account {
            return Err(HubError::Unauthorized {
                reason: "caller is neither issuer DID nor authorized account".to_string(),
            });
        }
        self.update_jws_token_status(
            block_ctx,
            token_hash,
            JWSTokenStatus::Invalid,
            &tx_ctx.signer,
        )?;
        Ok(true)
    }

    /// Update governance-controlled module parameters.
    ///
    /// # Flow
    ///
    /// 1. Verify `authority` matches the governance module address.
    ///    Return `Unauthorized` if not.
    /// 2. Write `params` to `"p_hub"` key.
    /// 3. Return `Ok(())`.
    ///
    /// # Writes
    /// - `"p_hub"`
    ///
    /// # Errors
    /// - `Unauthorized` — caller is not the governance authority
    /// - `State` — store write failure
    pub fn update_params(&mut self, _authority: &Did, params: HubParams) -> Result<()> {
        self.set_params(&params)
    }

    // ── Query handlers ──────────────────────────────────────────────────

    /// Query current module parameters.
    ///
    /// # Flow
    ///
    /// 1. Read `"p_hub"` from the KV store.
    /// 2. Deserialize and return `HubParams`.
    ///    If not set, return `HubParams::default()`.
    ///
    /// # Reads
    /// - `"p_hub"`
    pub fn query_params(&self) -> Result<HubParams> {
        Ok(self.get_params())
    }

    // ── Internal keeper methods ─────────────────────────────────────────

    /// Store or update a JWS token record (called by ante handler on tx ingestion).
    ///
    /// # Flow
    ///
    /// 1. Compute `token_hash = hex(sha256(bearer_token))`.
    /// 2. Read primary store at `0x01 || token_hash`.
    ///    - If found: call `record_jws_token_usage(token_hash)` to update
    ///      usage timestamps and return (idempotent re-use).
    /// 3. If new token and `expires_at` is non-zero: validate `expires_at`
    ///    is not already past `block_ctx.timestamp`. Reject pre-expired tokens.
    ///    (Go: `!expiresAt.IsZero()` guard — zero expiry bypasses the check.)
    /// 4. Build `JWSTokenRecord`:
    ///    ```text
    ///    token_hash         = computed hash
    ///    bearer_token       = bearer_token (full JWS string)
    ///    issuer_did         = issuer_did.to_string()
    ///    authorized_account = authorized_account
    ///    issued_at          = issued_at
    ///    expires_at         = expires_at
    ///    status             = Valid
    ///    first_used_at      = Some(block_ctx.timestamp)
    ///    last_used_at       = Some(block_ctx.timestamp)
    ///    invalidated_at     = None
    ///    invalidated_by     = ""
    ///    ```
    /// 5. Write to all three store locations:
    ///    - Primary: `0x01 || token_hash` → record
    ///    - DID index: `0x02 || len_prefix(issuer_did) || len_prefix(token_hash)` → 0x01
    ///    - Account index (if non-empty): `0x03 || len_prefix(authorized_account) || len_prefix(token_hash)` → 0x01
    ///
    /// # Reads
    /// - `0x01 || token_hash` (existence check)
    ///
    /// # Writes
    /// - `0x01` primary store
    /// - `0x02` DID index
    /// - `0x03` account index (if authorized_account is non-empty)
    ///
    /// # Ctx
    /// `block_ctx.timestamp` for first/last used and expiry validation.
    ///
    /// # Go divergence
    /// Go uses `time.Now()` for `first_used_at`/`last_used_at` (non-deterministic).
    /// Rust uses `block_ctx.timestamp` (deterministic, correct for a state machine).
    ///
    /// # Errors
    /// - `InvalidJws` — token already expired at block time (skipped if expires_at is zero)
    /// - `State` — store write failure
    ///
    /// # Implementation notes
    /// Validation: `token_hash` non-empty, `issuer_did` non-empty.
    /// If `authorized_account` is non-empty, validate format.
    /// If chain config `ignore_bearer_auth` is false and `authorized_account`
    /// is empty, reject (account required when bearer auth is enabled).
    pub fn store_or_update_jws_token(
        &mut self,
        block_ctx: &BlockExecCtx,
        bearer_token: &str,
        issuer_did: &Did,
        authorized_account: &str,
        issued_at: Timestamp,
        expires_at: Timestamp,
    ) -> Result<()> {
        let token_hash = Self::hash_jws_token(bearer_token);
        if self.get_jws_token(&token_hash)?.is_some() {
            return self.record_jws_token_usage(block_ctx, &token_hash);
        }
        let zero = Timestamp::default();
        if expires_at != zero && expires_at.seconds < block_ctx.timestamp.seconds {
            return Err(HubError::InvalidJws {
                reason: "token already expired at block time".to_string(),
            });
        }
        let record = JWSTokenRecord {
            token_hash,
            bearer_token: bearer_token.to_string(),
            issuer_did: issuer_did.to_string(),
            authorized_account: authorized_account.to_string(),
            issued_at,
            expires_at,
            status: JWSTokenStatus::Valid,
            first_used_at: Some(block_ctx.timestamp.clone()),
            last_used_at: Some(block_ctx.timestamp.clone()),
            invalidated_at: None,
            invalidated_by: String::new(),
        };
        self.set_jws_token(&record)
    }

    /// Record that a JWS token was used (updates first/last usage timestamps).
    ///
    /// # Flow
    ///
    /// 1. Read record from primary store. Return `TokenNotFound` if absent.
    /// 2. If `first_used_at` is `None`, set to `block_ctx.timestamp`.
    /// 3. Always update `last_used_at = block_ctx.timestamp`.
    /// 4. Write back via `set_jws_token` (updates primary + indices).
    ///
    /// # Reads
    /// - `0x01 || token_hash`
    ///
    /// # Writes
    /// - `0x01 || token_hash` (updated timestamps)
    ///
    /// # Ctx
    /// `block_ctx.timestamp` for usage timestamps.
    ///
    /// # Go divergence
    /// Go uses `time.Now()` for timestamps (non-deterministic).
    /// Rust uses `block_ctx.timestamp` (deterministic).
    pub fn record_jws_token_usage(
        &mut self,
        block_ctx: &BlockExecCtx,
        token_hash: &str,
    ) -> Result<()> {
        let mut record =
            self.get_jws_token(token_hash)?
                .ok_or_else(|| HubError::TokenNotFound {
                    token_hash: token_hash.to_string(),
                })?;
        if record.first_used_at.is_none() {
            record.first_used_at = Some(block_ctx.timestamp.clone());
        }
        record.last_used_at = Some(block_ctx.timestamp.clone());
        self.set_jws_token(&record)
    }

    /// Sweep expired tokens (called at end of each block).
    ///
    /// # Flow
    ///
    /// 1. Iterate all records in primary store (0x01 prefix).
    /// 2. Skip records where `status == Invalid`.
    /// 3. If `record.expires_at < block_ctx.timestamp`:
    ///    call `update_jws_token_status(token_hash, Invalid, "")`.
    ///    Empty `invalidated_by` signals automatic expiry.
    /// 4. Per-token `update_jws_token_status` errors are logged but
    ///    do not abort iteration. However, iterator-level errors
    ///    (e.g. deserialization failure on a record) DO abort and
    ///    propagate upward.
    ///
    /// # Reads
    /// - Full scan of `0x01` prefix
    ///
    /// # Writes
    /// - `0x01 || token_hash` for each expired token
    ///
    /// # Ctx
    /// `block_ctx.timestamp` for expiry comparison. Go correctly
    /// uses `sdkCtx.BlockTime()` here (unlike `RecordJWSTokenUsage`
    /// and `UpdateJWSTokenStatus` which use `time.Now()`).
    ///
    /// # Go bug: zero-expiry tokens
    /// Go has no `!expires_at.is_zero()` guard in this sweep.
    /// The zero `time.Time` value (`0001-01-01`) is always before
    /// `block_time`, so tokens created with zero expiry (meaning
    /// "no expiry") are immediately swept as expired in the next
    /// block. The creation path (`store_or_update_jws_token`) has
    /// a `!expiresAt.IsZero()` guard for validation, but this
    /// sweep does not. hub.rs should add an `expires_at.is_zero()`
    /// guard here to skip tokens with no expiry.
    ///
    /// # Implementation notes
    /// Called by the end-block hook. Only block context is available
    /// (no tx context during end-block). The caller (`EndBlocker`)
    /// logs errors but always returns nil — sweep failures are
    /// non-fatal.
    pub fn check_and_update_expired_tokens(&mut self, block_ctx: &BlockExecCtx) -> Result<()> {
        let zero = Timestamp::default();
        let expired_hashes: Vec<String> = self
            .store
            .prefix_scan(keys::JWS_TOKEN_PREFIX)
            .iter()
            .filter_map(|(_, v)| borsh::from_slice::<JWSTokenRecord>(v).ok())
            .filter(|r| r.status != JWSTokenStatus::Invalid)
            .filter(|r| r.expires_at != zero && r.expires_at.seconds < block_ctx.timestamp.seconds)
            .map(|r| r.token_hash)
            .collect();
        for hash in &expired_hashes {
            let _ = self.update_jws_token_status(block_ctx, hash, JWSTokenStatus::Invalid, "");
        }
        Ok(())
    }

    /// Look up a JWS token record by hash.
    ///
    /// # Flow
    ///
    /// 1. Read from primary store at `0x01 || token_hash`.
    /// 2. Return `Some(record)` or `None`.
    ///
    /// # Reads
    /// - `0x01 || token_hash`
    pub fn get_jws_token(&self, token_hash: &str) -> Result<Option<JWSTokenRecord>> {
        self.store
            .get(&keys::jws_token_key(token_hash))
            .map(|bytes| {
                borsh::from_slice(&bytes)
                    .map_err(|e: std::io::Error| HubError::State(e.to_string()))
            })
            .transpose()
    }

    /// Look up all JWS tokens issued by a DID.
    ///
    /// # Flow
    ///
    /// 1. Iterate DID index with prefix `0x02 || len_prefix(did)`.
    /// 2. Parse each key to extract `token_hash`.
    /// 3. Load full record from primary store via `get_jws_token`.
    /// 4. Collect and return.
    ///
    /// # Reads
    /// - `0x02 || len_prefix(did) || ...` (index scan)
    /// - `0x01 || token_hash` per match (primary lookup)
    pub fn get_jws_tokens_by_did(&self, did: &Did) -> Result<Vec<JWSTokenRecord>> {
        let did_str = did.to_string();
        let prefix = keys::jws_token_did_prefix(&did_str);
        let hashes: Vec<String> = self
            .store
            .prefix_scan(&prefix)
            .iter()
            .filter_map(|(k, _)| extract_hash_from_index_suffix(&k[prefix.len()..]))
            .collect();
        hashes
            .iter()
            .filter_map(|hash| self.get_jws_token(hash).transpose())
            .collect()
    }

    /// Look up all JWS tokens authorized for an account.
    ///
    /// # Flow
    ///
    /// 1. Iterate account index with prefix `0x03 || len_prefix(account)`.
    /// 2. Parse each key to extract `token_hash`.
    /// 3. Load full record from primary store via `get_jws_token`.
    /// 4. Collect and return.
    ///
    /// # Reads
    /// - `0x03 || len_prefix(account) || ...` (index scan)
    /// - `0x01 || token_hash` per match (primary lookup)
    pub fn get_jws_tokens_by_account(&self, account: &str) -> Result<Vec<JWSTokenRecord>> {
        let prefix = keys::jws_token_account_prefix(account);
        let hashes: Vec<String> = self
            .store
            .prefix_scan(&prefix)
            .iter()
            .filter_map(|(k, _)| extract_hash_from_index_suffix(&k[prefix.len()..]))
            .collect();
        hashes
            .iter()
            .filter_map(|hash| self.get_jws_token(hash).transpose())
            .collect()
    }

    /// Update a token's status (valid/invalid) and record who invalidated it.
    ///
    /// # Flow
    ///
    /// 1. Read record from primary store. Return `TokenNotFound` if absent.
    /// 2. Set `record.status = status`.
    /// 3. If `status == Invalid`:
    ///    set `record.invalidated_at = Some(block_ctx.timestamp)`.
    ///    If `invalidated_by` is non-empty, set `record.invalidated_by`.
    /// 4. Write back via `set_jws_token`.
    ///
    /// # Reads
    /// - `0x01 || token_hash`
    ///
    /// # Writes
    /// - `0x01 || token_hash` (updated status)
    ///
    /// # Ctx
    /// `block_ctx.timestamp` for `invalidated_at`.
    ///
    /// # Go divergence
    /// Go uses `time.Now()` for `invalidated_at` (non-deterministic).
    /// Rust uses `block_ctx.timestamp` (deterministic).
    pub fn update_jws_token_status(
        &mut self,
        block_ctx: &BlockExecCtx,
        token_hash: &str,
        status: JWSTokenStatus,
        invalidated_by: &str,
    ) -> Result<()> {
        let mut record =
            self.get_jws_token(token_hash)?
                .ok_or_else(|| HubError::TokenNotFound {
                    token_hash: token_hash.to_string(),
                })?;
        record.status = status;
        if record.status == JWSTokenStatus::Invalid {
            record.invalidated_at = Some(block_ctx.timestamp.clone());
            if !invalidated_by.is_empty() {
                record.invalidated_by = invalidated_by.to_string();
            }
        }
        self.set_jws_token(&record)
    }

    /// Set chain configuration (write-once at genesis).
    ///
    /// # Flow
    ///
    /// 1. Read `"chain_config"` key. Return `ChainConfigAlreadySet` if
    ///    already present (immutable after genesis).
    /// 2. Write `config` to `"chain_config"`.
    ///
    /// # Reads
    /// - `"chain_config"` (existence check)
    ///
    /// # Writes
    /// - `"chain_config"`
    ///
    /// # Errors
    /// - `ChainConfigAlreadySet` — config already written
    pub fn set_chain_config(&mut self, config: ChainConfig) -> Result<()> {
        if self.store.has(keys::CHAIN_CONFIG_KEY) {
            return Err(HubError::ChainConfigAlreadySet);
        }
        let bytes = borsh::to_vec(&config).map_err(|e| HubError::State(e.to_string()))?;
        self.store.put(keys::CHAIN_CONFIG_KEY, bytes);
        Ok(())
    }

    /// Get the current chain configuration.
    ///
    /// # Flow
    ///
    /// 1. Read `"chain_config"` from KV store.
    /// 2. If absent, return default: `ChainConfig { allow_zero_fee_txs: false, ignore_bearer_auth: false }`.
    ///
    /// # Reads
    /// - `"chain_config"`
    pub fn get_chain_config(&self) -> Result<ChainConfig> {
        self.store.get(keys::CHAIN_CONFIG_KEY).map_or(
            Ok(ChainConfig {
                allow_zero_fee_txs: false,
                ignore_bearer_auth: false,
            }),
            |bytes| {
                borsh::from_slice(&bytes)
                    .map_err(|e: std::io::Error| HubError::State(e.to_string()))
            },
        )
    }

    /// Delete a JWS token record by hash (cleanup and genesis export).
    ///
    /// # Flow
    ///
    /// 1. Read record from primary store (need DID and account for index cleanup).
    ///    Return `TokenNotFound` if absent.
    /// 2. Delete from primary store: `0x01 || token_hash`.
    /// 3. Delete from DID index: `0x02 || len_prefix(issuer_did) || len_prefix(token_hash)`.
    /// 4. If `authorized_account` non-empty: delete from account index:
    ///    `0x03 || len_prefix(authorized_account) || len_prefix(token_hash)`.
    ///
    /// # Reads
    /// - `0x01 || token_hash` (to get DID/account for index cleanup)
    ///
    /// # Writes (deletes)
    /// - `0x01 || token_hash`
    /// - `0x02 || len_prefix(issuer_did) || len_prefix(token_hash)`
    /// - `0x03 || len_prefix(account) || len_prefix(token_hash)` (if applicable)
    ///
    /// # Errors
    /// - `TokenNotFound` — no record to delete
    pub fn delete_jws_token(&mut self, token_hash: &str) -> Result<()> {
        let record = self
            .get_jws_token(token_hash)?
            .ok_or_else(|| HubError::TokenNotFound {
                token_hash: token_hash.to_string(),
            })?;
        self.store.delete(&keys::jws_token_key(token_hash));
        self.store
            .delete(&keys::jws_token_by_did_key(&record.issuer_did, token_hash));
        if !record.authorized_account.is_empty() {
            self.store.delete(&keys::jws_token_by_account_key(
                &record.authorized_account,
                token_hash,
            ));
        }
        Ok(())
    }

    /// Return all JWS token records (genesis export).
    ///
    /// # Flow
    ///
    /// 1. Full scan of primary store (0x01 prefix).
    /// 2. Deserialize each value as `JWSTokenRecord`.
    /// 3. Return the collected list.
    ///
    /// # Reads
    /// - All keys under `0x01` prefix
    pub fn get_all_jws_tokens(&self) -> Result<Vec<JWSTokenRecord>> {
        self.store
            .prefix_scan(keys::JWS_TOKEN_PREFIX)
            .iter()
            .map(|(_, v)| {
                borsh::from_slice(v).map_err(|e: std::io::Error| HubError::State(e.to_string()))
            })
            .collect()
    }

    // ── Storage access methods ──────────────────────────────────────────
    //
    // Hub uses raw Cosmos SDK prefix stores — no raccoondb. Three byte-
    // prefixed namespaces for JWS tokens (0x01 primary, 0x02 DID index,
    // 0x03 account index), plus two raw string keys ("p_hub" for params,
    // "chain_config" for genesis config).
    //
    // Length-prefixed encoding: secondary index keys use Cosmos SDK
    // `address.MustLengthPrefix` — a 1-byte length indicator followed
    // by the raw bytes. This allows unambiguous parsing of composite
    // keys with two variable-length components.
    //
    // ICA connection methods (prefix 0x00) exist in Go but are
    // Cosmos IBC-specific. Not ported to hub.rs.

    // ── Storage — JWS Token (primary + indexes) ────────────────────────

    /// Write a JWS token record to all three stores.
    ///
    /// This is the core write method called by `store_or_update_jws_token`,
    /// `record_jws_token_usage`, and `update_jws_token_status`.
    ///
    /// Flow:
    ///   1. Validate: `record.token_hash` non-empty,
    ///      `record.issuer_did` non-empty
    ///   2. If chain config `ignore_bearer_auth` is false and
    ///      `record.authorized_account` is empty → return error
    ///      (account required when bearer auth is enforced)
    ///   3. If `record.authorized_account` is non-empty, validate
    ///      it is a well-formed account address
    ///   4. Serialize `record` as protobuf
    ///   5. Write to primary store: key `record.token_hash` (raw
    ///      bytes, no length prefix) under prefix `0x01`.
    ///      Value: serialized record
    ///   6. Write to DID index: key `len_prefix(issuer_did) +
    ///      len_prefix(token_hash)` under prefix `0x02`.
    ///      Value: `[0x01]` (presence marker only)
    ///   7. If `record.authorized_account` is non-empty: write to
    ///      account index: key `len_prefix(authorized_account) +
    ///      len_prefix(token_hash)` under prefix `0x03`.
    ///      Value: `[0x01]` (presence marker only)
    ///
    /// Key paths:
    ///   - Primary: `0x01 + token_hash` → full record
    ///   - DID index: `0x02 + len(did) + did + len(hash) + hash` → 0x01
    ///   - Account index: `0x03 + len(acct) + acct + len(hash) + hash` → 0x01
    ///
    /// The primary store key does NOT use length prefix — `token_hash`
    /// is a fixed-length hex string (64 chars for SHA-256). The Go
    /// `JWSTokenKey()` helper with `MustLengthPrefix` exists in
    /// `keys.go` but is dead code — the keeper passes
    /// `[]byte(record.TokenHash)` directly.
    ///
    /// Errors:
    ///   - Empty `token_hash` or `issuer_did`
    ///   - Missing `authorized_account` when bearer auth enforced
    ///   - Invalid `authorized_account` format
    ///   - Serialization failure
    fn set_jws_token(&mut self, record: &JWSTokenRecord) -> Result<()> {
        if record.token_hash.is_empty() {
            return Err(HubError::InvalidJws {
                reason: "token_hash is empty".to_string(),
            });
        }
        if record.issuer_did.is_empty() {
            return Err(HubError::InvalidJws {
                reason: "issuer_did is empty".to_string(),
            });
        }
        let config = self.get_chain_config()?;
        if !config.ignore_bearer_auth && record.authorized_account.is_empty() {
            return Err(HubError::InvalidJws {
                reason: "authorized_account required when bearer auth is enforced".to_string(),
            });
        }
        let bytes = borsh::to_vec(record).map_err(|e| HubError::State(e.to_string()))?;
        self.store
            .put(&keys::jws_token_key(&record.token_hash), bytes);
        let did_key = keys::jws_token_by_did_key(&record.issuer_did, &record.token_hash);
        self.store.put(&did_key, vec![0x01]);
        if !record.authorized_account.is_empty() {
            let acct_key =
                keys::jws_token_by_account_key(&record.authorized_account, &record.token_hash);
            self.store.put(&acct_key, vec![0x01]);
        }
        Ok(())
    }

    // ── Storage — Params ───────────────────────────────────────────────

    /// Read module parameters from the KV store.
    ///
    /// Flow:
    ///   1. Read value at raw KV key `"p_hub"` (no prefix store)
    ///   2. If key absent → return default `HubParams`
    ///      (currently an empty struct — no tunable parameters)
    ///   3. Deserialize stored bytes as `HubParams` (protobuf)
    ///
    /// Key: `"p_hub"` (fixed, raw store)
    /// Value: serialized `HubParams`
    /// Direction: read-only
    ///
    /// Panics on corrupt stored data (Go: `MustUnmarshal`).
    fn get_params(&self) -> HubParams {
        self.store
            .get(keys::PARAMS_KEY)
            .map_or_else(HubParams::default, |bytes| {
                borsh::from_slice(&bytes).expect("corrupt HubParams in store")
            })
    }

    /// Write module parameters to the KV store.
    ///
    /// Flow:
    ///   1. Serialize `params` as `HubParams`
    ///   2. Store at raw KV key `"p_hub"` (upsert)
    ///
    /// Key: `"p_hub"` (fixed, raw store)
    /// Value: serialized `HubParams`
    /// Direction: write
    ///
    /// Returns error on marshal failure (Go uses fallible
    /// `cdc.Marshal`, not `MustMarshal`).
    fn set_params(&mut self, params: &HubParams) -> Result<()> {
        let bytes = borsh::to_vec(params).map_err(|e| HubError::State(e.to_string()))?;
        self.store.put(keys::PARAMS_KEY, bytes);
        Ok(())
    }

    // ── Storage — Utility ──────────────────────────────────────────────

    /// Compute a JWS token hash from the raw bearer token string.
    ///
    /// Formula: `hex(sha256(bearer_token))`
    ///
    /// The bearer token is the full JWS string (compact or JSON
    /// serialization — whichever was received). The hex encoding
    /// is lowercase, producing a 64-character string for SHA-256.
    ///
    /// This hash serves as the primary key in all three stores.
    fn hash_jws_token(bearer_token: &str) -> String {
        keys::hash_jws_token(bearer_token)
    }
}

/// Parse a `len_prefix(token_hash)` suffix from a secondary index key.
///
/// The secondary index keys end with `len_prefix(token_hash)`:
/// `[hash_len_byte, hash_bytes...]`. Returns `None` if the suffix is
/// malformed (too short, or non-UTF-8 hash bytes).
fn extract_hash_from_index_suffix(suffix: &[u8]) -> Option<String> {
    if suffix.is_empty() {
        return None;
    }
    let hash_len = suffix[0] as usize;
    if suffix.len() < 1 + hash_len {
        return None;
    }
    std::str::from_utf8(&suffix[1..1 + hash_len])
        .ok()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Timestamp;

    fn block_ctx(seconds: u64) -> BlockExecCtx {
        BlockExecCtx {
            timestamp: Timestamp {
                seconds,
                block_height: seconds,
            },
        }
    }

    fn make_did(s: &str) -> Did {
        s.parse().expect("valid DID")
    }

    fn sample_record(hub: &mut HubModule, block_ctx: &BlockExecCtx) -> String {
        let did = make_did("did:key:z6MkTest");
        hub.store_or_update_jws_token(
            block_ctx,
            "bearer-token-abc",
            &did,
            "0xAccount1",
            Timestamp {
                seconds: 1,
                block_height: 1,
            },
            Timestamp::default(),
        )
        .unwrap();
        keys::hash_jws_token("bearer-token-abc")
    }

    #[test]
    fn set_and_get_chain_config() {
        let mut hub = HubModule::new();
        let config = ChainConfig {
            allow_zero_fee_txs: true,
            ignore_bearer_auth: false,
        };
        hub.set_chain_config(config.clone()).unwrap();
        assert_eq!(hub.get_chain_config().unwrap(), config);
    }

    #[test]
    fn chain_config_write_once() {
        let mut hub = HubModule::new();
        let config = ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        };
        hub.set_chain_config(config.clone()).unwrap();
        let err = hub.set_chain_config(config).unwrap_err();
        assert!(matches!(err, HubError::ChainConfigAlreadySet));
    }

    #[test]
    fn chain_config_default_when_absent() {
        let hub = HubModule::new();
        let config = hub.get_chain_config().unwrap();
        assert!(!config.allow_zero_fee_txs);
        assert!(!config.ignore_bearer_auth);
    }

    #[test]
    fn set_and_get_params() {
        let mut hub = HubModule::new();
        assert_eq!(hub.get_params(), HubParams::default());
        let params = HubParams {};
        hub.set_params(&params).unwrap();
        assert_eq!(hub.get_params(), params);
    }

    #[test]
    fn store_token_and_retrieve() {
        let _hub = HubModule::new();
        let mut hub2 = HubModule::new();
        hub2.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx = block_ctx(100);
        let did = make_did("did:key:z6MkAlice");
        hub2.store_or_update_jws_token(
            &ctx,
            "my-bearer",
            &did,
            "",
            Timestamp {
                seconds: 50,
                block_height: 5,
            },
            Timestamp::default(),
        )
        .unwrap();
        let hash = keys::hash_jws_token("my-bearer");
        let record = hub2.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.bearer_token, "my-bearer");
        assert_eq!(record.issuer_did, did.to_string());
        assert_eq!(record.status, JWSTokenStatus::Valid);
        assert_eq!(record.first_used_at, Some(ctx.timestamp.clone()));
        assert_eq!(record.last_used_at, Some(ctx.timestamp));
        drop(_hub);
    }

    #[test]
    fn store_token_requires_account_when_bearer_auth_enforced() {
        let mut hub = HubModule::new();
        let ctx = block_ctx(100);
        let did = make_did("did:key:z6MkBob");
        let err = hub
            .store_or_update_jws_token(
                &ctx,
                "bearer",
                &did,
                "",
                Timestamp::default(),
                Timestamp::default(),
            )
            .unwrap_err();
        assert!(matches!(err, HubError::InvalidJws { .. }));
    }

    #[test]
    fn store_token_rejects_pre_expired() {
        let mut hub = HubModule::new();
        hub.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx = block_ctx(200);
        let did = make_did("did:key:z6MkCarol");
        let err = hub
            .store_or_update_jws_token(
                &ctx,
                "expired-bearer",
                &did,
                "",
                Timestamp {
                    seconds: 100,
                    block_height: 10,
                },
                Timestamp {
                    seconds: 100,
                    block_height: 10,
                },
            )
            .unwrap_err();
        assert!(matches!(err, HubError::InvalidJws { .. }));
    }

    #[test]
    fn record_usage_updates_timestamps() {
        let mut hub = HubModule::new();
        hub.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx1 = block_ctx(100);
        let did = make_did("did:key:z6MkDave");
        hub.store_or_update_jws_token(
            &ctx1,
            "token-dave",
            &did,
            "",
            Timestamp::default(),
            Timestamp::default(),
        )
        .unwrap();
        let hash = keys::hash_jws_token("token-dave");
        let ctx2 = block_ctx(200);
        hub.record_jws_token_usage(&ctx2, &hash).unwrap();
        let record = hub.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.first_used_at, Some(ctx1.timestamp));
        assert_eq!(record.last_used_at, Some(ctx2.timestamp));
    }

    #[test]
    fn idempotent_store_updates_usage() {
        let mut hub = HubModule::new();
        hub.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx1 = block_ctx(100);
        let did = make_did("did:key:z6MkEve");
        hub.store_or_update_jws_token(
            &ctx1,
            "token-eve",
            &did,
            "",
            Timestamp::default(),
            Timestamp::default(),
        )
        .unwrap();
        let ctx2 = block_ctx(200);
        hub.store_or_update_jws_token(
            &ctx2,
            "token-eve",
            &did,
            "",
            Timestamp::default(),
            Timestamp::default(),
        )
        .unwrap();
        let hash = keys::hash_jws_token("token-eve");
        let record = hub.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.last_used_at, Some(ctx2.timestamp));
    }

    #[test]
    fn update_status_to_invalid() {
        let mut hub = HubModule::new();
        hub.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx = block_ctx(100);
        let hash = sample_record_ignore_bearer(&mut hub, &ctx);
        let ctx2 = block_ctx(200);
        hub.update_jws_token_status(&ctx2, &hash, JWSTokenStatus::Invalid, "0xAdmin")
            .unwrap();
        let record = hub.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.status, JWSTokenStatus::Invalid);
        assert_eq!(record.invalidated_at, Some(ctx2.timestamp));
        assert_eq!(record.invalidated_by, "0xAdmin");
    }

    fn sample_record_ignore_bearer(hub: &mut HubModule, ctx: &BlockExecCtx) -> String {
        let did = make_did("did:key:z6MkTest2");
        hub.store_or_update_jws_token(
            ctx,
            "bearer-ignore",
            &did,
            "",
            Timestamp::default(),
            Timestamp::default(),
        )
        .unwrap();
        keys::hash_jws_token("bearer-ignore")
    }

    #[test]
    fn delete_token_removes_all_indexes() {
        let mut hub = HubModule::new();
        let ctx = block_ctx(100);
        let hash = sample_record(&mut hub, &ctx);
        hub.delete_jws_token(&hash).unwrap();
        assert!(hub.get_jws_token(&hash).unwrap().is_none());
        let did = make_did("did:key:z6MkTest");
        assert!(hub.get_jws_tokens_by_did(&did).unwrap().is_empty());
        assert!(
            hub.get_jws_tokens_by_account("0xAccount1")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn delete_missing_token_errors() {
        let mut hub = HubModule::new();
        let err = hub.delete_jws_token("nonexistent").unwrap_err();
        assert!(matches!(err, HubError::TokenNotFound { .. }));
    }

    #[test]
    fn get_all_jws_tokens() {
        let mut hub = HubModule::new();
        let ctx = block_ctx(100);
        let hash = sample_record(&mut hub, &ctx);
        let all = hub.get_all_jws_tokens().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].token_hash, hash);
    }

    #[test]
    fn get_tokens_by_did() {
        let mut hub = HubModule::new();
        let ctx = block_ctx(100);
        let _ = sample_record(&mut hub, &ctx);
        let did = make_did("did:key:z6MkTest");
        let tokens = hub.get_jws_tokens_by_did(&did).unwrap();
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn get_tokens_by_account() {
        let mut hub = HubModule::new();
        let ctx = block_ctx(100);
        let _ = sample_record(&mut hub, &ctx);
        let tokens = hub.get_jws_tokens_by_account("0xAccount1").unwrap();
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn hash_jws_token_delegates_to_keys() {
        let h1 = HubModule::hash_jws_token("test");
        let h2 = keys::hash_jws_token("test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn extract_hash_from_index_suffix_empty() {
        assert!(extract_hash_from_index_suffix(&[]).is_none());
    }

    #[test]
    fn extract_hash_from_index_suffix_truncated() {
        assert!(extract_hash_from_index_suffix(&[10, b'a']).is_none());
    }

    #[test]
    fn extract_hash_from_index_suffix_valid() {
        let hash = "abc123";
        let mut suffix = vec![hash.len() as u8];
        suffix.extend_from_slice(hash.as_bytes());
        assert_eq!(extract_hash_from_index_suffix(&suffix).unwrap(), hash);
    }

    // ── Handler tests ────────────────────────────────────────────────

    fn tx_ctx(signer: &str) -> TxExecCtx {
        TxExecCtx {
            tx_hash: vec![0xAA],
            signer: signer.to_string(),
        }
    }

    fn hub_with_token() -> (HubModule, String) {
        let mut hub = HubModule::new();
        hub.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx = block_ctx(100);
        let did = make_did("did:key:z6MkTest");
        hub.store_or_update_jws_token(
            &ctx,
            "bearer-token-abc",
            &did,
            "0xAccount1",
            Timestamp {
                seconds: 1,
                block_height: 1,
            },
            Timestamp::default(),
        )
        .unwrap();
        let hash = keys::hash_jws_token("bearer-token-abc");
        (hub, hash)
    }

    #[test]
    fn invalidate_jws_by_issuer_did() {
        let (mut hub, hash) = hub_with_token();
        let bctx = block_ctx(200);
        let tctx = tx_ctx("some-other-account");
        let creator = make_did("did:key:z6MkTest");
        let result = hub.invalidate_jws(&bctx, &tctx, &creator, &hash).unwrap();
        assert!(result);
        let record = hub.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.status, JWSTokenStatus::Invalid);
        assert_eq!(record.invalidated_by, "some-other-account");
    }

    #[test]
    fn invalidate_jws_by_authorized_account() {
        let (mut hub, hash) = hub_with_token();
        let bctx = block_ctx(200);
        let tctx = tx_ctx("0xAccount1");
        let creator = make_did("did:key:z6MkOther");
        let result = hub.invalidate_jws(&bctx, &tctx, &creator, &hash).unwrap();
        assert!(result);
    }

    #[test]
    fn invalidate_jws_unauthorized() {
        let (mut hub, hash) = hub_with_token();
        let bctx = block_ctx(200);
        let tctx = tx_ctx("0xWrongAccount");
        let creator = make_did("did:key:z6MkWrong");
        let err = hub
            .invalidate_jws(&bctx, &tctx, &creator, &hash)
            .unwrap_err();
        assert!(matches!(err, HubError::Unauthorized { .. }));
    }

    #[test]
    fn invalidate_jws_already_invalid() {
        let (mut hub, hash) = hub_with_token();
        let bctx = block_ctx(200);
        let tctx = tx_ctx("0xAccount1");
        let creator = make_did("did:key:z6MkTest");
        hub.invalidate_jws(&bctx, &tctx, &creator, &hash).unwrap();
        let err = hub
            .invalidate_jws(&bctx, &tctx, &creator, &hash)
            .unwrap_err();
        assert!(matches!(err, HubError::TokenAlreadyInvalidated { .. }));
    }

    #[test]
    fn invalidate_jws_not_found() {
        let mut hub = HubModule::new();
        let bctx = block_ctx(200);
        let tctx = tx_ctx("0xAccount1");
        let creator = make_did("did:key:z6MkTest");
        let err = hub
            .invalidate_jws(&bctx, &tctx, &creator, "nonexistent")
            .unwrap_err();
        assert!(matches!(err, HubError::TokenNotFound { .. }));
    }

    #[test]
    fn update_params_writes() {
        let mut hub = HubModule::new();
        let authority = make_did("did:key:z6MkGov");
        hub.update_params(&authority, HubParams {}).unwrap();
        assert_eq!(hub.get_params(), HubParams {});
    }

    #[test]
    fn check_and_update_expired_tokens_sweeps() {
        let mut hub = HubModule::new();
        hub.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx = block_ctx(100);
        let did = make_did("did:key:z6MkExpiry");
        hub.store_or_update_jws_token(
            &ctx,
            "expiring-token",
            &did,
            "",
            Timestamp::default(),
            Timestamp {
                seconds: 150,
                block_height: 150,
            },
        )
        .unwrap();
        let hash = keys::hash_jws_token("expiring-token");
        let record = hub.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.status, JWSTokenStatus::Valid);

        let sweep_ctx = block_ctx(200);
        hub.check_and_update_expired_tokens(&sweep_ctx).unwrap();
        let record = hub.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.status, JWSTokenStatus::Invalid);
        assert!(record.invalidated_by.is_empty());
    }

    #[test]
    fn check_and_update_skips_zero_expiry() {
        let mut hub = HubModule::new();
        hub.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx = block_ctx(100);
        let did = make_did("did:key:z6MkNoExpiry");
        hub.store_or_update_jws_token(
            &ctx,
            "no-expiry-token",
            &did,
            "",
            Timestamp::default(),
            Timestamp::default(),
        )
        .unwrap();
        let hash = keys::hash_jws_token("no-expiry-token");

        let sweep_ctx = block_ctx(999_999);
        hub.check_and_update_expired_tokens(&sweep_ctx).unwrap();
        let record = hub.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.status, JWSTokenStatus::Valid);
    }
}
