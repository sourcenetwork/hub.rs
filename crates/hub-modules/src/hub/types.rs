#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use crate::types::Timestamp;

/// Status of a JWS token in the invalidation registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JWSTokenStatus {
    Unspecified = 0,
    Valid = 1,
    Invalid = 2,
}

/// A stored JWS token record tracking lifecycle and usage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWSTokenRecord {
    pub token_hash: String,
    pub bearer_token: String,
    pub issuer_did: String,
    pub authorized_account: String,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub status: JWSTokenStatus,
    pub first_used_at: Option<Timestamp>,
    pub last_used_at: Option<Timestamp>,
    pub invalidated_at: Option<Timestamp>,
    pub invalidated_by: String,
}

/// Write-once chain configuration (set at genesis).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainConfig {
    pub allow_zero_fee_txs: bool,
    pub ignore_bearer_auth: bool,
}

/// Native BLS transaction operations for the Hub module.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HubOp {
    InvalidateJWS { token_hash: String },
}

/// Module-level parameters (governance-controlled).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HubParams {}
