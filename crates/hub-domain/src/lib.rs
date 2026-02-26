//! Core domain types used across hub nodes.
#![doc = include_str!("../README.md")]
#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/hub.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod aliases;
pub use aliases::{ConsensusContext, ConsensusDigest, FinalizationEvent, PublicKey};

mod commitment;
pub use commitment::{AccountChange, StateChanges, StateChangesCfg};

mod events;
pub use events::{LedgerEvent, LedgerEvents};

mod bootstrap;
pub use bootstrap::{BootstrapConfig, BootstrapError};

mod block;
pub use block::{Block, BlockCfg};

mod idents;
pub use idents::{BlockId, Idents, StateRoot, TxId};

mod native_tx;
pub use native_tx::{NATIVE_TX_TYPE, NativeTx, NativeTxPayload};

mod gossip;
pub use gossip::{GOSSIP_HEADER_SIZE, GossipHeader};

mod tx;
pub use tx::{Tx, TxCfg};

#[cfg(feature = "evm")]
pub mod evm;
