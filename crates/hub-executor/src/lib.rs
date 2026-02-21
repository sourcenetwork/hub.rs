//! Block execution abstractions, REVM implementation, and hub precompiles.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod adapter;
pub use adapter::StateDbAdapter;

mod config;
pub use config::{BaseFeeParams, ExecutionConfig, GasLimitBounds};

mod context;
pub use context::{BlockContext, ParentBlock};

mod error;
pub use error::ExecutionError;

mod outcome;
pub use outcome::{ExecutionOutcome, ExecutionReceipt};

mod revm;
pub use revm::{
    RevmExecutor, build_receipt, calculate_base_fee, convert_access_list,
    convert_authorization_list, convert_tx_kind, decode_evm_tx, decode_tx_env, extract_changes,
};

mod traits;
pub use traits::BlockExecutor;

mod validation;
pub use validation::{
    ACCESS_LIST_ADDRESS_GAS, ACCESS_LIST_STORAGE_KEY_GAS, MAX_BLOBS_PER_TX, TX_BASE_GAS,
    TX_CREATE_GAS, TX_DATA_NON_ZERO_GAS, TX_DATA_ZERO_GAS, TxValidator, ValidatedTx,
};

mod executor;
pub use executor::HubExecutor;

pub mod precompiles;
