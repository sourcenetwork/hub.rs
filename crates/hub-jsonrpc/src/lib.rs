//! JSON-RPC server for hub nodes.

#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod config;
pub use config::{CorsConfig, RateLimitConfig, RpcServerConfig};

mod error;
pub use error::{RpcError, codes as error_codes};

mod eth;
pub use eth::{
    EthApiImpl, EthApiServer, FeeHistory, NetApiImpl, NetApiServer, TxSubmitCallback, Web3ApiImpl,
    Web3ApiServer,
};

mod eth_subscribe;
pub use eth_subscribe::{EthSubscriptionApiImpl, EthSubscriptionApiServer};

mod hub_api;
pub use hub_api::{HubApiImpl, HubApiServer};

mod server;
pub use server::{JsonRpcServer, RpcServer, RpcServerHandle, ServerError};

mod state;
pub use state::{NodeState, NodeStatus};

mod state_provider;
pub use state_provider::{NoopStateProvider, StateProvider};

mod indexed_provider;
pub use indexed_provider::IndexedStateProvider;

mod types;
pub use types::{
    AddressFilter, BlockNumberOrTag, BlockTag, BlockTransactions, CallRequest, RpcBlock, RpcLog,
    RpcLogFilter, RpcNativeReceipt, RpcTransaction, RpcTransactionReceipt, SyncInfo, SyncStatus,
    TopicFilter,
};
