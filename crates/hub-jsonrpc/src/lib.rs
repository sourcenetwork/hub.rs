//! JSON-RPC server for hub nodes.

#![doc(issue_tracker_base_url = "https://github.com/sourcenetwork/hub.rs/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod archive;
pub use archive::{ArchiveReader, IndexLookup};

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

mod header_subscribe;

mod hub_api;
pub use hub_api::{HubApiImpl, HubApiServer, LightBlockLookup, ReceiptProofLookup};

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

#[cfg(test)]
mod transport_tests;
