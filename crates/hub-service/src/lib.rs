//! hub node service orchestration.
#![doc = include_str!("../README.md")]
#![doc(issue_tracker_base_url = "https://github.com/mizufinance/hub-commonware/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod runner;
pub use runner::{NodeRunContext, NodeRunner};

mod service;
pub use service::{HubNodeService, LegacyNodeService};

mod stubs;
pub use stubs::{StubAutomaton, StubBlocker, StubDigest, StubPublicKey, StubRelay, StubReporter};

mod traits;
pub use traits::{BoxFuture, NodeHandle, ServiceError};

mod transport_provider;
pub use transport_provider::TransportProvider;
