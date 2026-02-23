//! JMT-backed module state trees with RocksDB persistence.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

/// RocksDB-backed JMT store with column families for nodes, values, preimages, and raw KV.
pub mod store;

/// Module state tree with overlay-based execution isolation.
mod tree;
pub use tree::ModuleStateTree;
