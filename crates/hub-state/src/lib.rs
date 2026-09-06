//! JMT-backed module state trees with RocksDB persistence.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

/// RocksDB-backed JMT store with column families for nodes, values, preimages, and raw KV.
pub mod store;

mod snapshot;
pub use snapshot::TreeSnapshot;

/// Canonical module state and preparation of branch-local tree updates.
mod tree;
pub use tree::ModuleStateTree;

mod transfer;
pub use transfer::{ModuleRestore, SnapshotChunk};

mod checkpoint;
pub use checkpoint::{ModuleCheckpoint, PreparedCheckpoint, open_module_trees};
