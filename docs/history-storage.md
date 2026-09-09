# Finalized history storage

Commonware stores authenticated current state, pending forks, and consensus
archives. Finalized execution history is a separate database containing records,
certificates, query indexes and snapshot-import progress. Its backend does not
change the revision commitments or proof format.

Normal builds use RocksDB in the node's `history` directory. The opt-in
`regolith-history` build uses Regolith in `history/regolith`:

```sh
cargo build --frozen -p hubd --features regolith-history
```

Regolith is pinned to the revision used by DefraDB. History writes explicitly
request synchronous WAL persistence; they do not use Regolith's default eventual
durability. Execution, certificate and query-index updates share one batch.
Snapshots pin consistent reads and borrowed record values. Cursor reads check
status separately from exhaustion so errors cannot appear as empty history.
Recovery batches retain the existing flush threshold, using a running payload
estimate for the Regolith batch.

Each build rejects the other backend's history layout before initializing its
own store. There is no automatic on-disk conversion. Keep an existing node on its
original backend, or use a separate node directory and authenticated snapshot
recovery to obtain history with the selected backend. Copying storage files
between the two layouts is not a migration.

The Regolith feature is for qualification. Backend selection does not establish
throughput, memory bounds, or power-loss durability. Its `memtables` diagnostic
reports the engine's current memtable-size counter; it is not directly comparable
to RocksDB's allocation accounting. Unsupported `table_readers` accounting remains
absent, and block-cache usage is reported separately.

To exercise authenticated snapshot import from pruned peers with Regolith,
build the feature above, then point the harness at that binary:

```sh
HUBD_BINARY="$PWD/target/debug/hubd" RUST_LOG=warn,hub_storage=info \
  cargo test --frozen -p hub-e2e --test snapshot_catchup \
  snapshot_replica_recovers_from_pruned_peers -- --exact
```

This case checks historical receipts and proofs, restored revocation state,
restart, and subsequent writes requiring the recovered member's participation.
The prepared Linux CI workflow runs it after building the Regolith node.
