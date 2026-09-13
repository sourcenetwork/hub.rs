# Operating a validator

Deployment, recovery, monitoring and limits for a `hubd` validator. Protocol
behaviour is documented in the linked pages; this one covers the operational
surface.

## Deployment

A network needs one `genesis.json` shared by all nodes, one validator key and
epoch-0 BLS share per node, and a `peers.json` listing every participant's
dialable address. Two paths produce that material:

- `hubd genesis --peers peers.json` runs the distributed epoch-0 DKG across
  the participants and is the production path.
- `hubd --chain-id <id> testnet --nodes 4 --init-only ...` generates
  trusted-dealer material locally; see [wan-gates.md](wan-gates.md) for a
  worked multi-host example.

Run a node with:

```sh
hubd --config nodeN/config.toml --data-dir nodeN \
     --chain-id <id> validator --peers peers.json
```

`validator.key` and `secrets.json` in the data directory are the node's
identity: they are created owner-only and must never be regenerated for an
existing participant identity.

## Filesystem layout

| Path | Contents |
|------|----------|
| `config.toml` | Node, network, RPC, execution and pruning configuration |
| `genesis.json` | Shared deployment definition and epoch-0 key material |
| `peers.json` | Participant addresses for the authenticated network |
| `validator.key` | Ed25519 consensus identity (32 bytes, owner-only) |
| `secrets.json` | BLS shares and DKG state (owner-only, atomic writes) |
| `history/` | Durable execution and finalization records |
| `native-genesis.bin` | Published after all seven partitions first seal |

Backing up `validator.key` and `secrets.json` is sufficient to reconstitute a
participant; the remaining state re-syncs from peers.

## Recovery behaviour

- **Restart after clean stop** — startup aligns all journals to the durable
  anchor, rebuilds query indexes from durable history, then serves.
- **Restart after crash** — the same path: interrupted snapshot
  synchronization resumes from durable metadata; partially applied revisions
  rewind to the last durable anchor before execution continues.
- **Pruned peers** — a node joining late fetches a recent authenticated
  snapshot plus retained history; it does not need genesis-era data when
  pruning is configured (see [snapshot-recovery.md](snapshot-recovery.md)).
- **Disk write failures** — a failed or torn write during finalization stops
  the node before it acknowledges the revision; restart recovers to the last
  durable anchor. This is deliberate fail-stop, not a retry loop.

Do not delete `history/` or the genesis record to "reset" a node: existing
JMT directories or a missing genesis record alongside finalized history are
rejected and require an explicit migration decision, not silent reset.

## Configuration knobs operators own

- **Pruning** (`[pruning]`): `retained_consensus_revisions` bounds marshal
  archive retention; `retained_state_revisions = 0` prunes state snapshots
  aggressively. Retention must cover a complete DKG epoch. Memory retained by
  the archive window is bounded by retention divided by the section size —
  size deployments accordingly.
- **Snapshot catch-up** (`[snapshot]`): opt-in for newly admitted members;
  `record_bytes` and `peer_timeout_ms` must be positive.
- **Finality watchdog** (`watchdog_stall_seconds`, default 600, `0` disables): fails the
  process after that long without a new finalization while peers stay connected, so supervised
  restarts re-enter the boot-time rejoin that re-syncs from a current floor. It arms only after
  the first finalization, so initial synchronization is never interrupted.
- **History backend**: default RocksDB; the `regolith-history` build feature
  selects Regolith with synchronous writes. The two backends reject each
  other's directory layouts — pick one per deployment.
- **RPC exposure**: bind `http_addr` to an internal interface for validator
  operation; expose only through the intended client path. The JSON-RPC
  server enforces its own batch, subscription and body-size limits (see
  [permission-proofs.md](permission-proofs.md) for proof-path budgets).

## Monitoring

- `hub_nodeStatus` over JSON-RPC reports height, view, finalization count and
  peer count — poll it for liveness and progress alarms.
- `RUST_LOG=warn,hub_diagnostics=debug` emits a resource snapshot every 30
  seconds (runtime metrics, resident execution index, cache occupancy,
  history-backend memory counters) plus per-revision apply and publication
  times. Collection runs off the async executor and is opt-in.
- Consensus warnings (`floor not updated`, view skips) at `warn` are normal
  during epoch transitions; sustained notarization timeouts are not.

## Capacity reference

Single-host baseline (four validators, one machine, release build): sustained
certified-registration throughput in the high tens of operations per second;
certified-receipt p95 in the 1-2 s range locally; resident memory per node
in the 300-500 MiB range with pruning active and a decelerating growth curve
as caches fill. Wide-area expectations and their gate criteria are defined in
[wan-gates.md](wan-gates.md). Re-baseline with the `operation_baseline`
(local) and `wan_baseline` (remote) drivers after material changes.

## Security notes for operators

- `validator.key` and `secrets.json` are created with owner-only permissions;
  keep the data directory off shared storage.
- Peer messaging is authenticated (see `peers.json`); RPC traffic should be
  TLS-terminated or network-isolated as appropriate for the deployment.
- Certificate and proof endpoints apply fixed budgets; a client exceeding
  them receives retryable `-32002` errors and must back off, not reconnect
  harder.
