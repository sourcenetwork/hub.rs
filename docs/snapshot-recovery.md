# Snapshot recovery

An admitted member can request initial snapshot catch-up by adding this section
to its node configuration. Genesis, the member's identity and its bootstrap peer
configuration must already be provisioned.

```toml
[snapshot]
record_bytes = 67108864
logs = 100000
peer_timeout_ms = 10000
```

An empty `[snapshot]` section selects these defaults. Without the section, a
node replays retained history. Interrupted snapshot synchronization always
resumes from durable metadata, even if the section is removed. Once snapshot
synchronization completes, subsequent starts recover from its persisted floor
and later consensus progress; they do not request another snapshot.

## Startup sequence

1. The DKG probe authenticates a synchronization floor against the provisioned
   consensus identity. Commonware synchronizes the seven storage partitions and
   may advance the selected revision as finalizations arrive.
2. After storage verifies the final selected roots, its handoff imports history
   through that exact revision. Every record must match the selected ancestry,
   receipt commitment and independently verified finality evidence. A record and
   its resume cursor enter one synced write batch.
3. History recovery rebuilds query indexes at the selected revision. The handoff
   then permits native query-state hydration and returns storage to the processor.
   Commonware makes any pending execution suffix durable and records completion
   before exposing the databases. Admission and RPC start after this handoff.

An interrupted history import retains its selection, trust and cursor. If storage
resumes at a later verified revision, history starts a new descending pass from
that revision to the same previously committed prefix. This can refetch already
staged records. Unpublished imports remain unavailable to history clients.

`hub_nodeStatus` includes `snapshotRevision` after snapshot recovery. On restart,
it reports the persisted snapshot recovery floor, which can also cover execution
completed during the original handoff. It is operational status; clients still
verify revision certificates and permission evidence independently.

## Transfer bounds

`record_bytes` bounds each assembled execution record, and `logs` bounds its
decoded log count. `peer_timeout_ms` applies to one record or finality response
from one peer. After failure, the importer tries another eligible peer and keeps
using a successful peer. If all candidates fail, startup fails with its durable
progress retained. Synchronous verification and storage work can outlast the
asynchronous deadline.

Finality proofs retain their shared limits: 64 descendants, 35 MiB of decoded
artifacts, and 70 MiB plus 64 KiB for the JSON response. Peer responses contain at
most 64 KiB of data per chunk. These are transfer and decoding bounds; extra
buffers, caches and storage resources contribute to process memory. Aggregate
serving capacity and sustained catch-up throughput still require qualification.

## Private DKG material

Secret-store updates write a complete temporary file, sync its contents, replace
the destination atomically and sync the containing directory. Cloned store handles
serialize updates and publish in-memory changes after persistence succeeds. On
Unix, replacement files have mode `0600`. Debug output excludes private material.
Loading validates encoded shares, seeds and dealings before making them available.
Malformed material or dealing keys stop startup without rewriting the file; they
are not treated as missing shares. Only a missing file starts an empty store.
The JSON file remains plaintext under the operating system's access controls.

An existing malformed or empty secret file fails startup and is preserved.
Recovery requires valid retained private material; the node does not silently
replace lost shares. Process-crash checks do not establish power-loss, failed-fsync
or disk-full guarantees for the deployment filesystem.
