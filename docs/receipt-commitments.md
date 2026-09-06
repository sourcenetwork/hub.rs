# Execution receipt commitments

Native revisions include `Block::receipt_commitment`, a Keccak-256 commitment to
the ordered execution receipts and execution gas limit. Proposal verification
re-executes the operations and requires the same commitment. Missing commitments
are rejected by the native application and native checkpoint verifier.

`hub_executor::receipt_commitment` computes the commitment without constructing
an intermediate receipt buffer. Its input encoding is:

| Field | Encoding |
|---|---|
| Domain | Literal bytes `vera/receipts/v1` |
| Execution gas limit | Big-endian u64 |
| Receipt count | Big-endian u64 |
| Each receipt | Fields below, in execution order |

Each receipt contributes:

| Field | Encoding |
|---|---|
| Operation hash | 32 bytes |
| Gas used | Big-endian u64 |
| Cumulative gas used | Big-endian u64 |
| Success | One byte, 0 or 1 |
| Contract address presence | One byte, 0 or 1 |
| Contract address | 20 bytes, only when present |
| Log count | Big-endian u64 |
| Each log | Address (20 bytes), topic count (big-endian u64), ordered topics (32 bytes each), data length (big-endian u64), data bytes |

The commitment binds ordering, collection boundaries and every field retained by
the finalized execution history. The canonical revision digest binds it to the
operations, parent and resulting state. A certificate authenticating that digest
therefore also authenticates the receipt commitment. Verifying downloaded
receipts requires recomputing the commitment against an independently verified
revision; existing receipt RPC responses do not perform that verification.

History checks the commitment before appending a record and again before
publishing that record to query indexes during recovery. A changed receipt or
execution limit fails recovery. Record decoding also checks receipt count and
rejects malformed or trailing log bytes. These checks do not provide a bounded
peer history transport; snapshot startup remains disabled.

## Staging retained history

`FinalizedHistory::record_chunk` copies at most 64 KiB from a pinned RocksDB
snapshot into a response and reports the full record length and offset. The
caller must bound record assembly before allocating for the advertised length.
This API does not register a network endpoint. Pinned reads avoid copying the
entire stored value into a Rust buffer; RocksDB's own resource use still applies.

`begin_import` verifies the selected revision against the caller's independent
consensus key and persists that selection. Records arrive in descending height
order. `import_record` checks each canonical revision against the expected parent
hash, verifies its receipt commitment and requires the chain to connect to the
destination's committed prefix. `HistoryLimits` bounds assembled bytes and the
aggregate log count before decoding their fields. Operation counts obey the
existing revision codec bounds. Limits are caller-selected; no default import
workload or capacity is implied.

Each accepted record and the next expected ancestor are persisted in one synced
write batch. `import_anchor` and `import_next` expose restart progress. Replayed,
out-of-order, incomplete and altered records fail without advancing that cursor.
The final record advances the durable history head, but the import marker still
blocks normal appends, chunk serving and light-client proof serving.

The caller must keep admission and query publication stopped, recover application
state at the selected revision, and call `recover` with that same anchor. Recovery
rejects unfinished imports and other anchors before indexing records. Its final
durable batch removes the marker. This is the history-side handoff; the running
node does not yet start snapshot import or transfer peer certificate material.

Starting an import upgrades the history metadata format to 2 in the same batch
as the import marker. Older binaries reject that format rather than treating an
unfinished import as an execution suffix to discard. Record bytes remain
unchanged, and this implementation also opens format 1 histories.

## Canonical encoding and existing data

Commitment tag 3 encodes the optional DKG payload, optional four native storage
targets, 32-byte receipt commitment and existing execution storage targets.
Tags 0, 1 and 2 preserve their previous bytes and remain decodable. Tag 3 adds
33 bytes to a revision that already has native targets. Unknown tags and
truncated encodings are rejected.

Fresh native genesis uses the empty receipt list with gas limit zero because
genesis has no executed operations. Native startup rejects a persisted genesis
from before receipt commitments and preserves its files. There is no automatic
conversion of existing native history; these data require an explicit migration.
Legacy library execution and history can still read revisions without native
targets or receipt commitments, but those receipts have no authenticated
commitment.
