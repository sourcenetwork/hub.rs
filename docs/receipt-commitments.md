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
