# Finality proofs

`hub_getLightBlock(height)` returns the requested revision with evidence that
it is finalized. Verify it with `hub_domain::verify_light_block` and the
consensus public key from authenticated deployment configuration.

A revision can finalize through a descendant without receiving its own direct
certificate. The response then includes `descendants`: canonical encoded
blocks in ascending height order, starting immediately after the requested
revision and ending at the certified block. The `finalization` and
`epoch_material` fields describe that last block. When the requested revision
has a direct certificate, `descendants` is omitted.

All displayed fields, including `height`, `epoch`, `timestamp` and state roots,
describe the requested revision. Verification checks those fields against its
canonical bytes, follows contiguous heights and parent hashes, and verifies
the final descendant's threshold certificate against the configured key. It
returns the requested revision's roots. A newer descendant does not refresh
the requested revision's timestamp or change which state a record proof must
authenticate.

The node serves direct certificates from its existing index. It assembles
indirect proofs from one snapshot of its durable finalized history, using
the first retained direct certificate within the proof limits, and
does not copy canonical history into an additional memory index. History
reads run outside the asynchronous RPC worker. Missing history, inconsistent
ancestry, unavailable epoch material and excessive proofs return errors.

The shared limits are 64 descendants and 8 MiB of combined decoded block,
certificate and epoch-material bytes. The JSON response limit is 16 MiB plus
64 KiB for hex encoding and metadata. These are per-proof limits; they do not
establish aggregate server memory or sustainable serving capacity.

Direct proof responses retain their existing JSON shape. Consumers must use
the updated shared verifier to accept descendant proofs. Historical record
and permission evidence remains subject to its own retention and freshness
rules; a retained finality proof does not imply that all state at that revision
is still queryable.
