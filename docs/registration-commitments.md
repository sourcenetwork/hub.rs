# Registration commitments

An actor may commit to object registrations before revealing their identifiers.
A reveal can replace an existing owner only if the commitment's revision is no
later than the existing registration's creation revision. The resulting owner
record retains the commitment's creation timestamp, so a later commitment cannot
override an earlier claim after an amendment. Its submission ID and signer identify
the reveal; the amendment event records the reveal's own execution timestamp.

Native and optional EVM execution supply this metadata through the same module
command path. Delegated commands preserve the actor as owner and the worker as
submission signer. Ownership amendment deletes the former owner's relationship
key and writes the new key, keeping permission checks and certified owner-prefix
reads consistent.

Commitments belong to one policy and expire after ten minutes by default, matching
the Go service. The end-of-revision hook marks them expired once the current time
exceeds their creation time plus the configured lifetime. Expiry maintains separate ordered indexes for time and revision deadlines. The
hook reads due entries and stops at the first future deadline in each index;
expired records remain queryable without staying in the active indexes. Indexes
are persisted in ACP state and restored with it. A batch's cost is proportional
to the commitments expiring in that batch; this is not a fixed per-revision work
limit. Index inconsistencies return an error before any records in the batch are
expired.

Successful commitment
receipts include `RegistrationsCommitted(commitmentId, policyId, commitment)` so
native callers can obtain the identifier from a certified receipt.

The registration leaf is `vera/registration-leaf/v1` followed by a zero byte and
the Borsh encoding of four strings: policy ID, resource, object ID and actor DID.
Strings use Borsh's little-endian 32-bit byte lengths and UTF-8 bytes. The leaf
hash is SHA-256 of `0x00 || leaf`; inner hashes use `0x01 || left || right`.
Odd trailing nodes are promoted unchanged. Verification checks the leaf index,
leaf count, 32-byte sibling hashes and exact number of consumed siblings.

This encoding replaces the ambiguous concatenation used by the unfinished port.
Old commitment proofs are incompatible. Deploy on fresh state or provide an
explicit migration; this change does not repair existing owner records or
zero-timestamp commitments in an older store. A migration from an earlier store
must also populate expiry indexes for every unexpired commitment.
