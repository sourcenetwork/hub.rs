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
exceeds their creation time plus the configured lifetime. Reveals independently
check that deadline at execution, so a time jump cannot make an expired commitment
usable before the cleanup hook. The deadline itself remains inclusive. Expiry maintains separate ordered indexes for time and revision deadlines. The
hook reads due entries and stops at the first future deadline in each index;
expired records remain queryable without staying in the active indexes. Indexes
are persisted in ACP state and restored with it. A batch's cost is proportional
to the commitments expiring in that batch; this is not a fixed per-revision work
limit. Index inconsistencies return an error before any records in the batch are
expired.

Successful commitment
receipts include `RegistrationsCommitted(commitmentId, policyId, commitment)` so
native callers can obtain the identifier from a certified receipt.

Commitment generation accepts 1–256 objects and at most 64 KiB of aggregate
encoded leaf bytes, counting the repeated policy and actor strings for each leaf.
It checks these limits before state lookups and proof allocation. Larger sets
must be split into separate commitments. These limits bound this generator's
work; they do not limit the size of a proof supplied for an independently built
commitment beyond the verifier's existing proof-shape checks.

Owner queries inspect at most two records. Missing ownership returns unregistered;
malformed, duplicate or mismatched ownership records return an error. Unarchive
uses the same validation, including actor, policy, object and storage-key binding.
Archived ownership remains reserved for its previous owner.

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

## Commitment discovery

Each commitment has a root index entry using
`commitment/indexes/commitment/idx/ || root[32] || / || id_be[8]` with an empty value.
The entry remains after expiry. It is maintained with the primary record and
included in ACP snapshots. Older stores require explicit index population.

`HubClient::read_registration_commitment_ids` uses the existing certified native
prefix-page endpoint. Supply the root, optional continuation, a limit from 1 to
128, a minimum revision and trusted consensus key. The result contains verified
IDs in ascending order, its revision and an inclusive continuation for the next
page. A missing root returns a certified empty page. Later pages can select newer
state; the cursor does not pin a historical snapshot.

Read a discovered primary record with `read_current_record`, module `Acp` and
`acp::keys::commitment_key(id)`, using at least the page's revision. Such a read
may select newer state, including a changed expiry flag. The index authenticates
the root-to-ID association, not the primary record's mutable metadata.

The legacy by-value query uses the same index and returns complete results only
when they fit within 128 records and 1 MiB of stored record bytes. Larger results
return an explicit error directing callers to certified pages; they are never
silently truncated. Indexed record corruption is an error rather than absence.

`HubClient::read_registration_commitment` returns a typed record or certified
absence using caller-provided consensus trust and a minimum revision. The client
checks the requested policy, commitment identifier, root width and complete record
encoding. It preserves issuance metadata and expiry status; record presence is
not a guarantee that a later reveal will succeed.
