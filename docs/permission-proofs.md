# Verified relationship reads

`hub_getRelationProof(prefix, height)` returns every ACP relationship record under a raw prefix, with evidence for completeness at the requested finalized height. `prefix` is a hex byte string beginning with `relationship/` and ending with `/`. For example, a relation prefix has the form `relationship/<policy-id>//rel/<resource>/<object>/<relation>/`.

The response contains `version`, `count`, and `records`. Each uses the existing `ModuleStateProof` encoding. The version proof establishes the relationship-index format. The count proof establishes the number of records under the exact prefix, including archived records. Records must have distinct, ordered keys under that prefix, with an inclusion proof for each value. A missing count means zero only when the format marker is authenticated at the same revision.

Clients first verify the requested revision using `verify_light_block` and an independently configured consensus key. They then call `verify_relation_prefix_proof` with that revision's module root, height, requested prefix and local resource limits. The verifier rejects omitted, duplicated, reordered, out-of-prefix and mixed-revision records. Verified record contents still require policy evaluation; record inclusion alone does not grant access.

The endpoint currently permits at most 1,024 records, a 4,096-byte prefix and a 4 MiB serialized proof response. Oversized requests return `LIMIT_EXCEEDED` (`-32005`). There is no partial-result pagination: a truncated relation cannot establish the absence of a deny record. Clients must also bound their transport response before deserialization; the proof verifier checks limits on an already decoded response.

The server uses current module keys as enumeration candidates and proves their values at the requested retained revision. It verifies the complete response before returning it. If relation membership has changed since that revision, the server may return `RESOURCE_UNAVAILABLE` (`-32002`). It never substitutes a current scan for a historical one. Clients can select a newer verified revision and restart the entire evaluation; they must not combine revisions or treat an unavailable proof as an empty relation. Historical values remain provable when membership is unchanged.

## Index activation and recovery

Execution initializes relationship-index format 1 in the first selected revision whose parent lacks the marker. It derives counts from the resulting ACP records, so existing relationships are included. The marker and counts are authenticated ACP tree entries under the reserved null-prefixed namespace `vera/relationship_index`. Ordinary module record updates cannot write that namespace. Each later execution derives count changes from record presence before and after the update; changing or archiving a value does not change its count.

All slash-terminated relationship prefixes are counted, including delimiter ancestors. This preserves raw scan completeness even for legacy keys with extra separators. Counts and records enter the same branch-local tree update and durable revision. Pending alternatives do not change canonical counts, and revision rewind restores both together. Internal index entries are excluded from module record loading.

Activation changes consensus execution and the next module commitment. Existing deployments require a coordinated operator upgrade. No disk rewrite changes a previously finalized root; pre-activation revisions remain readable but cannot provide this complete-prefix proof. This index does not replace the underlying storage engine or supply historical key enumeration.

## Permission requests

`hub_getPermissionProof(policy, request, height)` returns the policy and relationship evidence needed to evaluate an `AccessRequest` at the requested finalized revision. The request contains an actor DID and one or more operations, each naming an object resource, object ID and permission. The response contains tagged point and complete-prefix reads. It carries no authoritative allow/deny flag.

`hub_permission::verify_permission_proof` authenticates every read against the caller's trusted module root and height, then runs the shared ACP evaluator on the caller's policy ID, actor and operations. Missing coverage remains an error, including within an exclusion. Proven policy absence returns false. Duplicate reads, mixed revisions and malformed records are rejected. Repeated reads consume the evaluation budget even when they use the same evidence.

`HubClient::verify_access_at` verifies a supplied finalized revision against an independently configured consensus key, fetches bounded evidence and evaluates it locally. It checks the HTTP response size before deserialization, including chunked responses, checks the JSON-RPC request ID, and applies a ten-second request timeout. The caller controls revision freshness. The method does not fall back to an older revision or interpret unavailable evidence as a denial or grant.

Service limits are 64 operations, 64 KiB of serialized policy ID and request, 256 evaluation reads, 4,096 returned records across those reads, 1 MiB of request-key and returned-record bytes, and 4 MiB of serialized evidence. JMT complete-prefix reads also obey the relation endpoint's limits. Client transport permits the proof limit plus 1 KiB for the RPC envelope. Clients may impose tighter limits. These read limits do not bound pure expression work or establish a sustained-throughput guarantee.

The server captures reads from one immutable current module snapshot, generates evidence at the requested revision and verifies the resulting request before returning it. Changes in membership or policy can make historical evidence unavailable. Every successful response nevertheless evaluates entirely against the requested revision. Client verification is independent of the server's capture decisions.

## Ordered Commonware evidence

The same permission endpoint supports ordered Commonware module storage when the
server is constructed with `with_hub_native_modules`. The node does not yet select
this storage path. The standalone point and relation endpoints remain JMT-based.

This format adds `roots`, the four namespace roots in ACP, bulletin, hub and
sequence order. Their combined commitment must match the caller's verified
revision. Reads use `kind: "current_point"` or `kind: "current_prefix"`, with
canonical Commonware evidence encoded as hex bytes. A point carries its key and
optional value; absence requires an exclusion proof. A prefix carries an
authenticated boundary followed by the complete ordered successor chain. A
missing successor, reordered record or substituted value invalidates the proof.
The verifier rejects mixed formats and replays the same ACP evaluator for both.
Existing JMT responses omit `roots` and retain their original encoding.

Generation holds read locks on all four namespaces and checks the selected root
before reading evidence. Prefix generation walks successors with aggregate record
and byte limits; it does not materialize a complete index bucket. The immutable
query snapshot selects candidate reads only. The server verifies the resulting
evidence before returning it, so a stale snapshot can cause unavailability but
cannot supply unauthenticated permission results.

Binary decoding bounds keys to 64 KiB, values and commit metadata to 1 MiB, Merkle
paths to Commonware's proof limit, and prefix entries to the remaining record
budget. These field limits match native storage. The full serialized response
limit is checked before binary decoding. Transport bounds still apply before JSON
deserialization. Storage may allocate an individual record before generation can
charge it; index collisions, evaluator work and concurrent-request resource use
have not been qualified by sustained-load testing.

Current-state evidence is available only when the live databases match the
requested finalized module root. A changed root returns an error instead of
substituting newer state. This path does not provide retained historical activity
proofs; operation-log history proofs cannot establish historical membership or
absence.
