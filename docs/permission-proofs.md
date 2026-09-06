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
