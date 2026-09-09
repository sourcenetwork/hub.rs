# Native policy reads

`HubClient::read_policy_page` returns policy records and creation metadata from
certified native state. Callers supply the trusted consensus key, a minimum
revision and a page limit. The client verifies complete-prefix evidence, decodes
each record and checks that its canonical policy ID matches its storage key.
Malformed records fail the page rather than being omitted.

Start with no cursor. Pass the returned continuation to obtain the next page;
no continuation means the selected policy prefix has ended. An empty initial
page proves that no policies existed at its selected revision. Existing proof
limits bound each page's record count and encoded bytes.

Each page includes its finalized revision and timestamp. Later pages may select
newer state, so enumeration does not provide a historical snapshot across pages.
Pass the previous revision as the next minimum to prevent moving backward.
Policy presence alone does not grant access; evaluate permissions using the
certified permission APIs.

`HubClient::read_policy` selects one policy by its 32-byte ID. It verifies the
record proof and ID binding with the same decoder used by discovery pages,
returning the policy definition and creation metadata or certified absence.
The returned revision and timestamp identify the state used for the read.

The module's `query_filter_relationships` convenience query inspects at most 128
records and 1 MiB of keys and encoded values within the selected policy prefix.
These limits apply before selector filtering. Exceeding either limit returns an
error, never a truncated result. Every inspected record must decode completely
and match its policy and relationship storage key. Larger enumerations use
`hub_getCurrentPrefixPageProof` with the policy's relationship prefix and verify
each page before applying selectors locally.

`HubClient::read_relationship_page` provides typed, verified pages for that
relationship prefix. Each record includes the relationship, archive status and
issuance metadata. Apply object, relation, subject and archive filters locally
after verification, and continue until the cursor is absent even if no records
in a page match. An empty prefix proves no relationships, not policy existence.
Pages may select newer revisions; pass the previous revision as the next minimum.
Enumeration is not a permission decision or a historical snapshot across pages.
