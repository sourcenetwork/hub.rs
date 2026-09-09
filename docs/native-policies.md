# Native policy discovery

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
