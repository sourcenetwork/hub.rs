# Token lifecycle

Token records remain queryable after invalidation. An ordered index contains only
tokens with an expiry and a status other than invalid. Its key is `0x04`, followed
by the expiry time as a big-endian 64-bit integer and the token hash's UTF-8 bytes;
its value is empty. The primary record and existing issuer/account indexes retain
their formats.

Every token write updates the expiry index. Usage updates retain one entry;
revocation removes it. The end-of-revision sweep visits due entries and stops at
the first deadline greater than or equal to the execution time. A token remains
valid at its exact deadline. A zero timestamp means no expiry and has no index
entry. Automatic invalidation records its execution timestamp; later sweeps do
not overwrite an operator's invalidation metadata.

The sweep validates due entries before updating records. Missing records, malformed
bytes, mismatched token hashes or inconsistent deadlines fail execution. Ordinary
record reads also validate the stored token hash against the requested key.
Proposal-local failures cannot publish partially updated module state.

Indexes persist with Hub state and recover with its snapshots. Existing stores
require an explicit migration that builds indexes for active, expiring tokens;
startup does not automatically migrate them. This change removes scans of token
history from each revision. It does not cap retained history or the number of
tokens that can expire at the same instant.

Token collection queries inspect at most 128 records and 1 MiB of combined
index, primary-key and record bytes. Larger results return errors instead of
partial lists. Use certified native prefix pages for larger collections.
Malformed index suffixes, unexpected index values, missing records and mismatched
record identities are errors. Account selectors must contain 1–255 bytes; DID
selectors are also capped at 255 bytes. Token writes validate every index
component before changing state, avoiding key-encoder panics and partial writes.

`HubClient::read_token_record` returns lifecycle metadata or certified absence
for a SHA-256 token hash at a caller-selected minimum revision. It verifies the
certificate, record key and stored token-content hash before returning the record.
After invalidation, read at or after the certified invalidation revision to check
the status, invalidating identity and execution timestamp.

This read does not evaluate signature claims, expiry, delegation scope, provider
grants or the separate revocation records for unused delegations. Neither record
presence nor absence proves that a token can authorize a new operation.
