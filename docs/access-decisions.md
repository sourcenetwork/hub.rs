# Access decisions

A successful access check persists an `AccessDecision`; denied or empty requests do
not produce a grant. The submitting identity may differ from the actor whose
permissions are evaluated.

`DecisionRequest` identifies the deployment, policy, submitting identity, its
authenticated operation sequence, and the actor's ordered operations. The identifier
is SHA-256 of `vera/access-decision/v1\0` followed by the Borsh encoding of that
request. String and vector lengths preserve field boundaries. Requests are limited to 64
operations and 64 KiB of Borsh data; consumers reject records above 128 KiB. A later submission
uses a different sequence and cannot replace an earlier decision under its key.

Issuance time and revision come from finalized execution context. Decision expiry
is measured in revisions: a decision issued at H with delta D is valid only while
`H <= current_height < H + D`. Overflow and zero lifetimes are rejected. The current
issuance defaults remain 100 revisions for decisions and tickets, and 50 for proofs;
these are not wall-clock latency guarantees. Ticket and proof workflows require
their own lifecycle checks.

Consumers must authenticate the stored bytes at a fresh finalized revision and use
`DecisionRequest::verify_record` to check the exact expected request, creator,
sequence, issuance metadata and expiry. Record presence alone is insufficient. A
decision proves successful evaluation at issuance; it does not prove that permission
remains granted after subsequent policy changes or authorize an unrelated payload.

The stored Borsh field layout is unchanged. Historical records remain readable, but
legacy identifiers and zero issuance placeholders do not pass the new verification
rules. Operators must coordinate the execution update and consumer dependency pins;
new and old decision producers derive different identifiers.

`HubClient::read_access_decision` combines the certified native record read with
`DecisionRequest::verify_record`. Supply the exact expected deployment, policy,
creator, submission sequence, actor and ordered operations, plus independent
consensus trust and a minimum revision. The result includes the selected revision
and timestamp, with either a valid decision or certified absence. Invalid or
expired records return errors. Callers still enforce freshness appropriate to
usage; this method does not prove that an earlier permission remains granted.
