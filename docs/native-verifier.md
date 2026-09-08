# Native client proof verification

`vera-verifier` exposes receipt, current-record and live object-owner verification through the C
interface in `crates/vera-verifier/include/vera_verifier.h`. It calls the same
`ReceiptResponse::verify`, `RecordResponse::verify` and
`PrefixResponse::verify_object_owner` implementations as Rust
clients. Build the shared library with `cargo build -p vera-verifier`.

Each call takes UTF-8 JSON bytes, without a terminating NUL. The caller keeps
the input alive until `vera_verify` returns and releases the returned buffer
exactly once with `vera_buffer_free`. The returned length is authoritative;
the output is not NUL-terminated. Input is limited to `RECEIPT_RESPONSE_BYTES +
4096`. Receipt decoding also enforces the light-block transaction count limit.

Receipt request:

```json
{"kind":"receipt","trusted_key":"<96-byte hex key>","submission":"0x<32-byte ID>","proof":{}}
```

`proof` is the unmodified `hub_getReceiptProof` result. Success returns
`{"result":{"height":0,"timestamp":0,"submission":"0x...","success":true,"logs":[]}}`
with actual verified values. A successful verification can report an unsuccessful
operation. A missing RPC receipt is not proof of rejection.

Current-record request:

```json
{"kind":"record","trusted_key":"<96-byte hex key>","module":"acp","key":"0x<key bytes>","minimum_height":1,"proof":{}}
```

`proof` is the `hub_getCurrentRecordProof` result. Modules are `acp`, `bulletin`,
`hub` and `native_nonce`. Success returns
`{"result":{"height":0,"timestamp":0,"value":"0x..."}}`; certified absence
returns a null value. The requested module, key and minimum height are verified.
Applications must also bind record contents to their operation and apply any
required freshness policy. Inclusion alone does not authorize an operation.

Current object-owner request:

```json
{"kind":"object_owner","trusted_key":"<96-byte hex key>","policy_id":"<policy ID>","object":{"resource":"document","id":"report"},"minimum_height":1,"proof":{}}
```

`proof` is the `hub_getCurrentPrefixProof` result for
`object_owner_prefix(policy_id, object)` in the ACP module. The verifier derives
the prefix again, authenticates complete coverage and the selected revision,
and returns `{"result":{"height":0,"timestamp":0,"owner":"did:..."}}` with
verified values. Missing or archived ownership returns a null owner. Invalid
owner records or multiple live owners fail verification. This describes live
registration; it does not return an archived owner as a current registration.
Minimum height bounds the accepted revision. Callers remain responsible for any
additional freshness requirement.

Malformed or invalid evidence returns `{"error":"..."}` with no result. Only
the result returned by this interface is authenticated. Consensus trust must
come from independent provisioning, never from the response being verified.

Consumers link dynamically against `libvera_verifier` and ship the matching
library and header from the same revision. Dynamic linking keeps the library's
native crypto dependencies separate from a consumer's own copies. On macOS the
install name is `@rpath/libvera_verifier.dylib`; the consumer supplies its runtime
search path. Linux uses `libvera_verifier.so` and the platform loader search path.

The ignored `hub-e2e` test `native_go_client` runs a prebuilt Trust API test binary
from `TRUST_NATIVE_TEST_BINARY`. It checks independent Go/Rust signing and
operation commitments, concurrent provider-owned policy creation, receipt and
record verification, object registration/archive/reactivation, altered owner
evidence, and revoked relay authority after node restart. The current owner
verifier rejects changed policy/object selection, minimum revision, consensus
trust, proof roots, witnesses and revision metadata.
