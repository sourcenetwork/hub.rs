# Native ACP workload baseline

Build optimized binaries before measuring:

```sh
cargo build --release -p hubd
cargo build --release -p hub-e2e --example operation_baseline
HUBD_BINARY=target/release/hubd target/release/examples/operation_baseline 1500 25 128 1
```

Arguments are operation count, offered arrivals per second, maximum outstanding
workflows and permission reads per write (0 or 1). An optional fifth argument selects `fast`,
`normal` (default) or `stress` timing. The example starts four local nodes and
records the selected preset and resolved timeouts. It prepares independent BLS signers and
signed registrations before the timed interval; signing time and byte volume are
reported separately. This isolates node/client request handling from signing
preparation and does not model a production gateway's worker pool.

Each timed registration must obtain a receipt verified against the configured
consensus key. With permission reads enabled, it then verifies current ACP access
for the registered owner at a revision no earlier than that receipt. A certified
denial is a correctness failure. Any receipt or permission proof verification
failure also fails the run, even if later replica checks agree. On a receipt
verification failure, the driver records a separately fetched proof and its
verification result for diagnosis; this does not replace the failed observation. Read errors or deadlines remain visible as
confirmed writes with incomplete workflows.

JSONL format version 2 reports:

- Offered, confirmed, reverted, rejected, unknown and locally unsent operations.
- Certified write-confirmation latency and complete-workflow latency from the
  scheduled arrival, including scheduler lag.
- Permission-read latency and completed-workflow throughput.
- Preparation time, request bytes, concurrency limit and receipt polling interval.
- Post-run replica consistency and restart receipt/state comparisons.

Arrivals follow their schedule even under overload. When the outstanding limit
is reached, the operation is recorded as unsent rather than delaying its arrival.
Throughput uses the entire interval through completion of the last task, including
drain time. The 50 ms polling interval contributes to observed confirmation
latency. Version 1 used unverified receipt responses and is not directly comparable.

The replica/restart checks run after timing. They compare receipt identity/status
and object ownership; they do not replace general fault or historical-state
qualification. The driver reports whether it was compiled with debug assertions;
record the node binary hash, build profile, machine, commands and raw output with
any measurement. A local baseline is not a regional deployment SLA or a maximum
capacity claim. Sustained mixed workloads, gateway signing/queueing, overload and
memory/storage growth still need separate qualification.
