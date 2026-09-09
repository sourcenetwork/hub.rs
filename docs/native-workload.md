# Native ACP workload baseline

Build optimized binaries before measuring:

```sh
cargo build --release -p hubd
cargo build --release -p hub-e2e --example operation_baseline
HUB_E2E_KEEP=1 HUBD_BINARY=target/release/hubd target/release/examples/operation_baseline 1500 25 128 1
```

`HUB_E2E_KEEP=1` preserves the printed run directories, including node logs and
state, for diagnosis. Replica reconciliation reuses one HTTP client per node
to avoid exhausting local connection ports during large runs. Replica and restart
checks process at most eight operations concurrently, reduced to the configured
per-node connection limit when lower. Every operation is still checked; these
checks run outside the measured load interval.

Arguments are operation count (1–100,000), offered arrivals per second (1–10,000),
maximum outstanding workflows (1–1,024) and permission reads per write (0 or 1).
The count ceiling bounds the runner's retained requests and observations; it is
not a node admission or throughput limit. An optional fifth argument selects `fast`,
`normal` (default) or `stress` timing. The example starts four local nodes and
records the selected preset and resolved timeouts. A sixth argument selects the
per-node RPC connection limit (default 100), independently of outstanding
workflows. Operators configure the same limit with `rpc.max_connections` in
node TOML; it must be a positive u32. A higher connection limit increases server
resource exposure and is not a throughput guarantee. The seventh argument sets
revisions per epoch (default 20); values too short for four participants are
rejected before node startup. The output records this value and the protocol's
operation-count and encoded-byte limits. An eighth argument optionally sets a
minimum revision for post-workload historical checks (default 0 disables them).
Choose a value beyond the execution cache's retained window, such as 1,100.
After timing and reconciliation, all replicas must reach it within ten minutes.
The driver compares six early revision/submission/receipt/log responses with
captured values and verifies the early receipt against the trusted consensus key.
It repeats these checks on the hard-restarted replica. This waiting and checking
is outside timing and does not extend the timed resource samples.

Use the same epoch length when comparing timing presets or implementation
changes. Short epochs exercise frequent DKG transitions. A run that finishes
inside one long epoch measures steady-state traffic and does not qualify
transition or membership-change behavior. Larger epochs also change how long
an operator-requested membership change may take to activate. It prepares independent BLS signers and
signed registrations before the timed interval; signing time and byte volume are
reported separately. This isolates node/client request handling from signing
preparation and does not model a production gateway's worker pool.

Each timed registration must obtain a receipt verified against the configured
consensus key. With permission reads enabled, it then verifies current ACP access
for the registered owner at a revision no earlier than that receipt. A certified
denial is a correctness failure. HTTP 429 on read requests is retried after
250 ms within the existing workflow deadline and counted as `read_throttles`.
`receipt_throttles` and `permission_throttles` split that total by read stage in
each observation and the summary.
Submission HTTP 429 is recorded as rejected; submissions are never retried. Any receipt or permission proof verification
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
- Per-node RSS and cumulative CPU time sampled with `ps` once per second during
  arrivals and drain. `resource_configuration` maps row PIDs to node indices;
  each `resources` record retains the raw `pid,rss,time` rows. RSS is in KiB;
  CPU time uses the platform's cumulative `ps` time format, not wall time.
- Logical data-directory bytes, allocated file bytes, and regular-file counts
  before and after timing, including node logs. These scans do not follow
  symlinks and run outside the measured interval. Storage rows retain
  `logical_bytes` and add `allocated_file_bytes` and `regular_files`.

Resource collection requires `ps`. Failed samples/scans carry an `error` field;
missing measurements are not zero usage. Validate PID coverage when analyzing
samples. One-second sampling can miss short memory peaks. Directory sizes are
live, non-atomic observations. Allocated file bytes use Unix file block counts
in 512-byte units; they exclude directory metadata and do not deduplicate hard
links or shared filesystem extents. They measure neither physical-device writes
nor write amplification. Sparse files can have logical sizes larger than their
allocated size. Process sampling runs during the workload and can perturb results.

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
long-duration memory/storage growth still need separate qualification.

## Fixed-object updates

A ninth argument selects a fixed object/signer count; zero (default) keeps the
registration workload. For example, `6000 100 128 1 normal 100 1000 0 128`
prepares 128 registered objects, then alternates archive and unarchive operations
on each. The object count must not exceed the operation count or outstanding
limit, and permission reads must be enabled. Preparation and signing occur before
timing and are reported together as `update_preparation_seconds`.

Each object has one signer and at most one active workflow. Its next scheduled
operation waits for the previous verified receipt and permission result: archive
must deny owner access and unarchive must restore it. A failed workflow aborts
the run instead of submitting later requests with sequence gaps. This mode does
not drop offered operations when a signer is busy; scheduling lag includes that
wait. Configuration records the distinct workload and arrival model. Its
throughput measures completed work through drain and is not directly comparable
to the registration mode's overload behavior.

Reconciliation and restart checks inspect every receipt and compare each object's
final active/archived state with its update count. Application objects and signer
records stay fixed in number, while sequences, revisions and retained history
continue advancing. This separates growing application cardinality from cache,
history and allocator behavior; it does not make total disk usage constant.
