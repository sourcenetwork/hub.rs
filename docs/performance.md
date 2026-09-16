# Performance measurements

Vera has two workload drivers:

- `operation_baseline`: four local members; certified native ACP writes,
  optional verified permission reads, per-member resource samples, replica
  reconciliation, and hard-restart checks. Growing registrations and repeated
  updates to a fixed object set exercise different memory behavior.
- `wan_baseline`: externally provisioned members, with explicit network and
  deployment settings. See [WAN gates](wan-gates.md).

The [Performance workflow](../.github/workflows/performance.yml) runs after a
successful main-branch CI push, or through manual dispatch. It builds release
binaries before measurement and runs RocksDB and Regolith history on separate
hosted runners. Each backend measures 3,000 operations at 50 offered arrivals/s,
first with growing registrations and then with 128 repeatedly updated objects.
These are fixed-load baselines, not searches for maximum throughput. They are
not part of every pull request's test loop.

Each artifact includes:

- Checkout revision, binary hashes, platform, CPU count, memory, runner image,
  load averages, backend selection, exact arguments, and process exit status.
- Raw versioned JSONL observations, including rejection, uncertainty, throttling,
  and incomplete workflows.
- A machine-readable report, Markdown summary, and SVG/PNG plots of certified
  receipt latency distribution and member RSS over the measured interval.
- Replica reconciliation and hard-restart results. Missing results or correctness
  failures fail report generation or mark the run failed, never successful.

Only measurement files are uploaded. Member data directories, identities, and
secret stores are outside the artifact directory. Artifacts retain 30 days of
results; no performance site is published by this workflow.

## Measured local results

Release builds with bounded parallel native verification produced these results
on an Apple M5 Max host (18 logical CPUs, 64 GiB RAM). Each run used four local
validators, QMDB state, RocksDB history, and growing ACP object registrations
with certified receipt verification. Permission reads were disabled. Signing
happened before timing.

| Preset | Offered writes/s | Operations | Completed writes/s | Median confirmation | p95 confirmation | p99 confirmation |
|---|---:|---:|---:|---:|---:|---:|
| Normal | 200 | 6,000 | 194.04 | 729 ms | 1,588 ms | 2,001 ms |
| Fast | 200 | 6,000 | 195.88 | 783 ms | 1,975 ms | 2,390 ms |

Every offered operation completed. All four replicas agreed, and receipt/state
checks passed after a member was forcibly restarted. Neither run had uncertain,
rejected, reverted or unverifiable outcomes. Bounded submission and receipt-read
retries handled admission throttling.

For comparison, the earlier sequential-verification revision
`c1f9cff9ac399757684b5dc539252934241278fa` passed these Normal-preset runs on the
same host:

| Offered writes/s | Operations | Completed writes/s | Median confirmation | p95 confirmation | p99 confirmation |
|---:|---:|---:|---:|---:|---:|
| 20 | 600 | 19.65 | 625 ms | 1,316 ms | 1,566 ms |
| 100 | 3,000 | 96.58 | 671 ms | 1,351 ms | 1,645 ms |
| 200 | 6,000 | 196.66 | 775 ms | 1,682 ms | 2,176 ms |

These are individual 30-second offered-load measurements, followed by draining
outstanding work. Completed writes/s includes that drain interval. They establish
a passing local load point, not maximum or sustained capacity, or a statistically
established throughput improvement. Normal had lower tail latency than Fast in
the new runs. Confirmation includes admission, execution, consensus, polling and
proof verification; these measurements do not establish 300 ms consensus
finality. WAN deployment and write-plus-permission workflows require separate
qualification.

The new workload arguments were:

```text
6000 200 1024 0 normal 100 20 0 0 32
6000 200 1024 0 fast 100 20 0 0 32
```

All runs used 50 ms receipt polling, a 30-second workflow deadline, 20 revisions
per epoch, and retention of 32 consensus revisions. The earlier 20/s and 100/s
runs used an outstanding-workflow limit of 256.

Before parallel verification, a Fast diagnostic at 100 offered writes/s stalled
at height 20: repeated 256-operation proposals took approximately 294–298 ms to
execute, exceeding its 100 ms leader and 200 ms notarization deadlines. A focused
follow-up measured median authentication around 590 microseconds per operation,
versus 8 microseconds for dispatch. These diagnostic runs used extra logging;
they are not throughput baselines. Parallel verification retains the original
Fast timeouts. Its passing short run does not qualify prolonged overload,
all epoch-transition failure scenarios, or WAN operation.

## Run locally

Build both executables from the same checkout and record any dirty changes:

```sh
cargo +1.98.0 build --frozen --release -p verad
cargo +1.98.0 build --frozen --release -p vera-e2e --example operation_baseline
python3 tools/performance/record.py \
  --node target/release/verad \
  --runner target/release/examples/operation_baseline \
  --history rocksdb --output /tmp/vera-performance-run \
  3000 50 128 1 normal 100 20 0 128 32
python3 -m venv /tmp/vera-performance-python
/tmp/vera-performance-python/bin/pip install -r tools/performance/requirements.txt
/tmp/vera-performance-python/bin/python tools/performance/report.py /tmp/vera-performance-run
```

The output directory must not already exist. For Regolith, build `verad` with
`--features regolith-history` and label that exact executable `--history regolith`.
The recorder hashes binaries but cannot infer their source revision or features;
its source field describes the checkout. The workflow binds that checkout to its
own build steps. Do not label an older prebuilt executable with a new checkout.

Each local run has a 15-minute process deadline; timeout terminates its process
group and remains a failed measurement. Compilation, report rendering, and
post-run correctness checks do not contribute to the driver's measured workload
interval. See [workload semantics and arguments](native-workload.md).

For diagnosis, pass `--rust-log warn,vera_storage=info,vera_diagnostics=debug`.
The `native execution stages` event separates block-wide signature authentication
from ordered native dispatch. Nodes share one Commonware verification pool across
executor clones, capped at four workers (or the available CPU count if smaller).
Every signature is still verified independently; nonce checks, module mutations,
receipts and error selection retain their original transaction order.
The recorder stores the selected filter in the manifest. Additional logging can
affect throughput and latency; treat diagnostic runs separately from baselines.

## Interpret the charts

Receipt latency runs from scheduled arrival through verified confirmation. It
includes scheduling delay, admission, execution, consensus, polling, and proof
verification. It is **not** consensus finality latency. Workflow latency includes
any configured permission read after confirmation. Throughput counts completed
workflows over the driver's measured arrivals-and-drain interval.

The Rust client limits each instance to 64 concurrent HTTP calls, including
response decoding. `with_max_concurrent_requests` changes this bound. Calls
over the limit return `ResourceBusy` before transmission; the workload counts
these alongside server throttles and retries within its existing deadline.
The outstanding-workflow limit is separate from this transport bound.

RSS is sampled once per second. Missing samples are counted, not filled with
zero; short peaks may be missed. A short fixed-state run cannot establish a
memory plateau, and growing state has a different working set. Plots contain
measured data only and show failed-run status explicitly.

Hosted runner hardware and contention vary. Compare matching workload settings,
backends, toolchains, and host classes; repeat runs before drawing conclusions.
Load averages are context, not proof of exclusive CPU or storage access. There
is no automatic percentage-regression gate on these shared hosts.

## Live visualization

A live view and a benchmark report answer different questions. The native RPC
already exposes member status and finalized-header subscriptions. Those can show
actual revision progress and connectivity. A client must verify finality evidence
against operator-provisioned trust before presenting authenticated results.

Browser-observed latency also needs an explicit clock-skew policy. Receipt
latency, revision interval, and client-observed finalization must remain separate
series. Unknown or disconnected members must show stale/missing data rather than
continued simulated activity. Gateway and Orbis workflow latency are additional
measurements; they cannot be inferred from a consensus header stream.

There is currently no deployed live Vera dashboard or qualified WAN capacity
result. The reports here provide reproducible evidence for that work without
claiming current release throughput from historical runs.
