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
