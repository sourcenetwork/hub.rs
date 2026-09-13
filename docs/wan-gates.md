# Wide-area release gates

Multi-region validation of a deployed validator set: sustained throughput,
certified-receipt latency, verified-read latency and cross-region consistency
under real network distance. The local baselines (same binary, one host) are
recorded in the release notes; these gates measure the same workload across
regions.

## Deployment layout

Four validator nodes, one per region (minimum viable BFT set). Recommended
regions pair ~50-150 ms RTT between peers, e.g. `eu-west / eu-central /
us-east / ap-southeast`.

Per host: 4 vCPU, 8 GiB RAM, 100 GiB SSD, ports open for the p2p listener and
the JSON-RPC port of that node's `config.toml`.

## Bringing the network up

1. On any machine, generate the deployment once and distribute it:

   ```sh
   hubd --chain-id <id> testnet --nodes 4 --seed <seed> \
        --base-p2p-port 31000 --base-rpc-port 8545 \
        --data-dir ./deployment --init-only
   ```

   This writes `node0..3/` (validator key, BLS share, `config.toml`,
   `genesis.json`) and a shared `peers.json`.

2. Edit each `nodeN/config.toml`: set `dialable_addr` to that host's public
   `ip:p2p_port`. Copy `peers.json` and `nodeN/` to host N; every host must
   use the same `peers.json`.

3. Start each node:

   ```sh
   hubd --config nodeN/config.toml --data-dir nodeN \
        --chain-id <id> validator --peers peers.json
   ```

4. Confirm each node reports healthy status:

   ```sh
   curl -s <host>:<rpc_port> -X POST -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"hub_nodeStatus"}'
   ```

Production deployments replace step 1 with `hubd genesis --peers peers.json`
(the distributed epoch-0 DKG) instead of the trusted-dealer testnet generator.

## Driving the gate

Run the driver from a fifth vantage point (or one of the regions, excluding
its own RPC) so submission latency crosses the WAN:

```sh
cargo build --release -p hub-e2e --example wan_baseline
./target/release/examples/wan_baseline \
    http://<region-a-rpc>:<port> \
    node0/genesis.json \
    30000 20 128 1 <chain-id> \
    http://<region-b-rpc>:<port>,http://<region-c-rpc>:<port>,http://<region-d-rpc>:<port>
```

Arguments: primary RPC, genesis file (the epoch-0 group key is derived from
it; a raw hex key also works), operation count, arrivals/second, max
outstanding, permission reads on/off, chain id, and the remaining RPC URLs for
the closing cross-region consistency check. The driver emits one JSON line per
operation plus `configuration`, `summary` and `verification` rows; the
summary carries percentile latency distributions identical to the local
`operation_baseline` format.

## Gate criteria

Run at 20 arrivals/second for at least 15 minutes (≥ 18,000 operations).
The release gate passes when, for the full window:

- zero `verification_failures` and `verification.unresolved == 0` — every
  certified receipt and permission proof verifies against every region;
- `summary.confirmed == summary.offered` (no rejects under WAN conditions);
- `scheduled_to_certified_receipt_ms.p95 < 5,000`;
- `permission_read_ms.p99 < 250` (measured from the remote vantage);
- sustained `completed_workflows_per_second >= 15`.

Record the inter-region RTT matrix (`ping` between hosts) alongside the
driver output; latency targets are defined against the measured RTT, not a
fixed geography.

## Evidence retention

Store the driver output, the RTT matrix and per-node `hub_nodeStatus` samples
with the release records. Node-side resource sampling is out of scope for the
remote driver; collect host metrics (`vmstat`, disk utilisation) separately if
a run needs diagnosis.
