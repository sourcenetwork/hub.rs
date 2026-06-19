# hub-e2e

End-to-end integration tests. Each test stands up a real multi-node `hubd`
cluster and drives it over JSON-RPC (EVM + native BLS paths).

## Running

Tests need a `hubd` binary. The harness's `resolve_binary()` looks for it in
this order: `HUBD_BINARY` → `HUBD_WORKSPACE` (builds the package) → `hubd` on
`PATH` → `backbone.toml` manifest. It does **not** auto-discover
`target/debug/hubd`, so point it at a build explicitly:

```bash
cargo build -p hubd
HUBD_BINARY="$(pwd)/target/debug/hubd" \
  cargo test -p hub-e2e --test hub_e2e_canonical
```

Or let the harness build the package for you:

```bash
HUBD_WORKSPACE="$(pwd)" cargo test -p hub-e2e
```

`hub_e2e_canonical` is the baseline gate (4-node cluster, both tx paths). Any
change that breaks it has broken the core pipeline.
