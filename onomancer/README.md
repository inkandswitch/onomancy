# onomancer

> [!WARNING]
> Alpha software. Interfaces, wire formats, and specifications change
> without notice — use at your own risk.

The Onomancy agent: publisher and verifier glue over the pure crates. Argument parsing, byte moving, and printing live here; everything cryptographic lives in the libraries.

## Publish a binding

```sh
# 1. Mint keys (keep the seeds SECRET)
onomancer keygen   # → root document key
onomancer keygen   # → generation key

# 2. Emit the record
onomancer record \
  --hostname example.com \
  --doc-seed <hex> --generation-seed <hex>
# ; publish this record (then re-sign the zone):
# _onomancy.example.com. IN TXT "v=ONO0;k=ed25519;n=…;g=…;p=…"

# 3. Put that TXT in the (DNSSEC-signed) zone, wait for propagation,
#    then sign a certificate with the live chain attached:
onomancer record --hostname example.com \
  --doc-seed <hex> --generation-seed <hex> \
  --cert-out example.onc --fetch-chain
```

## Resolve

```sh
# The zone-vouched facts, live from DNS:
onomancer resolve --hostname example.com

# The full graded verdict for a gossiped/fetched certificate:
onomancer resolve --hostname example.com --cert example.onc
```

## Caveats (v0)

- **Delegation carriages are verified** — `resolve` and `watch` run `KeyhiveAuthority`, which replays each certificate's carriage into a throwaway Keyhive instance and answers the spec's signing bar; `bind`/`record` mint real generation carriages. The remaining gaps are narrower: document *content* authorship is not yet checkable (resolutions grade `carriage-verified` at best), `sanctioned` is direct-membership only (nested-group delegation chains are future work — the `#[ignore]`d test in `onomancy_keyhive` is the executable gap), and no verb writes the decision document yet, so acceptance-on-use (binding-cache spec) never fires from this CLI.
- Seeds on the command line are a dev-tool convenience, not key management. Shells keep history.
