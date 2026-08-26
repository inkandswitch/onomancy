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

- **Keyhive pending**: delegation carriages are not verified — certificates are self-signed by the document key, and the verifier runs a permissive `AuthorityVerifier`. The DNSSEC walk is fully real; the delegation half of the trust story lands with `onomancy_keyhive`.
- Seeds on the command line are a dev-tool convenience, not key management. Shells keep history.
