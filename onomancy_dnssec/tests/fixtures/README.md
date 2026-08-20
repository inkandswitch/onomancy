# Chain Fixtures

Checked-in, hermetic `DnssecChain` fixtures (framed wire bytes) for the
validation walk. Each file's expected outcome is declared in the
fixture catalog (`src/test_utils/fixtures.rs`) and asserted by
`tests/fixtures.rs` — the catalog is the single source of truth for
both the bytes and the expectations.

## Regeneration

```sh
cargo run -p onomancy_dnssec --example generate_fixtures \
    --features test_utils,std
```

Fully deterministic: zones are Ed25519-keyed from fixed seeds and every
window is a constant, so regeneration is byte-identical unless a
fixture _definition_ changed. A diff here without a catalog change
means the codec changed shape — which is exactly what the fixtures
exist to catch.

## Catalog

| File | Expectation |
|------|-------------|
| `valid_binding.chain` | Binding proof (serial `1755000000000`) |
| `valid_absence.chain` | Absence proof (NSEC covering the owner) |
| `wildcard_proven.chain` | Binding (wildcard expansion + covering denial, D14) |
| `tampered_leaf.chain` | invalid — one bit flipped in the leaf |
| `disjoint_windows.chain` | invalid — RRSIG windows never jointly held |
| `ds_mismatch.chain` | invalid — child keys match no DS |
| `missing_leaf.chain` | invalid — neither TXT nor denial |
| `wildcard_unproven.chain` | invalid — wildcard without no-closer-match (D14) |
| `misordered_links.chain` | invalid — DS/DNSKEY links swapped |
