# Golden Vectors

Checked-in wire-format vectors mandated by [specs/serialization.md § Test Vectors](../../../specs/serialization.md#test-vectors). Each `{name}.hex` file holds one unit's canonical bytes (lowercase hex); `digests.txt` records the content hash of every unit that decodes. The catalog — the single source of truth — lives in [`tests/support/vectors_catalog.rs`](../support/vectors_catalog.rs), and [`tests/golden_vectors.rs`](../golden_vectors.rs) replays everything on every test run.

> [!WARNING]
> Byte drift here is a wire-format break, not a refactor. Canonical
> re-derivation (`encode(decode(b)) = b`) is load-bearing:
> only regenerate these files for a deliberate, versioned format
> change.

Regenerate with:

```sh
cargo run -p onomancy_dnssec --example generate_vectors
```

## Status

_Provisional._ The spec sources vectors from the Lean reference model (design/verification.md); until that toolchain lands, these are generated from the Rust implementation and gate against drift, not against an independent model. Mandated cases not yet covered here: maximal heads count and overlong-adjacent integer mutations. Covered elsewhere: the multi-link DNSSEC chain crossing a zone cut lives in `onomancy_dnssec/tests/fixtures/` — including `real_brooklynzelenka.chain`, a production capture with real IANA-rooted signatures — and the statement authority-carriage rejection set is validation-level, exercised in `onomancy_protocol` conformance tests.
