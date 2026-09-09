# Carriage Fixtures

Frozen authority carriages exercised by the integration tests in `tests/`. One `kh0` entry per line, hex-encoded. These are real-world captures, not generated: do not regenerate, recapture deliberately if ever needed.

## Catalog

| File | Test | Expectation |
|------|------|-------------|
| `variable_width_content_ref_carriage.hex` | `tests/variable_width_content_ref.rs` | invalid — `UndecodableEvent { index: 0 }`; authorizes nobody |

## `variable_width_content_ref_carriage.hex`

Captured 2026-09-08 from the `onomancy-demo` browser app (keyhive_wasm 0.1.0-alpha.8, automerge-repo-keyhive 0.5.0-alpha.6) while minting a certificate for `brooklynzelenka.com`. Eight entries:

- entry 0 — `Delegated`: root-issued, `Admin`, delegate = the certificate's signer, issuer = the document. Signature verifies. Its `after_content` carries a length-prefixed 10-byte reference: the peer instantiated Keyhive over `Vec<u8>` content references, where `kh0` is Keyhive's default `[u8; 32]`.
- entries 1–7 — `PrekeysExpanded` by the signer. No content references, so they decode identically under either instantiation.

The two wire formats differ only when `after_content` is non-empty, which minted carriages never are, so no generated fixture can detect an instantiation mismatch. This capture is the only thing that turns red if the crate is ever switched to variable-width references. Replace with a positive fixture once the browser stack emits `[u8; 32]` references.
