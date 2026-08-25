# Hacking on Onomancy

This document explains the key engineering patterns and abstractions used in Onomancy. It's intended for contributors and anyone trying to understand what is going on in the codebase.

**Start here**, then dive into the docs:

- [`specs/`](./specs/) — normative specifications (BCP 14 keywords): name grammar, path resolution, serialization, and the anchoring suite (DNS anchor, petname anchor, binding cache)
- [`design/`](./design/) — rationale, threat model, and the trade-offs behind the specs

## The Sans-IO Doctrine

Every library crate is sans-IO: machines take values in and hand verdicts out; the caller drives all IO. Only the couriers touch the network, and nothing they return is trusted.

```
  pure (sans-IO)                              byte couriers (IO)
 ┌───────────────────────────────────────────┐  ┌──────────────────────────┐
 │ onomancy_core — vocabulary: names, TXT,   │  │ onomancy_hickory         │
 │   certificate/statement units, digests    │  │   OS-socket stub DNS     │
 │        ▲                                  │  ├──────────────────────────┤
 │ onomancy_protocol — machines + seams      │◀─┤ onomancy_wasm::doh       │
 │        ▲                    ▲             │  │   RFC 8484 fetch()       │
 │ onomancy_dnssec       onomancy_automerge  │  └──────────┬───────────────┘
 │ onomancy_chain        onomancy_keyhive*   │             │ both drive
 └───────────────────────────────────────────┘             ▼
  onomancer (bin): the agent            onomancy_chain::builder::ChainBuilder
                                        (* keyhive is host-only, std)
```

Three consequences worth internalizing:

1. **Time is data.** No machine reads a clock. `VerifierState::compute(store, now, …)` takes `now` as a parameter; the DNSSEC walk grades nothing (windows are intersected, grading happens later, at the caller's instant). The only `now()` call in the workspace lives in the `onomancer` binary.
2. **Transport is untrusted by design.** The stub resolver uses weak query IDs and no transport security on purpose: DNSSEC validation against the baked-in IANA anchors is the only trust boundary. A spoofed answer produces a chain that fails validation — never a false bind.
3. **Framability is not validity.** `ChainBuilder` selects and frames bytes but proves nothing; `onomancy_dnssec::validator` renders every verdict.

## The ChainBuilder: Questions Out, Records In

Chain fetching is a state machine, not an async function:

```rust,ignore
let (mut builder, mut question) = ChainBuilder::start(&hostname)?;
loop {
    let records = transport.query(&question).await?; // driver's IO, driver's error
    match builder.answer(records)? {
        Step::Ask(next, asked) => {
            builder = next;
            question = asked;
        }
        Step::Done(chain) => break chain,
    }
}
```

`answer` consumes the machine by value — a finished or failed builder cannot be answered again. Transport failure never appears in `BuildError`; it stays on the driver's side of the seam. Both couriers (`onomancy_hickory` over sockets, `onomancy_wasm` over `fetch()`) are ~10-line loops around the same machine.

## Seams

`onomancy_protocol` defines the traits everything plugs into:

| Seam | Answers | Implemented by |
|------|---------|----------------|
| `ChainProvider` | "fetch me the DNSSEC chain for this hostname" | `onomancy_hickory`, `onomancy_wasm::doh` |
| `ChainValidator` | "is this chain valid from my anchors?" | `onomancy_dnssec` |
| `AuthorityVerifier` | "may this signer speak for this document?" | `onomancy_keyhive` |
| `Namestore` / `Replicas` | reads over locally-held documents | `onomancy_automerge` |

Seam implementations over foreign library types are **quarantine crates**: `onomancy_dnssec` isolates rsa/p256, `onomancy_keyhive` isolates the keyhive tree, `onomancy_chain` is pure over hickory-proto types, `onomancy_automerge` over automerge. Core and protocol stay lean.

## Signed Units: Decode Is the Witness

Certificate and statement units (`ONC`/`ONR`/`ONS`) verify their signature **at decode** — a signature-invalid unit is undecodable, so there is no verify-and-forget hazard and no separate witness type to thread around. Units drop their wire bytes and re-derive them canonically: `encode ∘ decode = id`, pinned by byte-identity property tests and golden vectors (`onomancy_core/tests/vectors/`).

Related invariants:

- Encoders cannot build units their own decoders reject (the 1 MiB unit cap is enforced on both sides)
- serde may _transport_, never _define_: no field-level derive on wire types, ever
- Wire formats are documented with box diagrams in the module docs

## Common Patterns

- **Parse, don't validate**: constructors return typed invariant-holders (`DnsName`, `DocAnchor`, `Serial`), never booleans
- **Newtypes everywhere**: `Digest<T>` is phantom-typed; `UnixSeconds` is not a `u64`
- **No unwrap-family combinators in production code** — even total ones like `unwrap_or`. Fallbacks are explicit `match`es or narrow `thiserror` variants; `expect("reason")` is fine in tests
- **Granular errors**: per-failure-mode variants with data, `#[from]`/`#[source]` preserving the chain, never `String`
- **Imports at module scope only** — never inside a function body, never inline-qualified paths when a sibling import exists
- **One module per primary type**; companion types (a type's error enum, its return vocabulary) stay co-located
- **`collections::{Map, Set}`** from core everywhere: std `HashMap` (SipHash) under std, `BTreeMap` under no_std. Determinism is required up to _values_, not iteration order
- **Comments state facts and invariants, not arguments.** Lint `allow`s get a terse one-line reason

## Testing Strategy

| Level | Tool | Notes |
|-------|------|-------|
| Property tests | `bolero` | Roundtrips, grammar disjointness, termination; live in `mod tests { mod props }` — `cargo test props::` selects them |
| Golden vectors | checked-in bytes | `onomancy_core/tests/vectors/` — byte drift is a wire-format break |
| Conformance | scenario replay | `verifier_state_conformance.rs` rows map to spec disposition tables; scenarios replay identically under memory fakes and the real validator |
| Never-rots fixtures | frozen production chains | `onomancy_dnssec/tests/fixtures/real_*` validate clock-free, forever |
| Browser | wasm-bindgen-test | `nix run .#ci-browser` (Chromium + Firefox); live DoH tests behind the `live` feature |
| Live smoke | `--ignored` tests | Query real resolvers; run deliberately |

Tests prefer `TestResult` returns and `matches!` on error variants; `expect` is confined to test modules under scoped allows.

## Dev Workflow

Everything runs through the Nix flake — it is the single source of truth for toolchains:

```sh
nix develop            # dev shell: pinned rust 1.91 + nightly rustfmt wrapper
nix run .#ci           # the full gate: fmt, clippy, test, wasm, no-std, deny
nix run .#ci-fmt       # any single check: ci-{fmt,clippy,test,wasm,no-std,deny}
nix run .#ci-browser   # real-browser wasm tests (pulls whole browsers)
```

GitHub Actions is a thin matrix over the same apps, so local runs are CI runs.

> [!WARNING]
> Always format via `nix develop --command cargo fmt` (or check with `nix run .#ci-fmt`). A bare `cargo fmt` outside the shell uses your ambient rustfmt and produces different import ordering.

Two version pins move in lockstep and must be bumped together:

- `rust-toolchain.toml` + flake rust-overlay + workspace `rust-version`
- `wasm-bindgen = "=0.2.121"` + the flake's `wasm-bindgen-cli` (bindgen schema versions must match exactly)

## Getting Started

1. Read `specs/name-grammar.md` and `specs/anchoring/dns-anchor.md` — the disposition tables (D-rules, B-rules) name most of the invariants you'll see cited in code
2. Read `onomancy_protocol/src/verifier_state.rs` for the derivation pipeline
3. Run `nix run .#ci` and `cargo run -p onomancer -- resolve --hostname brooklynzelenka.com`

## Questions?

The design docs in [`design/`](./design/) carry the rationale; open an issue for anything they don't answer.
