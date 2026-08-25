# Guidance

## For Publishers

1. **DNSSEC-sign your zone** — an unsigned zone cannot anchor a binding; algorithms 8, 13, and 15 are supported
2. **Bind, then refresh** — `onomancer bind` publishes the TXT record; `onomancer refresh` attaches the live chain to the certificate
3. **Keep superseded certificates retrievable** — they are immutable static files; verifiers returning after multiple migrations bridge through them
4. **Rotate on suspicion** — a leaked generation key is healed by rotation: fresh records under the old key are rejected once the zone moves
5. **Never rely on wildcard bindings** — wildcard-synthesized answers are rejected by verifiers

## For Verifier and App Developers

1. **Validate locally, always** — never delegate to a resolver's AD bit; the baked-in IANA anchors are the only trust root
2. **Framability is not validity** — a fetched chain is unverified input until your own validator accepts it
3. **The clock enters once** — grade freshness at your own instant; no other step reads time
4. **Surface, don't suppress** — divergence badges and ratchet resets exist so users can act on them
5. **Treat transport as hostile** — DoH narrows who sees your queries; it adds no trust

## For Extenders

The extension model in one line: **typed below the parse boundary, closed sum at it; compose at seams; new machines for new substrates; policy as data; closed sums where consensus lives.** Concretely:

1. **New anchor kind** (pkarr, ENS, did:…) — three steps, only the last needs a protocol revision:
   - _Grammar_: implement `onomancy_core::anchor::Anchor` on your name type, in your own crate. `onomancy_dnssec` is the worked example: `DnsName` and everything DNS live outside core.
   - _Attestation_: build your kind's anchor-to-document machinery behind your own seam trait. Do not extend the DNSSEC machines — write your own (sans-IO machines vary at their boundaries, never in their guts, and a new substrate's machine is usually small).
   - _The sigil_: existing edges dispatch on a closed enum (`SupportedName`), deliberately — a name's phishing analysis depends on readers knowing exhaustively what each sigil can mean. Ship your own edge that composes the crates (the walk is reusable today: resolve your anchor to a root document yourself, then hand it to the `~`-with-root APIs), or propose the sigil upstream as a protocol revision.
2. **New storage substrate** — implement `onomancy_protocol`'s `Namestore`/`Replicas`/`Vouched`; `onomancy_automerge` is one adapter, `MemoryNamestore` a second.
3. **New transport** — implement `onomancy_dnssec::chain_provider::ChainProvider`, or drive the sans-IO `ChainBuilder` with your own socket; hickory (UDP/TCP) and wasm (DoH) are two independent examples.
4. **New authority system** — implement `AuthorityVerifier`.
5. **Behavioral variation inside a machine** — prefer values over type parameters: trust-anchor sets, hop limits, and horizons are runtime data flowing into concrete machines, which keeps the semantic core printable and auditable.
6. **Evidence kinds and derivation rules are the protocol** — the store's item set and the verdict derivation are consensus-bearing (two verifiers holding the same evidence MUST reach the same verdict), so they are closed by design. Extension there is a coordinated protocol revision, never a plugin.

## Further Reading

See [`specs/`](./specs/) for the normative rules and [`design/`](./design/) for the threat model and rationale.
