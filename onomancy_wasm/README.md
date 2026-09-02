# onomancy_wasm

> [!WARNING]
> Alpha software. Interfaces, wire formats, and specifications change
> without notice — use at your own risk.

Wasm/JavaScript bindings for Onomancer (browser and Node.js). Built as an npm package with [wasm-bodge](https://github.com/alexjg/wasm-bodge).

Verification runs **entirely locally**, from trust anchors compiled into the
module. DNS proves one direction — that a zone names a document — and a
certificate proves the other, that the document accepts the hostname back.
Either alone is insufficient: anyone controlling any signed zone can point it
at any document, so a resolved name is not an authenticated one until both
directions agree. See the [DNS anchoring specification][dns-anchor]
§Verification.

## What's inside

- `buildInfo()` — `{ version, revision }`. The version does not identify an artifact (two builds can share one); the embedded source revision does. Check it before debugging anything else.
- `Name` (`JsName`) — the three-anchor name grammar: parse, normalize, and inspect anchors and segments. Names carry no version pins (`#` is reserved; pinning is edge data, not grammar).
- `doh` — the DNS-over-HTTPS chain courier (RFC 8484 POST, message ID 0): `DohProvider` drives the sans-IO chain builder (`onomancy_chain`) over global-scope `fetch()`, so it works in windows, workers, and Node 18+ alike. The transport is exactly as untrusted as the socket one — validation happens locally.
- `resolveHostname(hostname, dohUrl?, nowSeconds?)` — the one-call live walk: fetch the chain over `DoH`, validate it from the baked-in IANA anchors inside the Wasm module, and grade freshness. Returns `{ hostname, links, records, freshness, window: { inception, expiration }, checkedAt }`. `window` and `checkedAt` are the *inputs* to the freshness decision, returned so a caller can check the work: `checkedAt - window.expiration` is how far a stale chain has lapsed, and comparing `checkedAt` to your own clock detects skew, which is otherwise indistinguishable from staleness. Pass `nowSeconds` to grade at a fixed instant — validation is pure over bytes, so one captured chain can be graded deterministically in tests.
- `verifyCertificate(bytes, hostname, nowSeconds?)` — the other direction, for a certificate that arrived out of band (gossip, QR, a file). Checks the signature, the hostname, the DNSSEC chain from the baked-in anchors, the zone's cross-check, and the Keyhive delegation carriage. Returns `{ hostname, document, serial, freshness, generation, window, checkedAt }`.
- `verifyBinding(held, anchor, hostname, nowSeconds?)` — the same check, reading the certificate from a held document's reserved well-known path (following at most one hop of indirection). Replication stays the substrate's job: supply the document with `hold()`.
- `signableBytes(rootDoc, signer, issuedAt, hostname)` / `encodeCertificate(…, signature, carriage, chain)` — certificate issuance without the module ever holding a key. Assembly takes a signer, never key material: the `Signing` type (`{ verifyingKey, sign }`) is the contract. The signer MUST sign the bytes verbatim — a signer that frames its input (length prefix, domain tag, envelope) produces a signature `encodeCertificate` rejects, and no caller-side adjustment can fix that. `resolveHostname` returns the `chain` ready to pass through.

The delegation check replays each certificate's carriage into a **throwaway**
Keyhive instance and discards it, so nothing here shares state with an
application's own Keyhive — no second stateful instance, and verdicts depend
only on the evidence presented.

Verification is not optional: there is no build of this package that resolves a
name but cannot check it. `verifyBinding` additionally needs the document
substrate, so it follows the `names` feature; `verifyCertificate` is always
present.

## Demo

A browser demo lives at [`demo/index.html`](https://github.com/inkandswitch/onomancy/tree/main/onomancy_wasm/demo) (the `pkg/` directory is generated — see `demo/README.md` for build steps). It runs against production DNS in browsers and Node 18+.

<!-- Absolute URL deliberately: this file is the npm package README, where
     relative repository paths do not resolve. -->

[dns-anchor]: https://github.com/inkandswitch/onomancy/blob/main/specs/anchoring/dns-anchor.md
