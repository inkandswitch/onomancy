# onomancy_wasm

Wasm/JavaScript bindings for Onomancer (browser and Node.js). Built as an npm package with [wasm-bodge](https://github.com/alexjg/wasm-bodge).

## What's inside

- `Name` (`JsName`) — the three-anchor name grammar: parse, normalize, and inspect anchors, segments, and pinned heads.
- `doh` — the DNS-over-HTTPS chain courier (RFC 8484 POST, message ID 0): `DohProvider` drives the sans-IO chain builder (`onomancy_chain`) over global-scope `fetch()`, so it works in windows, workers, and Node 18+ alike. The transport is exactly as untrusted as the socket one — validation happens locally.
- `resolveHostname(hostname, dohUrl?)` — the one-call live walk: fetch the chain over `DoH`, validate it from the baked-in IANA anchors inside the Wasm module, and grade freshness at the current time. Returns `{ hostname, links, freshness, records }`.

## Demo

A browser demo lives at [`demo/index.html`](./demo) (the `pkg/` directory is generated — see `demo/README.md` for build steps). It runs against production DNS in browsers and Node 18+.
