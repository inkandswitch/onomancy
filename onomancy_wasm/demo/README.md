# Browser demos

Two pages, one Wasm module:

- [`index.html`](./index.html) — the live verifier: DoH fetch → DNSSEC walk from the baked-in IANA root keys → graded verdict. No certificate authority, no trusted resolver, no server component.
- [`names.html`](./names.html) — documents naming documents: mint in-tab Automerge documents, wire namestore edges between them, and resolve full onomancy names (`automerge:…/…`, `~/…`, `@host/…`) with the real greedy walk. `@host` names anchor live over `DoH` first, then walk the held documents — documents the tab doesn't hold are fetched from [`docs/`](./docs/) by anchor as the walk needs them. Try `@brooklynzelenka.com/team/john`: the zone attests the root document, `docs/` carries its real bytes, and the walk lands on John.

`docs/` holds real saved documents named by their anchors (the dev-bridge substrate, same convention as `onomancer name --docs`). Regenerate or extend them with the `namestore_doc` example:

```sh
cargo run -p onomancy_automerge --example namestore_doc -- \
  onomancy_wasm/demo/docs/<anchor>.automerge --note="…" "team/john=automerge:…"
```

One command builds and serves both (from the workspace root):

```sh
nix run .#demo        # or `wasm:demo` inside the dev shell; port arg optional
# → http://localhost:8080/ and /names.html
```

`pkg/` is generated (gitignored). To rebuild it by hand:

```sh
cargo build -p onomancy_wasm --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir onomancy_wasm/demo/pkg \
  target/wasm32-unknown-unknown/release/onomancy_wasm.wasm
wasm-opt -Oz -o onomancy_wasm/demo/pkg/onomancy_wasm_bg.wasm \
  onomancy_wasm/demo/pkg/onomancy_wasm_bg.wasm
```

Then serve the demo directory (Wasm needs real HTTP, not `file://`):

```sh
python3 -m http.server -d onomancy_wasm/demo 8080
# → http://localhost:8080
```

Node works too (18+, global fetch), no browser required:

```js
const { resolveHostname } = require("./pkg-nodejs/onomancy_wasm.js");
await resolveHostname("brooklynzelenka.com");
// { hostname, links: 6, freshness: "fresh", records: ["v=ONO0;…"] }
```

(build with `--target nodejs` into `pkg-nodejs/` for that one).
