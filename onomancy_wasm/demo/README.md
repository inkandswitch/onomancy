# Live verifier demo

The whole Onomancy verifier in a browser tab: DoH fetch → DNSSEC walk from the baked-in IANA root keys → graded verdict. No certificate authority, no trusted resolver, no server component.

`pkg/` is generated (gitignored). Rebuild it with:

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
