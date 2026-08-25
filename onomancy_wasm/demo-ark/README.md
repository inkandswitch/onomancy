# ARK spike: onomancy names over keyhive-protected documents

A Node spike driving [`@automerge/automerge-repo-keyhive`][ARK] (ARK) as the document substrate for the onomancy resolve walk.

> [!WARNING]
> Spike quality, pinned to fast-moving alphas (`0.5.0-alpha.6` + `automerge-repo@2.6.0-subduction.48`). Expect breakage on any bump. The walk still grades these documents `trusted-substrate`: ARK enforces membership on SYNC, but nothing in this process verifies the extracted bytes — inherited ingest verification is the endgame, not the current state.

## What it proves

- **Doc-ID alignment**: `repo.create2` documents get keyhive document IDs, and their `automerge:…` URLs parse verbatim as onomancy `DocAnchor`s (`anchorKind: "doc"`). The two systems name documents identically, by construction.
- **The walk composes**: namestore edges written through ARK's repo resolve with the real `onomancy_protocol::resolve` (via the wasm module) — `<root>/team/john` lands on John's keyhive-protected document.
- **Offline hive**: `syncServer: "none"` + an inert `remotePeerId` + empty `subductionWebsocketEndpoints` runs the whole stack with no network.

## Bridge notes (found the hard way)

- ARK imports `@automerge/automerge-subduction/slim` (uninitialized); under Node, `import "@automerge/automerge-subduction"` first — its node entrypoint runs `initSync` on the shared wasm module.
- Namestore references are ATOMIC values (spec condition E5: composite values never resolve), and automerge JS strings are collaborative `Text` by default — so JS writers use `new ImmutableString(...)` for namestore values. This is writer-side by design: reading `Text` leniently would let concurrent character-level merges splice two anchors into garbage. The eventual npm package should export a `writeEdge(handle, path, target)` helper so this cannot be gotten wrong.
- Pin `@automerge/automerge-repo` to ARK's exact lineage (`-subduction.*` builds); a second copy from the main line breaks `repo.subduction`.

## Run

```sh
npm install
# build the nodejs-target wasm first (from the workspace root):
# nix develop --command wasm-bindgen --target nodejs --out-dir onomancy_wasm/pkg-node \
#   target/wasm32-unknown-unknown/release/onomancy_wasm.wasm
node spike.mjs
```

## Next

- Live sync via `wss://keyhive.sync.automerge.org` (two peers, contact cards, `addMemberToDoc`)
- Stranger resolution is blocked on the public-documents question (`design/keyhive-coordination.md`, Ask 4)
- Inherited ingest verification once signed operations land (Ask 5)

[ARK]: https://www.npmjs.com/package/@automerge/automerge-repo-keyhive
