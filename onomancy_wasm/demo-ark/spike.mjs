// ARK spike, checkpoint 1: offline hive + repo, create2 a protected
// doc, test doc-ID ↔ DocAnchor alignment, write namestore edges,
// extract bytes for the onomancy walk.
import "@automerge/automerge-subduction"; // node condition: initSync on the shared wasm module
import {
  initializeAutomergeRepoKeyhive,
  KEYHIVE_SYNC_SERVER_PEER_ID,
} from "@automerge/automerge-repo-keyhive";
import { Repo } from "@automerge/automerge-repo";

class MemoryStorage {
  #data = new Map();
  #key(k) { return k.join("\u0000"); }
  async load(k) { return this.#data.get(this.#key(k)); }
  async save(k, v) { this.#data.set(this.#key(k), v); }
  async remove(k) { this.#data.delete(this.#key(k)); }
  async loadRange(prefix) {
    const p = this.#key(prefix);
    return [...this.#data.entries()]
      .filter(([k]) => k.startsWith(p))
      .map(([k, data]) => ({ key: k.split("\u0000"), data }));
  }
  async removeRange(prefix) {
    const p = this.#key(prefix);
    for (const k of [...this.#data.keys()]) if (k.startsWith(p)) this.#data.delete(k);
  }
}

const { hive, repo } = await initializeAutomergeRepoKeyhive({
  createRepo: (config) => new Repo(config),
  storage: new MemoryStorage(),
  peerIdSuffix: "ark-spike",
  syncServer: "none",
  remotePeerId: KEYHIVE_SYNC_SERVER_PEER_ID, // inert: no endpoints configured
  periodicallyRequestSync: false,
  automaticArchiveIngestion: false,
  enableCompaction: false,
  repo: { storage: new MemoryStorage(), subductionWebsocketEndpoints: [] },
});
console.log("hive up, peer:", hive.peerId.slice(0, 20) + "…");

// A keyhive-protected doc via the id factory.
const john = await repo.create2({ note: "hi from ARK 🐝" });
console.log("john url:", john.url);

// ALIGNMENT TEST: does the keyhive doc id parse as an onomancy DocAnchor?
const { HeldDocuments, Name } = await import("../pkg-node/onomancy_wasm.js");
const held = new HeldDocuments();
try {
  const name = new Name(john.url);
  console.log("DocAnchor alignment: PARSES ✓ anchorKind =", name.anchorKind);
} catch (error) {
  console.log("DocAnchor alignment: FAILS ✗", String(error));
}

// A root namestore doc naming john, in ARK.
const root = await repo.create2({});
const A0 = await import("@automerge/automerge");
await root.change((d) => { d.onomancy = { "team/john": new A0.ImmutableString(john.url) }; });
console.log("root url:", root.url);

// Extract bytes from the repo and walk with the REAL resolver.
const A = await import("@automerge/automerge");
held.hold(root.url, A.save(await root.doc()));
held.hold(john.url, A.save(await john.doc()));

const verdict = await held.resolve(`${root.url}/team/john`, undefined, undefined);
console.log("walk verdict:", verdict);
if (verdict.document !== john.url) throw new Error("landed on the wrong document!");
console.log("landing identity: CONFIRMED ✓ (resolved doc === john)");
process.exit(0);
