# onomancy_automerge

> [!WARNING]
> Alpha software. Interfaces, wire formats, and specifications change
> without notice — use at your own risk.

The [Automerge] substrate adapter: the sans-IO bridge between Onomancy's pure machines and the CRDT documents that carry user data.

| Seam (defined in `onomancy_protocol`) | Implementation here  |
|---------------------------------------|----------------------|
| `resolve::namestore::Namestore`       | `DocumentNamestore`  |
| `resolve::namestore::Replicas`        | `HeldDocuments`      |
| `verifier_state::decisions::Decisions`  | `DecisionsView`       |
| Derivation stage-8 `pins`             | `petname::pins`      |
| Certificate `heads` field             | `change_hash::*`     |

Plus `petname::PetnameStore` for the writes the petname-anchor spec mandates: pin, deliberate re-pin, rename, unpin.

## What lives in Automerge (and what does not)

Automerge documents hold three kinds of Onomancy data, all as **top-level keys**. A namestore is the document's own map, not a container inside it, so a name `foo` is the key `foo` and nothing is nested. Protocol data sits beside the names under the `.well-known/onomancy/` prefix, and is absent from name matching because its value is not a reference rather than because any resolver knows the key.

- **Namestore edges** — `path → automerge:‹id›` entries that path resolution walks; in the user's own root document these are the petnames.
- **`.well-known/onomancy/certificates`** — the certificates binding DNS hostnames to this document, inline or one hop away.
- **`.well-known/onomancy/decisions`** — the user's decisions (acceptances, resets, claims), private to the user but replicated across the user's own devices; concurrent decisions surface as ordinary MV conflicts, resolved by the derivation's receipts rule.

The verifiable protocol records — certificates, DNSSEC chains, TXT records, statements — live in the binding-cache store (`onomancy_protocol::verifier_state::store`), never here: decision entries reference them only by opaque content hash.

## Deliberate non-goals

- **No Keyhive.** Authority verification (`AuthorityVerifier`) is `onomancy_keyhive`'s single job — resolver-only consumers skip the CGKA crypto entirely.
- **No IO.** Every reader answers from documents already held; `Replicas::replica` returning `None` means "not replicated here", which the walk reports as `UnsyncedTarget` — the designed outcome under partition. Replication and persistence belong to the substrate and the agent.

[Automerge]: https://automerge.org

> [!WARNING]
> Held documents are GRADED, not fully verified: `HeldDocuments` vouches each replica at an explicit `Authority` grade, and no grade producible today proves the document's content was authored by the anchor's delegates. `trusted-substrate` checks nothing; `carriage-verified` proves only that a delegation graph roots at the anchor. Full verification waits on upstream signed operations / verified ingest — the seam exists so that upgrade is an impl swap.
