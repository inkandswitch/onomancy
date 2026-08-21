# onomancy_automerge

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

Automerge documents hold exactly two kinds of Onomancy data, both under the reserved top-level key `onomancy`:

- **Namestore edges** — the flat `path → automerge:‹id›` map that path resolution walks; in the user's own root document these are the petnames.
- **The decision document** — the user's decisions (acceptances, resets, claims), private to the user but replicated across the user's own devices; concurrent decisions surface as ordinary MV conflicts, resolved by the derivation's receipts rule.

The verifiable protocol records — certificates, DNSSEC chains, TXT records, statements — live in the binding-cache store (`onomancy_protocol::verifier_state::store`), never here: decision entries reference them only by opaque content hash.

## Deliberate non-goals

- **No Keyhive.** Authority verification (`AuthorityVerifier`) is `onomancy_keyhive`'s single job — resolver-only consumers skip the CGKA crypto entirely (ADR-043 §10).
- **No IO.** Every reader answers from documents already held; `Replicas::replica` returning `None` means "not replicated here", which the walk reports as `UnsyncedTarget` — the designed outcome under partition. Replication and persistence belong to the substrate and the agent.

[Automerge]: https://automerge.org
