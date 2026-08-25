# What Onomancy Needs from Keyhive

_The coordination asks blocking `onomancy_keyhive` — the last stubbed seam in an otherwise end-to-end system. Written for the upstream conversation; everything else in this repo runs today (CLI, Node, and browser verifiers against live DNS)._

## Context, in one diagram

```
DNS zone (DNSSEC-signed)                    Keyhive document
  TXT _onomancy.<host>:                       doc ID = ed25519 vk
    n=<serial> g=<generation> p=<doc id>      (root key destroyed at
         │                                     creation: EphemeralSigner)
         │  chain verified from IANA root          │
         ▼  keys — REAL today                       │  delegation graph
  Onomancy certificate (ONC)                        │  — STUBBED today
    root_doc, hostname, signature ──────────────────┘
    + attached Signed<Delegation> chain: doc root → signer
```

Onomancy binds hostnames to Keyhive documents. The DNS half is done: chains are fetched, walked from the baked-in IANA keys, and graded. The Keyhive half — verifying that the certificate's signer actually holds delegated admin authority over the document, and that the zone-attested _generation key_ lies on that delegation path — runs against a permissive stub (the `AuthorityVerifier` seam). Every verdict currently prints `VACUOUSLY: delegation checks are permissive until onomancy_keyhive`.

The seam is two functions (`onomancy_protocol::verifier_state::seam::AuthorityVerifier`):

```rust
/// Valid delegation chain: roots at `root`, terminates at `signer`,
/// delegating hop held at admin access.
fn authorizes(root: &DocAnchor, signer: &VerifyingKey,
              carriage: &[DelegationBytes]) -> bool;

/// Whether `generation` lies on the delegation path in `carriage` —
/// the path-membership check behind the TXT `g=` rules (D10).
fn on_path(carriage: &[DelegationBytes], generation: &GenerationKey) -> bool;
```

Everything below is what implementing those two functions honestly requires from upstream.

## Ask 1: `Signed<Delegation>` encoding stability (or versioning)

`DelegationBytes` is deliberately opaque in `onomancy_core`: verbatim Keyhive `Signed<Delegation>` bytes. But those bytes ride **inside Onomancy's own signed units** — statement authority carriages are part of the ONR/ONS signed region, and certificates embed the chain. If the encoding changes shape, previously issued certificates and statements stop verifying: evidence rot, in a protocol whose entire point is that old evidence keeps working offline.

**Ask**: a commitment to the wire encoding of `Signed<Delegation>` — frozen, or version-tagged so old bytes stay parseable forever. We don't need the format to be _pretty_; we need `decode(bytes)` to work in ten years.

## Ask 2: pure verification API over supplied bytes

`authorizes` must evaluate the delegation graph — access levels, concurrent-revocation resolution, seniority — **exactly as Keyhive does**. Reimplementing those semantics from a snapshot of the code is a soundness bug factory; the right shape is calling `keyhive_core`'s own evaluation.

**Ask**: an API that verifies a delegation chain _pure over supplied bytes_ — no live replica, no async, no storage handle. Signature: roughly "given these `Signed<Delegation>` bytes, a claimed root ID, and a claimed signer, is this a valid chain with an admin-held delegating hop?" Statements are gossiped and verified offline (self-authenticating evidence is the design), so verification cannot require a connection to anything.

Note this is the same sans-IO posture as the rest of our stack — the DNSSEC validator is "bytes in, proof out" against a baked-in anchor; we need the delegation validator to be "bytes in, bool out" against a self-certifying root.

## Generation keys are ordinary Keyhive keys

The TXT record attests a **generation key** (`g=`) — the rotation chokepoint that makes revocation verifier-visible without a revocation list ([dns-binding.md](./dns-binding.md#generation-key)). D10 requires that key to _lie on the delegation path_ from doc root to certificate signer.

Generation keys need no distinct representation: they are ordinary Keyhive agents/individuals, and `on_path` is membership over the delegation graph, decidable from the carriage bytes alone. `onomancy_keyhive` implements exactly that — `on_path` walks transitive membership at any access, and `mint::generation_carriage` introduces the key with a standard proof-of-possession prekey op plus a root delegation at Relay (the floor — generation keys hold no document access). Nothing here needs upstream action; it is stated so the model is explicit in the conversation.

## Ask 3: "naming" attenuation below admin

Today, issuing a certificate requires full admin on the document ([certificate.md](./certificate.md)) — deliberate (insider key borrowing defense), but coarse. The wish: a capability _below_ admin scoped to certificate issuance for specific hostnames — "may bind `expede.wtf`, and nothing else" — so an org can delegate naming without delegating document control.

**Ask**: is hostname-scoped (or generally payload-scoped) attenuation expressible in Keyhive's capability model, or plannable? This is a feature request, not a blocker: v0 ships admin-only issuance.

## Ask 4: public, resolvable documents under ARK

`@automerge/automerge-repo-keyhive` (ARK) defaults to end-to-end encryption with member-list access control — but a NAMESTORE's whole purpose is that strangers resolve through it. What is the intended shape for a world-readable document: broad read grants, a relay-level plaintext mode, or something else? Onomancy's DNS-anchored root documents must be readable by any verifier who validated the zone binding.

## Ask 5: signed operations and what ingest exposes

When Automerge op signing lands: the op/chunk signature format and its stability story, and what the load/ingest API exposes per-op (authors, at minimum). Onomancy's document-authority grade upgrades from "carriage-verified" to full verification exactly when a verifier can check that every op's author lies on the delegation path from the root key — whether that check runs in our code or is inherited from verified ingest (ARK), the seam is already in place (`onomancy_protocol::resolve::namestore::Authority`).

## Ask 6: the ARK ↔ carriage encoding bridge

ARK's membership events and our `kh0` carriage entries are the same underlying Keyhive events in different lineages (`@keyhive/keyhive` npm vs `keyhive_core` 0.5 crates.io). Certificates need PORTABLE proofs (static files); ARK is a live hive. The standalone-proof-export ask (Ask 2's cousin): a stable way to export the event set that proves one document's delegation graph, consumable by both lineages.

## Adjacent (automerge-repo, not Keyhive proper)

- **Reserved namestore location**: Onomancy walks a flat map at a reserved top-level key (currently `onomancy`, marked provisional) in the document. Coordination so no upstream convention collides — and a ruling on the flat-map-with-multi-segment-keys vs sub-tree-path tension ([names.md](./names.md), open warning).
- **Doc-ID text encoding**: we adopted `automerge:` + bs58check wholesale; confirm key-based document IDs keep that spelling.

## What we run meanwhile

`onomancy_keyhive` runs the REAL `AuthorityVerifier` today: carriages replay into a throwaway `keyhive_core` 0.5 instance behind a versioned envelope (`kh0`), so encoding churn (Ask 1) is a loud parse error and a re-attach — never a misread. Ask 2 (a pure bytes-in API) would delete the throwaway-instance workaround and unlock in-browser verification; Asks 4–6 gate document-content verification (today graded `carriage-verified` at best — the `Authority` seam in `onomancy_protocol` carries the gap explicitly until verified ingest or signed operations land).
