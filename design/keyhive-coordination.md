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

## Ask 3: generation keys as graph citizens

The TXT record attests a **generation key** (`g=`) — the rotation chokepoint that makes revocation verifier-visible without a revocation list ([dns-binding.md](./dns-binding.md#generation-key)). D10 requires that key to _lie on the delegation path_ from doc root to certificate signer.

**Ask**: a ruling on how generation keys should be modeled — are they ordinary Keyhive agents/individuals appearing as hops in the delegation graph (in which case `on_path` is just membership over the chain), or do they need a distinct representation? We have no preference beyond: the check must be decidable from the carriage bytes alone (see Ask 2).

## Ask 4: "naming" attenuation below admin

Today, issuing a certificate requires full admin on the document ([certificate.md](./certificate.md)) — deliberate (insider key borrowing defense), but coarse. The wish: a capability _below_ admin scoped to certificate issuance for specific hostnames — "may bind `expede.wtf`, and nothing else" — so an org can delegate naming without delegating document control.

**Ask**: is hostname-scoped (or generally payload-scoped) attenuation expressible in Keyhive's capability model, or plannable? This is a feature request, not a blocker: v0 ships admin-only issuance.

## Adjacent (automerge-repo, not Keyhive proper)

- **Reserved namestore location**: Onomancy walks a flat map at a reserved top-level key (currently `onomancy`, marked provisional) in the document. Coordination so no upstream convention collides — and a ruling on the flat-map-with-multi-segment-keys vs sub-tree-path tension ([names.md](./names.md), open warning).
- **Doc-ID text encoding**: we adopted `automerge:` + bs58check wholesale (ADR-017); confirm key-based document IDs keep that spelling.

## What we run meanwhile

The `AuthorityVerifier` seam with a permissive in-memory fake (deny-lists for tests). Everything downstream — derivation, bridging, grading, surfacing — is implemented and conformance-tested against the seam, so `onomancy_keyhive` is a drop-in: two functions, no architectural change. The moment Asks 1–3 land, the word "VACUOUSLY" disappears from the verdict output.
