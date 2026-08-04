# Assumptions

This document lists the assumptions Onomancy makes about its environment. Violating these assumptions may lead to incorrect resolution, accepted forgeries, or unrecoverable trust state.

## Cryptography

### Ed25519 Unforgeability

> **Assumption:** Ed25519 signatures cannot be forged without the signing key.

Onomancy certificates, root document edges, and (transitively) the entire key-anchor identity model rest on this. There is no fallback algorithm at v0; `k=ed25519` in the TXT record leaves room for migration via a version bump.

**Consequence of violation:** Arbitrary identity forgery.

### Random Number Generation

> **Assumption:** Signing keys are generated from a cryptographically secure source.

`getrandom` on native platforms; `crypto.getRandomValues()` in browsers (via the `wasm_js` backend).

**Consequence of violation:** Predictable keys, identity takeover.

## Keyhive / Automerge

### Doc ID Is the Controlling Authority

> **Assumption:** A Keyhive root document ID _is_ an ed25519 verifying key, is stable for the document's lifetime, and roots a self-certifying delegation graph.

**Verified** against inkandswitch/keyhive @ `d12511d`: `DocumentId` wraps an ed25519 `VerifyingKey`; identity keys are immutable and prekey rotation is ECDH-only, so the ID never changes. However, the doc-root _signing_ key is destroyed at creation (`EphemeralSigner`) — the ID is not a held key. Authority is proven by the `Signed<Delegation>` chain from the root, which the certificate embeds.

**Consequence of violation:** If Keyhive's semantics change (e.g. doc IDs become rotatable), the binding record and certificate schema must be redesigned.

## DNS / DNSSEC

### IANA Root KSK Integrity

> **Assumption:** The IANA root KSK is not compromised, and clients ship the correct one.

Exactly one KSK is baked in at a time. It rotates every few years — a deliberately slow trust anchor; empirically the root has seen one rollover (2018) and one ceremonial revocation (2019) in its history, so app-update cadence realistically outruns it. A trust-anchor _set_ plus an RFC 5011-style rollover story is future work: stale clients must be able to validate chains signed under a newer KSK, and clients shipped during a rollover overlap should carry both keys so chains gossiped across the boundary verify on either side.

**Consequence of violation:** The entire DNS anchor is forgeable. Doc anchors and petnames are unaffected. Note the offline sharpening: a client offline across a compromise-and-revocation accepts _fresh_ forged chains — graded freshness measures signature windows, not key legitimacy (see [security.md](./security.md#offline-anchor-rot)).

### The Revocation Ceremony Rotates the Generation

> **Assumption:** Revoking a naming-relevant key is one ceremony: the owner revokes the delegation, rotates the generation key, and publishes the new `g=` — the publication is not a separate task that can be forgotten.

There is no revocation oracle — requiring one would break offline verification (a rejected design alternative). The generation key makes revocation verifier-visible through the record itself: a revoked signer's chain no longer threads the attested chokepoint, and fresh chains reject it. This works only if the owner actually publishes the rotation; the spec makes it a MUST of the ceremony, and the ops guidance routes the owner through DNS at that exact moment anyway (rotating zone credentials).

**Consequence of violation:** A revocation performed in the document but not reflected in `g=` is invisible to record-only verifiers — the revoked signer keeps minting acceptable certificates until the rotation is published (fail-open). Residuals after correct rotation are the stale-chain window and lineage forks under zone+insider attack (provable equivocation, surfaced) (see [security.md](./security.md#revocation-lag)).

### Zone Operators Publish Correctly

> **Assumption:** A domain owner can publish a DNSSEC-signed TXT record and keep its serial (`n`) monotonically increasing.

The replay ratchet ([dns-binding.md](./dns-binding.md)) depends on serial monotonicity being maintained by the _legitimate_ owner. A transient attacker who publishes an inflated serial poisons the ratchet, but the damage is bounded: the 5-minute skew deferral caps the attacker's lead, and fresh-beats-stale heals any verifier that sees one fresh owner chain (see [security.md](./security.md#ratchet-poisoning)).

**Consequence of violation:** Replay of superseded bindings, or — for fully offline verifiers only — a poisoned ratchet requiring the per-name manual "reset trust" action (mandated by the spec; not yet implemented).

### Signature Windows Are Short

> **Assumption:** RRSIG validity windows are on the order of days to weeks (root ≈ 2 weeks; zones typically 1–30 days).

This is why chain freshness is _graded_, not boolean: hard-rejecting expired chains would break offline gossip within weeks. Staleness is a risk signal, not a forgery signal.

## Time

### Rough Clocks Only

> **Assumption:** Client clocks are roughly correct (hours, not months, of drift).

Clocks are used to grade chain freshness and to sanity-check claimed issuance timestamps. No protocol step requires tight synchronization; verification itself is clock-free (signatures over canonical bytes).

**Consequence of violation:** Freshness grading is wrong — a client with a wildly fast clock sees everything as stale; a slow clock over-trusts expired windows. Never a forgery.

### No Expiration on Bindings

> **Assumption:** Bindings do not expire; revocation is an explicit act — revoking the signer's delegation inside the document (key compromise) or changing the TXT record (document migration).

Expiry is at odds with local-first operation. The trade-off is that staleness must be surfaced to users rather than enforced by the protocol.

## Network

### DNS May Be Unavailable

> **Assumption:** Clients are frequently offline or without DNS access.

Everything must degrade: offline introductions root as petnames and upgrade later; verified bindings gossip P2P as self-authenticating records; stale chains warn rather than fail.

### Resolution Is Observable

> **Assumption:** DNS lookups and certificate-endpoint fetches leak metadata to resolvers and networks.

DoH narrows this in browsers; native resolver traffic leaks. The certificate fetch is integrity-safe even over plain HTTP (the record is self-authenticating) but is not private.

## Storage

### Caches Confer No Authority

> **Assumption:** The binding cache may be corrupted, tampered with, or maliciously populated — and this must not matter.

Cache entries are self-authenticating (certificate + DNSSEC chain) and are re-verified from the baked-in KSK at use. Presence in the cache proves nothing.

**Consequence of violation:** None by design — this assumption exists so that its violation is harmless.

### Your Root Document Is Yours

> **Assumption:** The user's signed root document is written only by keys the user controls.

Petname edges live here; local malware with signing access can forge petnames. This is the one storage surface that _does_ carry authority.

**Consequence of violation:** Forged petname edges — equivalent to full local compromise.

## What We Don't Assume

| Non-Assumption | Handled By |
|----------------|------------|
| DNS is reachable | Petname fallback + gossiped certificates |
| Peers are honest | Records are self-authenticating; receiver re-verifies from own KSK |
| TXT records are fresh | Graded freshness (`fresh ✓ / stale ⚠ / invalid ✗`) |
| Caches are trustworthy | Re-verification at use; cache confers no authority |
| Clocks are synchronized | Verification is clock-free; time only grades freshness |
| Names are unambiguous to humans | Syntactic anchor disjointness + display-layer confusable detection |
| The onomancer server is honest | It serves signed records it cannot forge; servers hold no keys, so compromise is DoS/staleness only |
