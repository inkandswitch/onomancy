# Assumptions

This document lists the assumptions Onomancer makes about its environment. Violating these assumptions may lead to incorrect resolution, accepted forgeries, or unrecoverable trust state.

## Cryptography

### Ed25519 Unforgeability

> **Assumption:** Ed25519 signatures cannot be forged without the signing key.

Onomancer certificates, root document edges, and (transitively) the entire key-anchor identity model rest on this. There is no fallback algorithm at v0; `k=ed25519` in the TXT record leaves room for migration via a version bump.

**Consequence of violation:** Arbitrary identity forgery.

### Random Number Generation

> **Assumption:** Signing keys are generated from a cryptographically secure source.

`getrandom` on native platforms; `crypto.getRandomValues()` in browsers (via the `wasm_js` backend).

**Consequence of violation:** Predictable keys, identity takeover.

## Keyhive / Automerge

### Doc ID Is the Controlling Authority

> **Assumption:** A Keyhive root document ID _is_ an ed25519 verifying key, and that key is the controlling authority of the document — not merely derived from a one-time key.

> [!WARNING]
> This assumption is **unverified** (tracked in TODO). If key rotation does not preserve the doc ID, TXT records must point at current keys rather than doc IDs, which reshapes the binding record and the successor-key story in the certificate schema.

**Consequence of violation:** Bindings go stale on rotation; the "no identity migration" property (ADR-010) breaks.

## DNS / DNSSEC

### IANA Root KSK Integrity

> **Assumption:** The IANA root KSK is not compromised, and clients ship the correct one.

Exactly one KSK is baked in at a time. It rotates every few years — a deliberately slow trust anchor. A trust-anchor _set_ plus an RFC 5011-style rollover story is future work (tracked in TODO): stale clients must be able to validate chains signed under a newer KSK.

**Consequence of violation:** The entire DNS anchor is forgeable. Key anchors and petnames are unaffected.

### Zone Operators Publish Correctly

> **Assumption:** A domain owner can publish a DNSSEC-signed TXT record and keep its version monotonically increasing.

The replay ratchet ([dns-binding.md](./dns-binding.md)) depends on version monotonicity being maintained by the _legitimate_ owner. A transient attacker who publishes an absurdly high version poisons the ratchet — an accepted risk with a manual reset escape hatch (see [security.md](./security.md)).

**Consequence of violation:** Replay of superseded bindings, or a burned ratchet requiring manual reset.

### Signature Windows Are Short

> **Assumption:** RRSIG validity windows are on the order of days to weeks (root ≈ 2 weeks; zones typically 1–30 days).

This is why chain freshness is _graded_, not boolean: hard-rejecting expired chains would break offline gossip within weeks. Staleness is a risk signal, not a forgery signal.

## Time

### Rough Clocks Only

> **Assumption:** Client clocks are roughly correct (hours, not months, of drift).

Clocks are used to grade chain freshness and to sanity-check claimed issuance timestamps. No protocol step requires tight synchronization; verification itself is clock-free (signatures over canonical bytes).

**Consequence of violation:** Freshness grading is wrong — a client with a wildly fast clock sees everything as stale; a slow clock over-trusts expired windows. Never a forgery.

### No Expiration on Bindings

> **Assumption:** Bindings do not expire; revocation is an explicit act (swapping the TXT record's key).

Expiry is at odds with local-first operation. The trade-off is that staleness must be surfaced to users rather than enforced by the protocol.

## Network

### DNS May Be Unavailable

> **Assumption:** Clients are frequently offline or without DNS access.

Everything must degrade: offline introductions root as petnames and upgrade later; verified bindings gossip P2P as self-authenticating records; stale chains warn rather than fail.

### Resolution Is Observable

> **Assumption:** DNS lookups and `/.well-known/onomancy` fetches leak metadata to resolvers and networks.

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
| The onomancer server is honest | It serves signed records it cannot forge; the TXT key revokes it |
