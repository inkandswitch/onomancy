# Security

Threat model, mitigations, and accepted residual risks. Read alongside [assumptions.md](./assumptions.md).

## Assets

- _Identity bindings_ — name → key-anchor mappings (petnames, DNS bindings)
- _Your root document_ — the one signed artifact carrying your authority
- _The user's mental model_ — what a human believes a name refers to

## Adversaries

| Adversary                  | Capabilities                                                            |
|----------------------------|-------------------------------------------------------------------------|
| Network attacker           | Observe/modify/drop traffic; malicious resolver                         |
| Transient zone attacker    | Briefly controls a DNS zone (registrar compromise, expired-domain grab) |
| Malicious gossip peer      | Sends arbitrary records P2P                                             |
| Malicious onomancer server | Serves arbitrary bytes at `/.well-known/onomancy`                       |
| Local malware (limited)    | Reads/corrupts caches, but no signing-key access                        |
| Local malware (full)       | Signing-key access — out of scope, game over                            |

## Threats and Mitigations

| Threat                                               | Mitigation                                                                            | Residual                  |
|------------------------------------------------------|---------------------------------------------------------------------------------------|---------------------------|
| Near-miss phishing (`@bob` vs `@bob.co`)             | Grammar: petnames never under `@`; dotless must parse as key ([names.md](./names.md)) | homographs (below)        |
| Homograph/confusable DNS names (Cyrillic lookalikes) | Layered: A-label canonicalization + petname pinning + display-layer confusable detection (below) | attentive-user gap until display layer built |
| Key borrowing via TXT (attacker's zone points at victim's pubkey) | Certificate binds `hostname` and is signed by the key owner — no valid cert for the attacker's hostname can exist | none |
| Replay of superseded TXT record                      | Monotonic version ratchet                                                             | ratchet poisoning (below) |
| Stripped-record downgrade ("no binding here")        | NSEC/NSEC3 denial-of-existence validation (TODO)                                      | open until built          |
| Forged certificate                                   | Ed25519 sig + chain from baked-in KSK + TXT pubkey match                              | KSK compromise (below)    |
| Malicious gossip peer                                | Records are self-authenticating; receiver verifies from own KSK                       | DoS only                  |
| Malicious onomancer server                           | Serves signed records it cannot forge; TXT key swap revokes it                        | DoS only                  |
| Poisoned binding cache                               | Cache confers no authority; chain re-verified at use                                  | none by design            |
| Forged petname edges                                 | Only writable by your signing keys                                                    | full local compromise     |
| Replayed stale chain offline                         | Graded freshness: stale ⚠ is surfaced, not hidden                                     | user judgment             |

## Homographs and the Display Layer

DNS is ASCII on the wire: Unicode names (U-labels, `аррӏе.com`) are IDNA-encoded to A-labels (`xn--80ak6aa92e.com`) — see [names.md](./names.md#parse-rules). Each layer is attackable (or not) as follows:

| Layer | Form | Defense |
|-------|------|---------|
| Parse / store / compare / TXT lookup | A-label (ASCII) | IDNA canonicalization in the grammar — look-alikes are byte-wise distinct names |
| Chain validation | A-label | immune; DNSSEC signs ASCII all the way down |
| Display | U-label (Unicode) | confusable/mixed-script detection (UTS #39); fall back to raw `xn--` form when suspicious |

The crypto layer is immune; only the human is attackable. A homograph domain necessarily resolves to a _different key anchor_ — the attacker cannot produce a valid certificate under the victim's key for their own hostname (the key-borrowing row above).

### Petname Pinning Is the Structural Defense

Once a user pins `~/apple` to a key, the look-alike domain resolves to a different key and divergence surfaces mechanically ([resolution.md](./resolution.md#petname-store)) — the comparison a user would never do visually is done by the machine. Display-layer confusable detection is a second line for first-contact cases.

### Why Not Name Fingerprints

Displaying a hash of the name was considered and rejected as a mechanism: a fingerprint only helps if the user holds a reference to compare against, which first contact lacks, and SSH/PGP experience shows humans don't compare fingerprints. The key anchor is already the canonical, collision-free differentiator — a name-hash would be a second identifier strictly weaker than the identity itself. Visual hashes _of the key_ (identicon/randomart) are acceptable as UI garnish, and side-channel confirmation ("read me the end of my key") falls out of the QR/gossip intro carrying the key anchor — but the security boundary is pinning, not display.

## Accepted Risks

### Ratchet Poisoning

A transient zone attacker publishes an absurdly high TXT version (e.g. `v=2^60`), burning the monotonic ratchet even after the legitimate owner recovers the zone — the real owner can no longer publish an acceptable version.

_Accepted_ (ADR-011 §1). Mitigation is a per-name manual "reset trust" action. Revisit if it bites in practice. Note the same mechanism means domain re-registration works for legitimate new owners: a higher version simply wins.

### Domain Re-Registration

No mechanism distinguishes a legitimate new domain owner from an attacker who acquired the domain. This is inherent to rooting in DNS: the zone _is_ the authority. Users who need stronger continuity should pin the key anchor (petname edge) rather than trusting the DNS spelling — divergence then surfaces as a re-pin event ([resolution.md](./resolution.md#petname-store)).

### Stale Chains Offline

Offline peers accept once-valid (stale ⚠) chains by policy. An attacker replaying a chain for a since-revoked binding wins until the victim gets connectivity. Bounded by RRSIG windows (days–weeks) and surfaced in the UI.

## Trust-Anchor Compromise

| Compromise               | Blast radius                                                                                                                              |
|--------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| IANA root KSK            | All DNS anchors forgeable. Key anchors and petnames unaffected — the system degrades to petnames + keys, which is the offline mode anyway |
| Zone key (one domain)    | That domain's binding forgeable until owner rotates; ratchet limits replay                                                                |
| A user's signing key     | That user's root doc + petnames forgeable; successor-key statement in the certificate schema is the (open) recovery story                 |
| Baked-in KSK is outdated | Cannot validate new chains: availability failure, not forgery. RFC 5011-style rollover is future work                                     |

## Privacy

Resolution leaks metadata; verification does not require trust but does require _observation_:

- DNS lookups reveal which names you resolve — DoH narrows this in wasm/browsers; the native hickory path leaks to the configured resolver.
- The `/.well-known/onomancy` fetch reveals interest to the server and network. It is integrity-safe over plain HTTP (the record is self-authenticating) but not private.
- P2P gossip reveals your binding set to peers you gossip with.

No mitigation at v0 beyond DoH; noted as a known property.

## What the Design Refuses to Do

- _No precedence rules between anchors_ — ambiguity is a parse error, never a lookup-order decision ([names.md](./names.md#rejected-alternative-one-spelling-precedence-rules))
- _No authority in caches_ — nothing trusted can be planted in unsigned local state
- _No borrowed authority in your root doc_ — you never sign attestations about DNS you can't back ([anchors.md](./anchors.md#consequence-1-dns-bindings-are-not-edges-in-your-root-doc))
- _No expiration_ — revocation is explicit; freshness is advisory
