# Limitations

What Onomancy does **not** fix. Naming systems attract magical thinking — "cryptographically verified" reads as "safe" — so this document states the boundaries plainly. Every entry here is inherent to the problem or deliberately out of scope, not an oversight; where a partial mitigation exists, it is linked, and its partiality is stated.

## Phishing Is Not Solved

Onomancy removes specific phishing _mechanisms_ — it does not and cannot make users unphishable.

| What the design removes | What remains |
|-------------------------|--------------|
| Near-miss anchor confusion (`@bob` vs `@bob.co`): dotless `@` names are parse errors, petnames never appear under `@` | A _plausible-looking wrong name_ still works on humans: `@expede-wtf.com`, `@expede.wtf.evil.example` are distinct valid names an attacker can register and legitimately bind |
| Silent identity swaps behind a known name: divergence detection, successor statements, tenure-graded surfacing ([security.md](./security.md#domain-re-registration-and-spelling-capture)) | The user who clicks through the warning. Surfacing is a tripwire, not a wall |
| Homograph names resolving to the victim's identity: a look-alike domain necessarily binds a _different_ document; no valid certificate can borrow the victim's key ([security.md](./security.md#homographs-and-the-display-layer)) | The human reading `аррӏе.com` as `apple.com` before any pinning exists. Display-layer confusable detection narrows this; nothing closes it |
| Trust accumulating on a capturable string: pins hold keys | Only for people who pin. First contact via a bare name string trusts whoever holds the zone at that moment |

The honest summary: Onomancy makes impersonating an _established relationship_ cryptographically hard, and does approximately nothing about deceiving someone who has no relationship yet. Social engineering — "this is my new account, re-pin me", "read me the code on your screen" — passes through every layer of this design untouched, as it does every other.

## First Contact Is Trust-on-First-Use

A verifier meeting a name for the first time has no history: whatever the anchor attests _right now_ is all there is. During a zone compromise, that means the attacker. Petname pinning converts first contact into durable trust, and future gossip witnessing may lend borrowed history (tenure), but the first introduction is TOFU — same epistemics as SSH, stated rather than hidden.

## DNS Anchors Inherit DNS's Politics

`@` names are verifiable _modulo the DNS power structure_: registrars, registries, ICANN, and the jurisdictions they answer to. Seizure, coercion, and re-registration are legitimate operations of that system and produce cryptographically valid bindings ([the GNS comparison](./comparisons/GNS.md#the-dnssec-disagreement) takes the opposite bet). The design's answer is containment, not prevention: identity never lives in the name, the other two anchor families owe DNS nothing, and capture is loud and recoverable — but a user whose social identity _is_ their domain string has bet that string on their registrar account.

## Key Custody Is the User's Problem

Self-certifying identity moves the root of trust from institutions to key material. That is the point — and it means there is no password reset. Full local compromise (signing-key access) is out of scope: game over. Total loss of all admin keys forces identity migration via the DNS backstop ([anchors.md](./anchors.md#the-mutual-backstop)); loss of all keys _and_ all replicas is unrecoverable, and E2EE means nobody — including us — can change that. Plural cold keys and social-recovery delegations are guidance, not enforcement.

## Availability Is Best-Effort

No mechanism here makes anyone serve you bytes. Every retrieval path is an unauthoritative hint; a name whose record you cannot obtain does not resolve, and `Partial` results are the designed norm under partition, not an error state. Verification never degrades — but liveness is explicitly not guaranteed by the protocol.

## Privacy Is Bounded, Not Engineered

Resolution metadata leaks are documented, not eliminated ([security.md](./security.md#privacy)): binding fetches reveal interest to resolvers and servers, gossip reveals your binding set to peers, and namestore contents are plaintext to everyone you sync with. There is no query privacy in the GNS sense and no anonymity set anywhere. Participation in the DNS anchor is publicly observable by construction (`_onomancy` exists or it doesn't).

## Offline Has Irreducible Residuals

The local-first commitments buy specific, permanent gaps: stale-chain acceptance is policy (bounded and surfaced, not closed); revocations and successor statements arrive at gossip speed, so a revoked key keeps verifying until the news does ([security.md](./security.md#revocation-lag)); a client offline across a root-KSK compromise has a rotted trust anchor and no way to know ([security.md](./security.md#offline-anchor-rot)); and a fully offline verifier that accepted ratchet poison heals only by manual reset.

## No Global Namespace Arbitration

Onomancy does not decide who _deserves_ a name. Two strangers can both be `~/bob` to different people (by design); whoever controls a domain controls its `@` names (DNS's rule, not ours); and nothing prevents squatting, resale, or dispute except the DNS system's own processes. Zooko's triangle is navigated, not defeated.

## What This Document Is For

Every system in this space eventually publishes claims like "phishing-proof naming." When this one is tempted, the table above is the pre-registered rebuttal. The design's real claim is narrower and defensible: _trust, once established, is cryptographically durable and survives the loss of any single anchor._ Establishing it in the first place remains a human problem.
