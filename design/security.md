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
| Malicious onomancer server | Serves arbitrary bytes at its certificate endpoint                       |
| Local malware (limited)    | Reads/corrupts caches, but no signing-key access                        |
| Local malware (full)       | Signing-key access — out of scope, game over                            |

## Threats and Mitigations

| Threat                                               | Mitigation                                                                            | Residual                  |
|------------------------------------------------------|---------------------------------------------------------------------------------------|---------------------------|
| Near-miss phishing (`@bob` vs `@bob.co`)             | Grammar: petnames never under `@`; dotless must parse as key ([names.md](./names.md)) | homographs (below)        |
| Homograph/confusable DNS names (Cyrillic lookalikes) | Layered: A-label canonicalization + petname pinning + display-layer confusable detection (below) | attentive-user gap until display layer built |
| Key borrowing via TXT (attacker's zone points at victim's pubkey) | Certificate binds `hostname` and is signed by the key owner — no valid cert for the attacker's hostname can exist | none |
| Replay of superseded TXT record                      | Serial ratchet (stale must exceed; fresh may reset, surfaced)                         | ratchet poisoning (below) |
| Stripped-record downgrade ("no binding here")        | Absence is never provable at v0: a missing record is always a possible downgrade, never "no binding" — fails toward retention | closed by doctrine |
| Forged certificate                                   | Ed25519 sig + chain from baked-in KSK + TXT pubkey match                              | KSK compromise (below)    |
| Malicious gossip peer                                | Records are self-authenticating; receiver verifies from own KSK                       | DoS only                  |
| Malicious onomancer server                           | Serves signed records it cannot forge; delegation revocation cuts it off    | DoS only                  |
| Poisoned binding cache                               | Cache confers no authority; chain re-verified at use                                  | none by design            |
| Forged petname edges                                 | Only writable by your signing keys                                                    | full local compromise     |
| Replayed stale chain offline                         | Graded freshness: stale ⚠ is surfaced, not hidden                                     | user judgment             |
| Revoked signer keeps minting certs                   | Generation rotation: `g=` no longer attests their chain's chokepoint; fresh chains reject | stale-chain window (below) |
| Revoked insider who also regains zone control        | Rewinds `g=` — provable via generation lineage (ratchet + equivocation surfacing)       | lineage forks (below)     |
| KSK rolls/revoked while client offline               | Trust-anchor set + RFC 5011 rollover (future work); app-update cadence at v0          | offline anchor rot (below) |

## Homographs and the Display Layer

DNS is ASCII on the wire: Unicode names (U-labels, `аррӏе.com`) are IDNA-encoded to A-labels (`xn--80ak6aa92e.com`) — see [names.md](./names.md#parse-rules). Each layer is attackable (or not) as follows:

| Layer | Form | Defense |
|-------|------|---------|
| Parse / store / compare / TXT lookup | A-label (ASCII) | IDNA canonicalization in the grammar — look-alikes are byte-wise distinct names |
| Chain validation | A-label | immune; DNSSEC signs ASCII all the way down |
| Display | U-label (Unicode) | confusable/mixed-script detection (UTS #39); fall back to raw `xn--` form when suspicious |

The crypto layer is immune; only the human is attackable. A homograph domain necessarily resolves to a _different document ID_ — the attacker cannot produce a valid certificate under the victim's key for their own hostname (the key-borrowing row above).

### Petname Pinning Is the Structural Defense

Once a user pins `~/apple` to a key, the look-alike domain resolves to a different key and divergence surfaces mechanically ([resolution.md](./resolution.md#petname-store)) — the comparison a user would never do visually is done by the machine. Display-layer confusable detection is a second line for first-contact cases.

The same treatment covers _sigil-shaped segments_: `@foo.bar` is a legal, grammatically inert path segment (labels are arbitrary strings), but rendered mid-path it can masquerade as a DNS anchor (`~/bank/@wellsfargo.com/…`). Confusable detection SHOULD flag anchor-sigil-shaped segments when rendering full paths — the sigil confers trust only at position zero.

### Why Not Name Fingerprints

Displaying a hash of the name was considered and rejected as a mechanism: a fingerprint only helps if the user holds a reference to compare against, which first contact lacks, and SSH/PGP experience shows humans don't compare fingerprints. The document ID is already the canonical, collision-free differentiator — a name-hash would be a second identifier strictly weaker than the identity itself. Visual hashes _of the key_ (identicon/randomart) are acceptable as UI garnish, and side-channel confirmation ("read me the end of my key") falls out of the QR/gossip intro carrying the document ID — but the security boundary is pinning, not display.

## Accepted Risks

### Ratchet Poisoning

A transient zone attacker publishes an absurdly high TXT serial (e.g. `n=2^60`), trying to burn the monotonic ratchet past the legitimate owner's reach. Two mechanisms bound this:

1. _Serial-as-timestamp with 5-minute skew_: serials reading more than 5 minutes in the future are deferred, so the attacker can advance the ratchet at most ~5 minutes past wall-clock — honest serials (`max(now_ms, last+1)`) outgrow the poison within the skew window.
2. _Fresh-beats-stale_: a record carried by a fresh DNSSEC chain may lower the ratchet (surfaced as a binding change, never silent). Minting a fresh chain requires current zone control — exactly what the transient attacker lost — so one fresh owner chain heals any verifier immediately.

_Residual (accepted)_: a fully offline verifier that accepted poison before the owner recovered has no automatic path — the escape hatch remains a per-name manual "reset trust" action. Note the ratchet's direction also means domain re-registration works for legitimate new owners: a higher serial simply wins, and fresh chains carry the day.

### Domain Re-Registration and Spelling Capture

No mechanism distinguishes a legitimate new domain owner from an attacker who acquired the domain. This is inherent to rooting in DNS: the zone _is_ the authority. What the design controls is what the capture is _worth_:

| Relationship to the name | Outcome under capture |
|--------------------------|----------------------|
| Pinned to the document ID (petname edge, cached binding) | Safe — edges hold keys; divergence surfaces loudly |
| The identity's data, delegations, collaborators | Untouched — the identity layer never depended on the name |
| Prior contact who carelessly re-pins through the warning | Captured — the tripwire needs the human not to slam it |
| First contact via the bare string during the capture window | Captured — for them, the attacker verifiably _is_ the name |

Mitigations, layered: successor statements make hostile `p=` changes structurally incapable of looking routine _to any verifier with history_ — no proof of continuity can exist without the old document's keys ([certificate.md](./certificate.md)); proofs are relative evidence, so on first contact they confer nothing (two attacker documents vouching for each other is not continuity — [the spec's relativity rule](../specs/anchoring/dns-anchor.md#proofs-are-relative-evidence)), while long-offline verifiers can bridge multi-migration gaps through pooled superseded certificates ([bridging](../specs/anchoring/dns-anchor.md#bridging-history-gaps)); unproven changes are graded by **tenure** — the displaced binding's accumulated window evidence in the verifier's own store, history a capture-era newcomer can neither fake nor remove — so displacing a long-established binding draws the hostile-suspect tier automatically; introductions SHOULD carry the document ID with the name as display metadata (the QR/gossip payload already does — the norm extends to rendered contexts: put the key's QR next to the string on the slide); and one identity MAY bind several names, so capture of one registrar account becomes a detectable inconsistency across previously-agreeing spellings rather than a clean story. The floor is unchanged — a memorable string as sole introduction is capturable in any DNS-rooted system — but every layer above the floor either survives or screams.

### Unpoisoning After Zone Recovery

There is no recall mechanism, deliberately — a recall oracle would break offline verification. Each cache layer decays or heals on its own clock; the owner's job is to publish fast and push through every hint channel:

| Layer | Poison lifetime | Healing mechanism |
|-------|----------------|-------------------|
| Resolver DNS caches | ≤ TTL | Ages out; publish `_onomancy` records with low TTL (~5–15 min) |
| Serial ratchet | ≤ ~5 min of lead | Skew deferral caps the attacker's serial; `max(now_ms, last+1)` outbids it almost immediately |
| Online binding caches | Until next contact with any fresh owner artifact | Fresh-beats-stale resets any verifier it reaches |
| Circulating gossiped cert | ≤ its RRSIG window (days–weeks) | The attacker cannot refresh the chain post-eviction; their record decays to stale ⚠ and never returns to fresh |
| Fully offline caches | Until contact | Honest residual; heals on first sync with anyone who has seen the recovery |
| Pins made to the attacker's document during the window | Until the owner's record is seen | Divergence fires; re-pin prompt |

The attacker's certificate cannot be revoked by the owner — it is signed by the _attacker's_ document's delegation graph, outside the owner's jurisdiction. It dies of staleness instead.

### Stale Chains Offline

Offline peers accept once-valid (stale ⚠) chains by policy. An attacker replaying a chain for a since-revoked binding wins until the victim gets connectivity. Bounded by RRSIG windows (days–weeks) and surfaced in the UI.

### Staleness Saturation

Stale ⚠ was designed as an exceptional risk signal, but offline it is the _steady state_: chain windows are the ∩ of RRSIG windows (≤ ≈ 2 weeks via the root), so every record in a gossip-only mesh decays to ⚠ within days — and a warning that is always on protects nothing. Worse, several defenses terminate in "surfaced to the user" (binding changes, downward ratchet moves, unproven `p=` changes, lineage forks), and they all draw on one attention budget that ambient staleness would drain — in exactly the offline population where the ratchet-poisoning residual lives. Three layers keep the signal alive:

| Layer | Rule |
|-------|------|
| Events vs states | Staleness is a passive badge, never a prompt; interruptive UX is reserved for events — the tripwires keep their contrast |
| Age tiers | Grade staleness by lapse magnitude, and against the local baseline: staler-than-the-mesh-median is the anomaly, not ⚠ itself |
| Chain couriers | Chain refresh is keyless (the chain is attached unsigned), so one connected member re-fetching and gossiping chains heals a whole mesh — evidence union upgrades entries in place |

The last is the structural one: the unsigned attached region makes freshness a _community good_ — no owner action, no cold keys, just bytes anyone can courier in from the trailhead. Normative wording lives in [the dns-anchor spec](../specs/anchoring/dns-anchor.md#staleness-in-practice).

## Trust-Anchor Compromise

| Compromise               | Blast radius                                                                                                                              |
|--------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| IANA root KSK            | All DNS anchors forgeable. Doc anchors and petnames unaffected — the system degrades to petnames + keys, which is the offline mode anyway |
| Zone key (one domain)    | That domain's binding forgeable until owner rotates; ratchet limits replay                                                                |
| A user's signing key     | That user's edits forgeable until the key's delegation is revoked inside the doc; the doc ID — and every name pointing at it — survives, since authority lives in the delegation graph, not a held root key |
| Baked-in KSK is outdated | Cannot validate new chains: availability failure, not forgery. RFC 5011-style rollover is future work                                     |

## Revocation Lag

Revocation knowledge is local-first — there is no oracle (requiring one would break offline verification, so it was rejected by design). The [generation key](../specs/anchoring/dns-anchor.md#generation-key) bounds the damage without a list: revoking a signer rotates the attested chokepoint, so their certificates fail against any **fresh** chain immediately. What remains:

- _Stale-chain window_: verifiers on stale ⚠ chains grade the generation check provisional — the revoked signer's certificates linger for at most the RRSIG window (days–weeks) of chains captured before rotation, which the attacker cannot refresh. Bounded by time, not by sync luck.
- _Rewind residual_: a revoked insider who **also regains zone control** can republish the old `g=` and resurrect their chain — indistinguishable from legitimate rotation to verifiers without history. Generation lineage closes the silent version (rotation statements are REQUIRED at rotation; verifiers ratchet and treat competing statements as provable equivocation, surfaced rather than resolved). The residual shrinks to: a forked lineage under zone+insider attack warns instead of silently deciding, and recovery follows the ordinary unpoisoning path.
- _Fork blast radius is fork-local_: a fork suspends the rewind rejection (D12) only for its fork-implicated suffix — the single-headed **protected prefix** below the fork point stays fully armed, so one equivocation cannot buy rewind immunity for the document's whole history. Repair is an ordinary generation rotation converging the heads (`g=` only — never escalating to `p=` succession, which would hand the insider a forced-migration kill switch); the historical fork stays permanently surfaced. See the spec's [Heads and the Protected Prefix](../specs/anchoring/dns-anchor.md#heads-and-the-protected-prefix).

The trust statement stays honest either way ("not revoked _as far as the verifier currently knows_"), and online clients SHOULD still opportunistically re-fetch or sync when acting on a stale ⚠ verdict.

## Offline Anchor Rot

A client offline (or gossip-only) across a root-KSK rollover-plus-revocation cannot learn of it, by construction — and if the old KSK was _compromised_, the attacker mints fresh chains that the stale client accepts; graded freshness does not help, because freshness measures signature windows, not key legitimacy. Calibration: root rollovers are multi-year events (one rollover in 2018, one ceremonial revocation in 2019, ever), so app-update cadence realistically outruns the anchor at v0. The residual is real only for long-lived, unattended, un-updatable deployments; RFC 5011 tracking is the eventual mitigation for online clients, and none exists for fully-offline ones. Because rollovers overlap (successor pre-published long before it signs), clients shipped during an overlap should carry both KSKs so that chains gossiped across the boundary verify on either side.

## Privacy

Resolution leaks metadata; verification does not require trust but does require _observation_. The exposure is per-binding-refresh, not per-resolution:

| Event | DNS queries | Who learns what |
|-------|-------------|-----------------|
| Resolve `~/bob/pics` | none | nobody — local reads over synced replicas |
| Resolve `automerge:…/foo` | none | nobody beyond existing sync peers |
| Resolve `@name/…` with cached binding | none | nobody — chain re-verified locally |
| Receive a binding via gossip | none | the gossiping peer (who already had it) |
| First fetch / stale-refresh of a binding | one `_onomancy` lookup + one endpoint fetch | resolver, network, and server learn interest in that _name_ |

- DNS lookups reveal which names you refresh — DoH narrows the on-path observer in wasm/browsers (while shifting that visibility to the DoH resolver); the host hickory path leaks to the configured resolver.
- The certificate-endpoint fetch reveals interest to the server and network. It is integrity-safe over plain HTTP (the record is self-authenticating) but not private.
- P2P gossip reveals your binding set to peers you gossip with.

No mitigation at v0 beyond DoH; noted as a known property. Record-first verification is itself the main structural mitigation: after the first fetch there is no query stream to observe.

## Transparency Is Advisory, Forever

Verification MUST never depend on any log, witness, or observation service — the same "hints carry no authority" principle, applied to history instead of transport. CT-style enforcement (verifiers reject unlogged certificates) is rejected outright: it breaks record-first offline verification, makes log operators a liveness and governance dependency, and creates a globally enumerable roster of participants. What transparency machinery MAY do, as advisory reputation only: owner self-monitoring (watch your own names' DNS and endpoints — recommended practice, needs no protocol support), and eventually gossip witnessing, where peers exchange observed-binding attestations to give first-contact verifiers the one signal an attacker cannot mint: tenure. Any public log that emerges is a view over gossip, never an authority gossip must feed.

## Operational Guidance for Publishers

The protocol cannot outrun a hijacked registrar login. Boring hygiene carries real weight:

| Practice | Why |
|----------|-----|
| Registry lock + hardened registrar account (real 2FA) | Zone control is the whole DNS-anchor attack surface |
| DNSSEC on (mandatory anyway) | Without it there is no binding at all |
| Low TTL (~5–15 min) on `_onomancy` records | Shrinks the resolver-cache poison window |
| Two or more cold admin keys at document creation | Losing one is a revocation, not a catastrophe; total admin loss forces `p=` migration (see [anchors.md](./anchors.md#the-mutual-backstop)) |
| Revocation is one ceremony: revoke → rotate the generation → publish new `g=` → rotate zone credentials → re-attach chains on mirrors | The `g=` publication is what makes the revocation verifier-visible; forgetting it fails open. Rotation statements (required at rotation) make rewinds provable |
| Self-monitor your own names | Converts capture from quiet theft to an incident within minutes |
| Introduce with key + name together | First contact pins the key; the string is decoration |

## What the Design Refuses to Do

- _No precedence rules between anchors_ — ambiguity is a parse error, never a lookup-order decision ([names.md](./names.md#rejected-alternative-one-spelling-precedence-rules))
- _No authority in caches_ — nothing trusted can be planted in unsigned local state
- _No borrowed authority in your root doc_ — you never sign attestations about DNS you can't back ([anchors.md](./anchors.md#consequence-1-dns-bindings-are-not-edges-in-your-root-doc))
- _No expiration_ — revocation is explicit; freshness is advisory

## Leaked generation keys

The signing bar (dns-anchor §Who Signs) is the _delegating hop_, so a root-granted generation key can sign certificates. What a leaked current generation key enables — and does not:

| Capability | Outcome |
|------------|---------|
| Rebind the hostname | No — `p=`/`g=` are zone-attested |
| Forge document content | No — writes need Edit on the doc graph |
| Forge a rotation to an attacker key | No — the attacker key has no admin-hop delegation |
| Sign certificates (attacker heads, `issued_at` games) | Yes — until rotation |

Rotation heals fully: post-rotation the attacker's carriage proves only the retired `g=`, so D10 rejects fresh records, and grafting the owner's new carriage fails (it terminates at the wrong key). Since a leaked generation key already demands immediate rotation, its cert-signing ability changes neither the response nor the blast radius. Admins hold the lineage pen but never the zone: rotation takes effect only when DNS control moves `g=`.
