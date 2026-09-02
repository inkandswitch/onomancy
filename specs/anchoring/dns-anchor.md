# Onomancy DNS Anchoring Specification
## Version 0.1.0

## Dependencies
[Dependencies]: #dependencies

- [Onomancy Name Grammar]
- [Onomancy Path Resolution]
- [Serialization] — byte layouts for the certificate and TXT record
- [Keyhive]

## Language
[Language]: #language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14] when, and only when, they appear in all capitals, as shown here.

# Abstract
[Abstract]: #abstract

This specification defines how a name spelled `@<dns-name>[/segments]` is rooted: the `@` grammar, the DNSSEC-protected TXT binding record, the Onomancy certificate, and the local verification that turns untrusted bytes into a verified binding `hostname → root document`. Once the root document is established, resolution proceeds per [Onomancy Path Resolution] and this specification imposes nothing further.

# Introduction
[Introduction]: #introduction

DNS names are the memorable corner of [Zooko's triangle]: globally meaningful, human-readable, and — with DNSSEC — verifiable from a single, slow-moving trust anchor. Onomancy layers DNS names over self-certifying document identities so that binding a domain adds a _memorable spelling for an existing identity_, never a new identity.

The binding is **record-first**: everything needed to verify it travels together, so a binding fetched from the owner's server, a local cache, or a Bluetooth peer at a field campout verifies identically, with no trust in the party that relayed it.

## Trust Statement
[Trust Statement]: #trust-statement

A verified DNS binding proves exactly this:

> The name `<hostname>`, as attested by a DNSSEC chain from the IANA root KSK **during the chain's signature window**, designated the document whose ID appears in the certificate, and a key — delegated by that document, and **not revoked as far as the verifier currently knows** — signed the certificate.

Both clauses are graded, not absolute. The first proves nothing about the current instant (see [Graded Freshness]). The second is bounded by the verifier's knowledge: revocations propagate via document sync and gossip, so a revoked-but-not-yet-known signer's certificates still verify until the revocation arrives (see [Chain Validation]). It proves nothing about the name owner's intentions, and nothing about any other name.

# Grammar
[Grammar]: #grammar

``` abnf
dns-name-ref = "@" dns-name *( "/" segment )
dns-name     = label 1*( "." label )   ; ≥ one dot, post-normalization
```

Segments follow the shared [Onomancy Name Grammar]; this section defines the `dns-name` production it references.

- `@` means DNS and nothing else. There is no fallback to any other anchor family.
- Parsers MUST reject dotless `@` names as flat parse errors (no key-parse fallback; [ICANN SAC053] alignment). This deletes the `@bob` vs `@bob.co` near-miss phishing class rather than mitigating it.
- Parsers MUST reject IP literals (v4 and v6) under `@`.
- Names MUST be normalized at parse time: lowercase, trailing dot stripped, [IDNA] U-labels converted to A-labels. The parser, stores, comparisons, and chain validation operate on **A-labels only**; U-labels exist purely at the display layer.
- DNS length limits apply: 253 octets total, 63 per label.
- `#` is reserved in segments, as in every family; names carry no version pins.

# TXT Binding Record
[TXT Binding Record]: #txt-binding-record

The owner of a name publishes:

``` zone
_onomancy.<name>.  IN TXT  "v=ONO0;k=ed25519;n=<serial>;g=<base64 generation key>;p=<base64 doc ID>"
```

`<name>` is the A-label domain from the `@` anchor, exactly as parsed — it need NOT be a zone apex. `@blog.expede.wtf` binds at `_onomancy.blog.expede.wtf` even when `blog.expede.wtf` is just a name inside the `expede.wtf` zone. Distinct names carry distinct bindings (and thus distinct identities), regardless of how they group into zones; the DNSSEC chain covers whatever zone the owner name falls in.

| Field | Requirement |
|-------|-------------|
| `v` | Format tag. MUST be `ONO0` for the grammar defined here; a record with an unrecognized `ONO`-prefixed tag MUST be skipped, and a TXT record without a `v=ONO…` tag is not an onomancy record at all (see [Format Evolution]) |
| `k` | MUST be `ed25519` at `v=ONO0`; unknown algorithms MUST cause that record to be rejected — per-record, siblings still processed; unlike skipping an unknown `ONO` tag, the rejection SHOULD be surfaced (see D5) |
| `n` | Serial: a non-negative integer, monotonically increasing across re-bindings (see [Serial Ratchet]) |
| `g` | MUST be the base64 encoding of the 32-byte generation key: the delegation-chain chokepoint that certificate chains must pass through (see [Generation Key]) |
| `p` | MUST be the base64 encoding of the 32-byte root document ID (an ed25519 verifying key) |

- The record MUST live at the `_onomancy` underscore service label ([RFC 8552] convention) directly under `<name>`.
- The record carries **no expiration**. Revocation happens inside the document's delegation graph (see [Chain Validation]); changing `p=` is reserved for genuine document migration and MUST be accompanied by a serial bump.
- If multiple parseable records are present, the resolver MUST select by the zone-state key ([Comparing Records Offline]) — highest `n` within a chain window, later window end across them; overlap is expected during migration.

## Format Evolution
[Format Evolution]: #format-evolution

`v` is a self-identifying format tag (like `v=DKIM1`), not a counter: it changes only when this grammar changes. Within a known tag, parsing is strict — unknown fields, reordered fields, or malformed values MUST reject that record. A record with an `ONO`-prefixed tag the verifier does not recognize is a message to newer software: it MUST be skipped, and MUST NOT poison processing of other records in the RRset. A TXT record at the label without a `v=ONO…` tag is foreign and MUST be ignored entirely. Only if no record parses does the verifier report an unusable binding.

This is the migration mechanism: a publisher moving to a future `v=ONO1` dual-publishes `ONO0` and `ONO1` records in the same RRset. Old verifiers keep working from the `ONO0` record; new verifiers prefer the highest tag they understand, then the highest `n` within it. No new DNS label is ever needed.

## Serial Ratchet
[Serial Ratchet]: #serial-ratchet

`n` is the anti-replay ratchet. To any verifier it is an opaque `u64`; publishers are RECOMMENDED to choose it as milliseconds since the Unix epoch, computed as `max(now_ms, last_n + 1)` — monotone by construction, wall-clock-tracking, and collision-free across a publisher's devices when seeded from the highest serial seen.

The `max` is load-bearing, not tidiness. A bare clock read fails two ways, and both are silent at **both** ends of the wire:

- Two records minted in the same millisecond **tie**. A tie at the top serial naming different documents is `contested` (rule 2), so a publisher that races itself across two devices or two tabs reports _its own name as misconfigured_ to every visitor.
- A clock that steps backwards mints a record that **loses to the one it supersedes**, leaving the old binding live. Nothing looks wrong from either side: the losing record is well-formed, the zone is correctly signed, and the verifier is behaving exactly as specified. Once a ratchet is in play a correct verifier refuses the new record as a replay — so the publisher sees a valid record rejected and the verifier sees an attack, and neither is mistaken.

The bump is also half of a defence whose other half lives elsewhere. The poisoning bound holds because honest serials outgrow planted ones within the skew window, which is only true while they grow at roughly clock rate; a publisher whose serials do not track the clock cannot overtake a serial planted five minutes ahead on schedule. A publisher-side shortcut therefore weakens a verifier-side defence, in a different document, at a different layer — which is why the rule appears here rather than only in a publisher's own notes.

Seed the floor from the **record body**, not from the hostname: a serial orders records, and the binding has not changed unless `g=` or `p=` has. Keying by name re-mints on every read, which also makes the printed record shift under anyone mid-copy into a DNS console.

Ratchet rules:

1. There is exactly **one** definition of the ratchet: the **effective serial** is the serial of the ladder-winning record for the hostname ([Binding Cache spec], derivation) — a derived quantity, which implementations MAY memoize as a counter. Records that derive as pending, contested, or deferred contribute nothing — otherwise gossiping unacceptable records would poison the ratchet without any zone control.
2. A record of the **same document** whose zone-state key `(window_end, serial, issued_at)` does not exceed the accepted record's is a **replay**: it MUST be dominated — it contributes to no derivation output. ("Rejected" means dominated at derivation, never refused at the store: union sync stores any bytes; domination is what makes them inert. A chain refresh carries a later `window_end` and therefore wins — refreshes are never replays.)
3. A record whose chain is **fresh ✓** (window covers now) wins rung 0 outright, including with a _lower_ serial than the previous winner. A downward move of the effective serial is a **ratchet-reset event** and MUST be surfaced, never applied silently; if the record also attests a different document, it is additionally a surfaced binding change. This is deterministic, not discretionary — the ladder decides, the surfacing is the obligation. It is sound because minting a fresh chain requires current control of the zone — exactly the capability a transient attacker has lost.
4. A record whose serial reads more than **5 minutes** in the future (interpreted as milliseconds since epoch) is **deferred**: not considered by the derivation until the verifier's clock reaches it — never treated as malformed, never allowed to poison processing of other records. **Deferral precedes everything and applies regardless of chain freshness**: rule 3 operates only on serials within the skew bound, else a fresh far-future serial would burn the ratchet past wall-clock and the ~5-minute poisoning bound would hold only on the stale path.

```
seen n=3  →  stale record n=2 arrives          →  reject (replay)
          →  stale record n=4 arrives          →  accept, ratchet to 4
          →  fresh record n=1 arrives          →  accept, ratchet to 1,
                                                  surface serial regression
          →  record n ≈ now + 20 min arrives   →  defer, retry later
```

Together, rules 3 and 4 bound ratchet poisoning: a transient zone attacker can advance the ratchet at most ~5 minutes past wall-clock, honest serials outgrow that within the skew window, and any verifier that sees one fresh owner chain heals immediately regardless.

> [!WARNING]
> Residual risk: a **fully offline** verifier (no fresh chains, no clock confidence) that accepted a poisoned serial has no automatic recovery. Implementations MUST provide a per-name manual "reset trust" action as the escape hatch, and MUST NOT reset automatically.

The 5-minute bound is a sanity check, not a validity semantic: records are never "not yet valid" in a trust sense, and verifier clocks remain advisory (the same epistemic status as `issued_at`). A strict not-before gate was considered and rejected — it would make verifier clocks a load-bearing attack surface and turn clock skew into hard verification failures, against the local-first grain.

## Generation Key
[Generation Key]: #generation-key

The certificate's delegation chain proves the signer was authorized _at issuance_; revocation knowledge otherwise travels only by document sync. Without a recency coupling, a revoked admin holding an old key and its once-valid chain could keep minting verifying certificates — and successor statements — for any verifier that never syncs the document. The generation key closes that gap with a single attested chokepoint:

```
doc ──▶ admin ──▶ Gₙ ──▶ {alice, bob, carol}
                  └─ the TXT g= names this key
```

- The publisher designates one key in the delegation graph as the current **generation key** and attests it in `g=`. The rule is **path membership**, not topology: the attested key MUST appear as an **authority-carrying hop** in the certificate's delegation chain, at any depth — that is, a delegation on the root → signer path is _signed by_ the attested key, or the attested key is the terminal delegatee (the `signer` itself). Mere appearance of the key bytes elsewhere in a delegation record does NOT satisfy the check: what is attested is that the generation key _vouched for_ the signer's authority, not that it was mentioned. A solo publisher MAY attest their admin key directly (`doc → admin`, chain trivially passes through); an organization MAY interpose a dedicated generation key over its cert-signing members.
- **Grants are free**: delegating a new signer under Gₙ changes nothing in DNS.
- **Revocation rotates the generation**: revoke the delegation to Gₙ, mint Gₙ₊₁, re-delegate the surviving signers, publish the new `g=` (with a serial bump), and refresh outstanding certificates. A revoked signer's chain routes through a key that is no longer attested — it dies against any fresh chain, with no revocation list, no set enumeration, and no proof machinery: the verifier's check is positive path membership, nothing more.
- When the DNSSEC chain is **fresh ✓**, the chain-contains-`g=` check is strict (mismatch MUST reject); when **stale ⚠**, it is graded and provisional like every other claim. Revocation lag for record-only verifiers is thereby bounded by RRSIG windows (days–weeks) instead of by sync luck, and resolution remains record-first: bytes plus the baked-in KSK suffice, and syncing the document stays an optional corroboration, never a prerequisite.

The update requirement is deliberately incentive-aligned: the only mandatory DNS touch coincides with a revocation ceremony — the moment the publisher is already in DNS rotating zone credentials and maximally motivated to broadcast. This is also the DS/KSK pattern one level up: exactly as a DS record commits a zone to one key that vouches for its working keys, the TXT commits a name to one key that vouches for its certificate signers.

> [!NOTE]
> This is structurally similar to ATProto's rotation-key hierarchy — a more-powerful key gates which working keys are currently valid — but decentralized: the current-generation attestation lives in the publisher's own DNSSEC-signed zone rather than a central directory, verification needs no oracle, and recovery is generation rotation plus Keyhive's merge semantics rather than a sequencer's 72-hour history rewrite.

### Generation Lineage
[Generation Lineage]: #generation-lineage

A generation is identified by the pair **(root document ID, generation key)** — the key alone is not an identity, since the same key bytes may be delegated in more than one document. There is no generation counter on the wire: the ordinal is derived from lineage length, never asserted (an asserted counter would be vouched by nothing the lineage doesn't already vouch better).

Each rotation MUST produce a **rotation statement** signed by Gₙ₊₁ over the triple `(root_doc, Gₙ, Gₙ₊₁)` — the document ID is inside the signed statement precisely so a statement minted in one document cannot be replayed into another document's lineage when keys are reused. Certificates carry the accumulated lineage in the attached region; the wire format is `ONR\x00` per [Serialization], each statement traveling with its **authority carriage** — the delegation chain proving its signer speaks for the document. The signature costs nothing extra — it happens inside the rotation ceremony, when the keys are already out — and it buys the one comparator that works with no network and no zone trust: valid lineage entries are self-authenticating, so **two artifacts for the same name can be ordered offline** — the generation with lineage descent from the other is newer, vouched by the document rather than the zone.

**Statement validity.** A rotation statement is _valid_ only when all of the following hold; anything less is **malformed evidence** — it MUST be ignored entirely, MUST NOT advance lineage memory, and MUST NOT count as fork evidence (otherwise anyone who knows a document ID could mint rival statements and schedule equivocation alarms at will):

1. It decodes strictly per [Serialization]'s `ONR\x00` layout and its signature verifies under the `successor` key.
2. Its `root_doc` equals the document under consideration (the certificate's `root_doc`).
3. Its authority carriage is a valid delegation chain rooting at `root_doc`, terminating at the `successor` key, with the delegating hop held at admin access — the same bar as certificate signing ([Who Signs]).
4. The document's valid statements MUST form a **confluent chain** in the replaced → successor graph, and chain-shape violations are evaluated **set-wise** — never by which statement came "first," because any such tiebreak would be evaluation-order-dependent. A key **replaced twice** or a **cycle** (a retired generation key reappearing as a successor) is a **fork**: every involved statement surfaces per D12a/D16, none is silently preferred, and — because D12's hard rejection is scoped to the [protected prefix](#heads-and-the-protected-prefix) — a fork can never brick fresh chains and never disarms the history beneath it. A key appearing as `successor` in more than one statement with **distinct** replaced keys is NOT a violation: it is a **convergence merge**, the fork-repair primitive — safe to permit because statements are signed *by* the successor, so only that key's holder can merge into it (an attacker cannot merge branches into the owner's key). Publishers MUST NOT reuse generation keys: reuse converts their own lineage into a permanent surfaced fork.

Forks exist only between **valid** statements: two valid statements replacing the same generation are provable equivocation (both signers were genuinely delegated — an insider event, not noise); a valid statement and an invalid one are a statement and some garbage.

The attached lineage SHOULD be complete from the first rotation: the list of every rotated generation key is its projection (`lineage.map(replaced)`), with the signatures being what distinguish it from an assertion. A partial lineage answers only what it covers — ordering G₇ against G₈ needs one statement, but ordering a very stale artifact against a current one needs the receipts in between — and verifiers MUST treat missing coverage as "incomparable," never as evidence.

Size stays trivial by construction: one statement (~150–300 bytes) per rotation, and rotations are cold-key ceremonies coupled to security incidents, not usage — a decades-old identity plausibly carries zero. The DNSSEC chain dominates the certificate regardless. An attacker cannot inflate a lineage (every entry needs a validly-signed statement whose authority lies on the document's graph); only the owner can grow it, one ceremony per entry. Should a policy-rotating organization ever accumulate a pathological lineage, CT-style compaction (checkpoint statements or a consistency-proof log, under a new `ONx` schema tag) is the documented upgrade path — the format does not preclude it.

Verifiers MUST use lineage when present:

- Ratchet: once a valid, **uncontested** statement shows Gₙ₊₁ replacing Gₙ, an attested `g=` of Gₙ is a provable rewind. A **stale** ⚠ attestation of Gₙ MUST be rejected outright. A **fresh** ✓ attestation splits on the zone's own attested history — the monotone-generation clock: if any held record attests a lineage-later generation for the document (the zone was observed moving forward and now attests backward), the rewind is **corroborated** and MUST be rejected regardless of chain freshness, with the fork surfaced — the owner must learn their zone is publishing a retired key, and the fresh chain's minting required exactly the zone control the rewind attacker holds. Where **no** such corroboration is held — the statement alone claims the succession — the case is genuinely two valid observations pointing opposite ways: a forged statement over an honest zone (the kill switch), a rewind racing ahead of gossip, and a slow zone mid-rotation are indistinguishable from the evidence. The record MUST NOT be hard-rejected and MUST NOT silently win: it survives, the fork surfaces, and the document derives **contested** ([Binding Cache spec]) — resolution falls to pins and the use-time prompt until repair (the convergence merge) or an explicit acceptance. Forks are insider-grade events (every valid statement was signed by a genuinely delegated key); collapsing them silently in either direction hands the insider a kill switch over the honest owner's fresh chains or a silent rewind, depending on the direction chosen.
- Comparison: between two stale artifacts, the lineage-descendant generation wins; the serial `n` is only a zone-vouched tiebreak when lineage is absent or incomparable (see [Comparing Records Offline]).
- Forks: two statements claiming to replace the same generation are **provable equivocation** (e.g. a zone-holding revoked insider minting a rival successor). A fork MUST be surfaced and MUST NOT be silently resolved in either direction — detection where resolution is impossible, the same epistemics as divergence and re-pin.

### Heads and the Protected Prefix
[Heads and the Protected Prefix]: #heads-and-the-protected-prefix

The scope of D12 under a fork is defined by the lineage's **heads**. In the replaced → successor graph of a document's valid statements, a *head* is a generation that no valid statement replaces. A healthy lineage has exactly one head — the current generation. A fork is precisely the multi-headed (or otherwise chain-shape-violating) state.

A fork suspends D12 **fork-locally, never document-wide**:

- The **protected prefix** is the portion of the lineage strictly below the fork point (below the lowest common uncontested ancestor of all heads). Every generation in the prefix was superseded by an individually uncontested statement, and an attested `g=` from the prefix remains a provable rewind: D12 MUST still reject it — fork or no fork — when stale, or when fresh and corroborated by the zone's own attested history (the monotone-generation clock; [Generation Lineage]); the uncorroborated fresh residual derives contested (D12a). A document-wide suspension would let an insider *purchase rewind immunity for the entire history* with one cheap equivocation — the exact inversion of what the ratchet exists for.
- The **fork-implicated suffix** — the fork point and the generations reachable from it on any branch — is D12a territory: records attesting those generations MUST surface as forks and MUST NOT be hard-rejected or silently resolved in either direction.

**Repair narrows the suffix.** The owner converges heads by ordinary rotation: statements retiring each branch head into a single fresh successor (Gₙ₊₁ MUST be a fresh key) — a convergence merge, per validity rule 4 — a new `g=` in the zone, a serial bump, a fresh chain. The retirement of a branch does not require the branch key's cooperation — rotation-statement authority is the admin-held carriage, never the outgoing key — which is what makes repairing an attacker's branch possible at all. **A single head settles the lineage**: when the graph converges to one head (and contains no cycle), every replaced generation is protected — all branches were retired, however contested the route — and D12 resumes over the whole history. The fork's statements remain permanently in the lineage: repair converges heads going forward; it never launders the historical equivocation, which stays surfaced as evidence of an insider event.

**Layer confinement.** Fork repair is a generation-layer (`g=`) ceremony. It MUST NOT require, and verifiers MUST NOT escalate it to, document succession: `p=` moves only for identity loss ([Succession]), never for lineage hygiene. Were succession ever the mandated repair, one insider statement could force an identity migration — a strictly worse kill switch than the ones this section already refuses.

### Comparing Records Offline
[Comparing Records Offline]: #comparing-records-offline

Given two certificates (or cached bindings) for the same name, a verifier determines which is current by a precedence ladder, each rung consulted only when stronger rungs are silent. First, **pool the evidence**: both artifacts' attached regions are self-authenticating, so their lineages and chains MUST be evaluated as a union — one artifact's lineage may order the other.

| Rung | Comparator                                                       | Vouched by                                     | Rule                                                                                                                                                                                                                 |
|------|------------------------------------------------------------------|------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0    | Chain freshness                                                  | DNSSEC windows                                 | A fresh ✓ artifact beats any stale ⚠ one outright                                                                                                                                                                    |
| 1    | Succession proofs / lineage descent                              | The document's keys                            | Across documents: valid successor statements (incl. bridged chains) establish continuity and order. Same `root_doc`: the generation with signed descent from the other is newer. Equivocation → surface, do not pick |
| 2    | Zone-state key: `(window_end, serial, issued_at)`, lexicographic | DNSSEC windows, then the zone, then the signer | Later window end wins; equal ends → higher serial; equal serials → later `issued_at` (within one document only; see below)                                                                                           |

The maximal record is the **unique undominated candidate**: the one no other candidate beats on the ladder. Implementations MUST select it by dominance testing (or an equivalent order-insensitive computation), never by a fold whose result can depend on enumeration order. The reason folding is unsafe: the full ladder is not guaranteed transitive — a rung-1 proof can order a pair one way while the rung-2 keys order it the other — so a pairwise fold's answer can depend on which pair it happened to compare first. Zero or several undominated candidates — dominance cycles, equivocation, forks — derive as **contested** *among the eligible candidates*: the [Binding Cache spec]'s incumbency and eligibility rules decide what a tie does to the accepted output (B1/B13/B14), and in particular a tie among stale, unproven challengers is their pending set, never a contest that blanks a decision-backed incumbent.

Rung 2's key details, in prose:

- `window_end` is the end of the chain's ∩-window ([Graded Freshness]). It leads the key because it is DNSSEC-vouched, where serials are publisher-chosen; serials break exact window ties (e.g. two records published under one chain window).
- `issued_at` breaks ties only **within a single document**. Cross-document equality at `(window_end, serial)` is zone equivocation — contested, surfaced, never resolved by a signer-claimed field.
- One lexicographic key per record, rather than pairwise comparators, is deliberate: mixed pairwise rules (windows for disjoint pairs, serials for overlapping ones) are non-transitive and can cycle on honest inputs after a serial reset. A single key makes the order total and "the maximal record" well-defined.
- The key orders **zone states** — which record is the zone's later word — but confers no _continuity_ (only a successor proof does that) and no _movement_: displacing a verifier's incumbent accepted binding additionally requires fresh evidence, a proof, or a user acceptance ([Binding Cache spec] B1 — a stale later-window record proves the zone moved during a past window, not that its word is current). An unproven cross-document winner is still a surfaced binding change, graded by the displaced binding's tenure ([Succession]).

Two verifiers holding the same evidence MUST reach the same verdict — the ladder is deterministic, including any bridged succession verdicts built from the pooled evidence ([Bridging History Gaps]), and its determinism is a conformance target (see [design/verification.md](../../design/verification.md)).

> [!NOTE]
> Generation lineage is about naming-key generations within the **same** document. It is distinct from [Succession], which is about identity continuity across **different** documents (a `p=` change). Transferring a domain to a new owner is neither: the new owner binds their own document with no continuity proof, and the change is deliberately surfaced — from a verifier's perspective, transfer and capture are the same event.
>
> The two statement types scope oppositely, on purpose: rotation statements bind `(root_doc, Gₙ, Gₙ₊₁)` with **no hostname** — a revoked generation must die across every name bound to the document, in one ceremony — while successor statements bind `(hostname, predecessor_doc, successor_doc)` because migration is per-name and its proof must not be replayable across names.

# Onomancy Certificate
[Onomancy Certificate]: #onomancy-certificate

The certificate is a self-authenticating record: integrity does not depend on the transport, the server, or the peer that relayed it. Consequently, **any** source MAY carry any name's certificate — a source is an untrusted byte courier, and a malicious one can at worst withhold or serve stale records (denial of service), never forge a binding.

Retrieval paths, ordered by the work a verifier performs before it can judge what it received:

| Path                                                          | Requirement                | Work before verification                                | Notes                                                                                              |
|---------------------------------------------------------------|----------------------------|-----------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| Gossip / cache                                                | OPTIONAL                   | none — the bytes are already held                        | Certificates travel peer-to-peer and verify identically (see [Binding Cache])                      |
| A linked certificate document (see [In the Bound Document])  | RECOMMENDED for publishers | one small document                                        | Small, admin-written, and independently replicable — a mirror of everyone's certificates and a publisher's own host are the same kind of thing |
| The bound document itself (see [In the Bound Document])       | OPTIONAL                   | unbounded — materializes a document named by the claim under test | No new infrastructure: the document is already replicated by any verifier that walks a path under it |

Publishers MUST make the certificate retrievable through at least one path; verifiers MUST accept certificate bytes from any source, subject only to [Verification]. A name with no designated endpoint is still fully conformant — it just is not self-bootstrapping for cold verifiers with no peers.

Verifiers SHOULD attempt sources in increasing order of work performed before verification. Retrieving from the bound document requires materializing a document named by the very claim under test, so a bounded source — where one is available — is preferred.

The certificate is document content, so whoever can write the document holding it can remove or replace it — a naming-layer capability that [Who Signs] otherwise reserves to admin-delegated keys. The ceiling is denial of service and a freshness downgrade, never a forged or redirected binding, but publishers SHOULD close it: either place the certificate in a document whose write authority matches its issuing authority (see [In the Bound Document]), or maintain a second retrieval path.

## Designated Endpoints
[Designated Endpoints]: #designated-endpoints

Publishers designate where a verifier can obtain the bound document with an SVCB record ([RFC 9460]) at the same owner name as the TXT — keeping all onomancy records under one owner name, with one DNSSEC coverage story and one denial-of-existence story. A publisher MAY designate several hosts at ascending priorities:

``` zone
_onomancy.expede.wtf.  IN TXT   "v=ONO0;k=ed25519;n=1;g=…;p=…"
_onomancy.expede.wtf.  IN SVCB  1 sync.example.
```

This section is the SVCB _protocol mapping_ for onomancy:

- The record is queried at `_onomancy.<name>` — the same owner name as the binding record, so it rides the same DNSSEC coverage and (for resolvers that ask for both types) the same lookup.
- In ServiceMode (SvcPriority ≥ 1), TargetName designates a host from which the bound document can be replicated — and with it the certificate ([In the Bound Document]). Lower priorities MUST be tried first; equal priorities MAY be tried in any order; a verifier that cannot reach a designated host MUST fall through to the next rather than failing.
- AliasMode (SvcPriority 0) follows standard [RFC 9460] semantics.
- The `port` SvcParam applies; other SvcParams MAY be ignored at v0.
- Publishers SHOULD use SVCB. Publishers whose DNS provider cannot create SVCB records MAY publish the equivalent SRV record at `_onomancy._tcp.<name>` (priority/weight/port/target map one-to-one — the gap set is real: several major registrars sign zones but cannot create ServiceMode SVCB, and all of them support SRV). Verifiers MUST try SVCB first and SHOULD fall back to SRV only when SVCB yields nothing — sequential, so when both exist SVCB wins by construction and no precedence ambiguity arises. SRV support is **transitional**: a future version of this specification MAY drop it as registrar SVCB support catches up.

The SVCB record is a [transport hint][Transport Hints] like any other: DNSSEC coverage protects it from off-path spoofing, but it confers no authority, and verifiers MUST NOT require it. Bootstrap order for a cold verifier is therefore: gossip/cache, else the designated endpoint (SVCB, then SRV) — and if neither exists, the name is resolvable only through peers or mirrors learned out of band.

> [!NOTE]
> A designated endpoint is a hint about **where the bytes can be obtained**, in the sense a magnet link's tracker and web-seed fields are hints. What is being pointed at is identified self-certifyingly elsewhere — the document by its `p=` key, the certificate by the signature that binds it — so a hint can only affect whether a verifier obtains bytes, never whether those bytes verify. Designating a host that serves the bound document therefore satisfies this section exactly as much as designating one that serves the certificate, and a verifier MAY ignore designation entirely in favour of peers it already has.

## In the Bound Document
[In the Bound Document]: #in-the-bound-document

The certificate list lives at the key `.well-known/onomancy/certificates` in the bound document's top-level map — beside its names, not nested under a container ([Onomancy Path Resolution], Namestore Layout). The value is either:

- **inline** — a list of certificate units; or
- **a reference** — pointing at a document whose entry at the same path holds the list inline.

Exactly one hop is permitted: a referenced document's entry MUST be inline, and a verifier MUST NOT follow a second reference. An inline list is not a reference and so takes no part in path resolution ([Onomancy Path Resolution], E8); a reference is an ordinary edge and resolves like one.

Indirection is RECOMMENDED wherever the two documents can carry different write authority. The certificate is document content, so whoever can write the document holding it can remove or replace it; putting it in a document written only by the keys that issue certificates keeps naming authority above collaboration authority ([Who Signs]). It also isolates the identity document from chain-refresh churn — the frequent event by design, since any party MAY re-fetch and re-attach evidence — and lets a small, widely-replicated certificate document be mirrored without replicating the identity.

More than one certificate is the normal case: a document is commonly named by more than one hostname, and each certificate binds exactly one.

Entries follow the same dispositions as the binding `RRset` — the rules are already stated in [Grammar] and are not restated here:

- An entry that does not decode is rejected on its own; it MUST NOT poison the processing of its siblings.
- An entry naming a hostname other than the one being resolved is **not** an error — it is this document's certificate for another of its names — and is ignored for this resolution.
- Several valid entries for one hostname are selected by [Comparing Records Offline].
- No entry for a hostname means the certificate is unavailable **from this source**. It never means no binding exists: absence is not provable.

A writer refreshing a certificate's attached evidence MUST replace the entry whose **signed region** is identical rather than appending one. A refreshed certificate is the same certificate carrying different evidence ([Serialization]), so appending would grow the list without bound while adding nothing. Entries differing in their signed region are distinct certificates and MUST be retained.

## Transport Hints
[Transport Hints]: #transport-hints

Designated endpoints, mirrors, and sync peers are **transport hints**: they affect whether a verifier can obtain the bytes, never whether the bytes verify. There is no canonical location for a certificate. Address records (A/AAAA/CNAME) **on the name itself have no role in this protocol** — no fetch path consumes them (retrieval resolves the SVCB/SRV _target_ host, not the name), and a website on the same name is unrelated infrastructure. A verifier MAY try the name's own host as a last-resort endpoint guess; that is out-of-band knowledge like any other, one more hint, nothing else.

- Verifiers MUST NOT treat any retrieval path as authoritative, MUST NOT ascribe any meaning to which source supplied a certificate, and MUST NOT reject a certificate because it arrived from somewhere other than the name's own host.
- A wrong, stale, or malicious hint can cause only denial of service or staleness — all trust derives from the TXT binding record and the certificate's own proofs.
- By analogy with magnet links: the TXT `p=` is the infohash; every endpoint is a tracker hint.

## Fields
[Fields]: #fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `root_doc` | `DocumentId` | Yes | Root [Automerge] document ID; MUST equal the TXT record's `p` |
| `signer` | `VerifyingKey` | Yes | The delegated admin key that signed this certificate (see [Who Signs]) |
| `issued_at` | `Timestamp` | Yes | Claimed; sanity-checked against rough client clocks only |
| `hostname` | `DnsName` | Yes | The full DNS name this certificate binds (subdomains included, e.g. `blog.expede.wtf`; need not be a zone apex) |
| `heads` | `[ChangeHash]` | No | OPTIONAL **advisory** attestation of the root document's heads at issuance; MUST NOT pin resolution (see [Handoff to Path Resolution]) |
| `predecessor` | `SuccessorStatement` | No | OPTIONAL proof of continuity from a previously bound document (see [Succession]) |
| `signature` | `Signature` | Yes | By `signer`, over the canonical encoding of the format tag and all fields above — the **signed region**. Everything below is the **attached region**: unsigned, independently verifiable, replaceable keylessly |
| `delegation_chain` | `[Signed<Delegation>]` | Yes | [Keyhive] authority proof from the doc root down to `signer`. Attached: any valid chain for the same `signer` is interchangeable, so generation rotation is repaired by re-attaching, not re-signing |
| `lineage` | `[RotationStatement]` | No | Generation lineage: rotation statements ordering the document's generation keys (see [Generation Lineage]). Attached; empty = never rotated |
| `chain` | `DnssecChain` | Yes | DNSSEC chain from the IANA root KSK down to the TXT record at `_onomancy.<hostname>`. Attached: refreshed as RRSIG windows lapse |

Field order follows the wire layout ([Serialization]): within the signed region, fixed-width fields first, then variable-width; the signature closes the signed region, and the attached fields follow it.

The document-root signing key is destroyed at creation ([Keyhive]'s `EphemeralSigner`), so the certificate cannot be signed by the document ID itself; the embedded delegation chain is the standard Keyhive authority proof from the self-certifying init down to `signer`.

The canonical encoding (the signature target) MUST be injective; the byte layout, signature target, and chain framing are defined in the [Serialization] specification.

## Who Signs
[Who Signs]: #who-signs

Certificates are signed by **user-held keys, never servers**: onomancy servers hold no keys and are pure byte couriers (a compromised server can withhold or serve stale, nothing more).

The `signer` MUST hold **admin** access in the delegation chain. Lesser access is insufficient by design: a collaborator with Write access to a shared document could otherwise sign a certificate binding _their_ hostname to _your_ document — the insider variant of key borrowing. Naming authority sits strictly above collaboration authority.

Admin-only signing is operationally cheap because certificate issuance is rare by construction: the DNSSEC chain is attached **unsigned**, so chain refresh (the only frequent event) requires no key at all — any keyless machine re-fetches and re-attaches a fresh chain to the same signed certificate. The admin key leaves cold storage only for deliberate acts: new bindings, migration, revocation. Publishers are RECOMMENDED to delegate admin to two or more cold keys at document creation (backup or social recovery), so losing one is a revocation, not a catastrophe.

## Succession
[Succession]: #succession

A `p=` change re-binds the name to a different document — either voluntary migration or a hostile re-binding (domain capture, re-registration). The two are distinguished by proof, not appearance:

- A **successor statement** (wire format `ONS\x00` with authority carriage, per [Serialization]) is signed by the _previous_ document's delegation graph over the triple `(hostname, predecessor_doc, successor_doc)`; it is subject to the same validity bar as rotation statements — strict decode, signature, and a carried admin-held delegation chain rooting at `predecessor_doc` — with invalid statements ignored as malformed evidence (D17). The hostname is inside the signature because migration is per-name: a document bound to several names may migrate only one, and without hostname scoping, one name's migration proof could be replayed under a different name to make a hostile capture look like continuity-proven migration. The statement's chain MUST pass through the predecessor's generation key as last known to the verifier — after migration the predecessor's TXT is gone, so this is checked against the verifier's **accepted binding** (document + generation key, as derived per the [Binding Cache spec]; or live during a dual-publish window). The accepted binding is the **single** succession anchor — every rule in this section and in [Proofs Are Relative Evidence] means exactly it when it says "last known." A new certificate carrying a valid `predecessor` proof _for its own hostname_ is a _continuous_ re-binding: verifiers MAY treat it as routine.
- A `p=` change **without** a successor proof MUST be surfaced as a binding change and MUST NOT be accepted silently, regardless of ratchet or freshness — a zone attacker cannot forge the statement (it requires the old document's admin keys, which zone control does not confer), so hostile capture is structurally incapable of looking routine to any verifier with prior knowledge of the binding.
- The severity of an unproven change SHOULD be graded by **tenure**: the accumulated window evidence for the displaced binding in the verifier's own store. Months of RRSIG windows attesting a stable binding are unforgeable-by-newcomers history — an unproven change displacing a long-tenured binding warrants the strongest warning UX, while displacing a week-old binding is ordinary. Tenure is derived, not asserted: an earlier design carried an owner-set `continuity` flag promising future proofs, rejected because it was an owner self-assertion of custody quality (the recurring lesson: asserted fields lose to derived evidence), it punished the key-loss backstop with the owner's own past promise, and it demanded sticky cross-migration verifier memory that tenure gets for free. Escalation degrades to warnings, never lockout — no grading can be weaponized to brick a name.

Successor statements also give clock-free ordering across the one boundary the serial ratchet handles weakest: between two documents with no shared history, the signed handoff — not a number — is what establishes which came second.

### Proofs Are Relative Evidence
[Proofs Are Relative Evidence]: #proofs-are-relative-evidence

A successor proof proves continuity _with a specific prior document_; it confers exactly as much trust as the verifier already had in that predecessor — and therefore nothing at all absent history:

- A proof upgrades a binding change to routine **only** when its `predecessor_doc` matches the verifier's current accepted binding for this hostname ([Binding Cache spec]). A proof chaining from an _older_ previously-accepted document (superseded evidence) is neither routine nor nothing: it is **competing history**, surfaced like a fork — with [Bridging History Gaps] the path to making it comparable. A proof naming a predecessor the verifier has never seen bound MUST confer nothing.
- On first contact the succession rules never fire (there is no prior binding to change from), and implementations MUST NOT render continuity status for a name the verifier has no history with — a certificate _carrying_ a proof is not a certificate whose proof was _evaluated_. Two attacker-controlled documents can vouch for each other in a circle the verifier has never seen; rendering that as "✓ continuity-proven" is free legitimacy for capture.
- The converse subtlety is accepted: an attacker who genuinely bound one document during their own tenure and later migrated to another has produced a _true_ proof — of continuity within a tenure the verifier never trusted. Relativity is the point: proofs order documents against _your_ history; they never speak to legitimacy in the absolute.

### Bridging History Gaps
[Bridging History Gaps]: #bridging-history-gaps

A verifier returning after multiple migrations holds an accepted binding the current certificate's proof does not name (they knew `R`; the cert for `T` proves only `S → T`). Alone, that is incomparable — a surfaced binding change. But successor statements are self-authenticating and superseded certificates keep circulating, so the evidence-union rule ([Comparing Records Offline]) extends across documents:

- Bridging is part of the derivation, not a discretionary feature: verifiers MUST compute bridges from the pooled store (`R → S` from the superseded certificate for `S`, `S → T` from the current one) whenever an unbroken proof chain exists from their own accepted binding to the current document. (Whether to _act_ on a bridged verdict remains policy; whether it is _derived_ is not — two verifiers with the same store MUST agree.)
- Grading is per hop and honest about what is checkable: the hop departing the verifier's accepted binding is checked **fully** — only when the departing document has **fresh support** in the pooled store ([Binding Cache spec], stage 4); without it the departing hop grades provisional too — that document's last-known generation key MUST lie on the statement's delegation path; subsequent hops are **provisional** — chain-valid against the intermediate document's self-certifying delegation graph, but with no generation-key memory to check attestation against. A bridged continuity verdict MUST be distinguishable from a directly-proven one.
- Two statements claiming to succeed the same document are **provable equivocation** (e.g. a once-legitimate key of an intermediate document forking history): a fork MUST be surfaced and MUST NOT be silently resolved in either direction — the same rule as generation-lineage forks.
- A verifier acting on a bridged verdict SHOULD opportunistically re-fetch the current certificate or cross-check against additional peers when connectivity exists — the same obligation as acting on a stale ⚠ verdict. The provisional hops are checkable only against wider evidence, and a bridged verdict under eclipse is exactly what a history-forging attacker wants a verifier to sit on.
- A missing or broken hop leaves the artifacts incomparable, and the unbridged behavior — surfaced change, pins decide — is the REQUIRED fallback. Bridging is OPTIONAL evidence, never a prerequisite: the common case remains one record plus one memory.
- Publishers SHOULD keep superseded certificates retrievable after migration (they are immutable static files; the endpoint or any mirror can keep serving them) — a gap-bridging verifier needs exactly those bytes.
- Intermediate certificates function as **statement carriage**: the statements (with their authority carriages) are the evidence, so an intermediate certificate's own DNSSEC chain MAY be stale or absent without affecting the bridge — hops are graded by statement validity, not by the courier certificate's freshness.

## Verification
[Verification]: #verification

Given certificate bytes from _any_ source (server, cache, gossip peer), a verifier MUST perform all of the following, in an order that never exposes unverified claims to the caller:

1. Decode the canonical encoding; malformed input MUST be rejected.
2. Verify `signature` under `signer` over the canonical encoding.
3. Verify the delegation chain: first hop signed by the doc-root key itself, each subsequent hop by the previous delegate, terminating at `signer` with sufficient (admin) access, with no revocation _known to the verifier's causal past_. Revocation knowledge propagates by sync and gossip, never by oracle ([Chain Validation]): a record-only verifier satisfies this step with the chain's internal validity alone — the recency coupling is step 8's generation check, not an external lookup this step implies.
4. Validate the embedded DNSSEC chain from the verifier's **own** baked-in IANA root KSK down to the `_onomancy.<hostname>` TXT record (see [Chain Validation]). The chain MUST cover every indirection (CNAMEs, zone cuts), not only the final owner name.
5. Check `TXT p= == certificate.root_doc`.
6. Check the chain's owner name matches `certificate.hostname`.
7. Apply the [Serial Ratchet].
8. Apply the [Generation Key] rule: with a fresh ✓ chain, the key attested in the TXT `g=` MUST lie on the delegation path as an authority-carrying hop; with a stale ⚠ chain the check is provisional. If valid generation lineage has been observed, a `g=` in the protected prefix MUST be rejected when stale, or when fresh with the rewind corroborated by the zone's own attested history ([Heads and the Protected Prefix]); an uncorroborated fresh attestation derives contested (D12a), and a `g=` in a fork-implicated suffix is surfaced, never silently resolved or hard-rejected (D16/D12/D12a).
9. If the binding's document differs from the previously known one, apply the [Succession] rules: verify the `predecessor` proof if present (evaluated per [Proofs Are Relative Evidence]; a history gap MAY be bridged per [Bridging History Gaps]); surface the change if the proof is absent or names an unknown predecessor, graded by the displaced binding's tenure ([Succession]). With no previously known binding, this step does not run and no continuity status exists to render.

``` mermaid
flowchart TD
    A["Certificate bytes<br/>(from server, cache, or gossip peer)"] --> B[decode canonical encoding]
    B --> C{signature valid under signer?}
    C -->|no| X1[✗ reject]
    C -->|yes| K{delegation chain valid:<br/>root_doc → … → signer?}
    K -->|no| X2[✗ reject]
    K -->|yes| D{DNSSEC chain valid<br/>from baked-in KSK?}
    D -->|no| X3[✗ invalid / stale ⚠]
    D -->|yes| E{TXT pubkey == root_doc?<br/>hostname matches?}
    E -->|no| X4[✗ reject]
    E -->|yes| G["Verified { verified_at, chain_window }"]
```

Any failure of steps 1–3, 5, or 6 MUST yield rejection. Step 4 yields the graded verdict (see [Graded Freshness]). Step 7 may reject (stale replay), defer (far-future serial), or accept-and-surface (fresh downward move); step 8 rejects on fresh-chain generation mismatch (or provably replaced generation); step 9 surfaces or escalates per [Succession]. Implementations SHOULD use a type-state witness (`Certificate → Verified<Certificate>`) so that unverified claims are inaccessible by construction.

Step 6 is what defeats key borrowing: an attacker's zone can point its TXT record at a victim's document ID, but no certificate binding the attacker's hostname can exist without a delegation from that document.

# Chain Validation
[Chain Validation]: #chain-validation

- Verifiers MUST validate locally against a baked-in IANA root KSK (exactly one at v0; a trust-anchor set with [RFC 5011]-style rollover is future work — root rollovers overlap, so clients shipped during an overlap SHOULD carry both keys). Verifiers MUST NOT delegate validation to a resolver's AD bit.
- Verifiers MUST support the signature algorithms in real-world chains (RSA/SHA-256 for the root; ECDSA P-256 at zones, at minimum). A chain whose validation requires an algorithm the verifier does not implement MUST yield invalid ✗ — never stale ⚠, and never an "insecure" verdict: [RFC 4035]'s treat-unknown-as-insecure resolver semantics would be an algorithm-downgrade path here, because an Onomancy binding is only ever KSK-rooted and "insecure" has no meaning for it.
- Verifiers MUST reject wildcard-synthesized answers ([RFC 4035] §5.3.4: an RRSIG label count below the owner name's). The no-closer-match proof a synthesized answer would require is a negative proof, and negative proofs are outside the protocol at v0; accepting one unproven would let a stripped exact-match record go undetected. Publishers MUST NOT rely on wildcard TXT records for bindings.
- Verifiers MUST NOT evaluate NSEC/NSEC3 denial of existence: negative proofs are outside the protocol at v0. Denial links encountered in a chain are skipped unverified — they prove nothing and MUST NOT invalidate an otherwise-valid chain. Consequences accepted: a missing TXT record is always "absence not proven" (D3 — possible downgrade, never "no binding"), and deliberate unbinding does not propagate; the future owner-signed unbind statement is the planned mechanism, consistent with the doctrine that lifecycle events are statement-vouched, not zone-shape-vouched.
- The fetching side (the `ChainProvider` seam) is an **untrusted byte fetcher**: hosts via [hickory], browsers via DNS-over-HTTPS. A malicious provider MUST at worst be able to cause denial of service, never a false verified verdict — all verification runs in core.
- Revocation is layered: a compromised signer is revoked inside the document's delegation graph, and the [Generation Key] rotation makes that verifier-visible without any list — the attested chokepoint no longer lies on the signer's delegation path. `p=` never changes for key compromise; `g=` does.
- Revocation knowledge is local-first: it propagates via document sync and gossip, not via any oracle. A revoked-but-not-yet-known signer's certificates continue to verify until the revocation reaches the verifier — an accepted residual, symmetric with graded chain freshness. Online verifiers SHOULD opportunistically sync the binding document's delegation graph (or re-fetch the certificate) when acting on a stale ⚠ verdict.

# Graded Freshness
[Graded Freshness]: #graded-freshness

RRSIG windows are short (root ≈ 2 weeks; zones 1–30 days). Verifiers MUST NOT hard-reject expired chains; output is graded. A chain whose RRSIG windows have an **empty intersection** never had a moment of joint validity: it is invalid ✗, not stale.

``` rust
pub struct Verified {
    pub verified_at: Timestamp,
    pub chain_window: Range<Timestamp>, // ∩ of all RRSIG windows
}
```

| Verdict | Meaning | Online policy | Offline policy |
|---------|---------|---------------|----------------|
| fresh ✓ | window covers now | proceed | proceed |
| stale ⚠ | once-valid; window lapsed | SHOULD re-fetch, then proceed | MUST warn, MAY proceed |
| deferred | window has not yet begun | not considered until inception (like far-future serials) | same |
| invalid ✗ | never verified from the KSK | MUST reject | MUST reject |

Staleness is a risk signal, not a forgery signal.

## Staleness in Practice
[Staleness in Practice]: #staleness-in-practice

Offline, staleness is ambient, not exceptional: every gossiped record decays within its RRSIG window, so an offline mesh operates in stale ⚠ as its steady state. Three rules keep the signal meaningful:

1. **Staleness is a state, not an event.** Implementations SHOULD render stale ⚠ as a passive indicator and SHOULD NOT interrupt for it. Interruptive UX is reserved for _events_ — binding changes, downward ratchet moves, unproven `p=` changes, lineage forks — the tripwires that share the user's finite attention.
2. **Staleness has magnitude.** Verifiers SHOULD grade by how far the `chain_window` has lapsed, and MAY grade relative to a local baseline: where everything a verifier holds is two weeks stale, two-weeks-stale is ambient, and a record far staler than the local median is the anomaly worth showing. The baseline is a display heuristic only, computed over distinct names/publishers — it MUST NOT feed verdicts, so flooding a verifier with gossiped records can at most dull a badge, never flip an outcome.
3. **Freshness is a community good.** The DNSSEC chain is attached unsigned ([Serialization]), so _any_ party MAY re-fetch and re-attach a fresh chain — no keys, no owner involvement — and evidence pooling ([Comparing Records Offline]) upgrades existing entries in place. A single connected member gossiping refreshed chains keeps an entire offline mesh fresh.

# Binding Cache
[Binding Cache]: #binding-cache

Verified bindings MUST NOT be installed as edges in the user's root document (that would launder DNS's authority into the user's signature). They live in a local **binding cache**:

- Entries are self-authenticating (certificate + DNSSEC chain), keyed by hostname.
- Presence in the cache confers no authority; the chain MUST be re-verifiable, and verifiers MUST re-check it at use (yielding a possibly-stale graded verdict).
- Entries MAY be gossiped peer-to-peer as-is (record-first sharing); receivers MUST re-verify from their own KSK and MUST NOT extend any trust to the sender.
- Alongside the cache, the user's **claims** — alleged `hostname → document` associations from introductions that no certificate has yet corroborated (see [Petname Anchoring]'s divergence flow) — live in the user-private decision document ([Binding Cache spec]): E2EE and device-delegated, so they reach the user's own devices and structurally nothing else. A claim confers nothing and grades below stale ⚠. A verified record for the same hostname takes precedence, but the claim MUST be retained as introduction provenance ([Binding Cache spec] B6).
- All verifier conclusions — the accepted binding, effective serial, tenure, pending and contested conditions — are a deterministic derivation over the store, normative in the [Binding Cache spec]. In particular, a stale ⚠ record attesting a different document derives as pending and never changes the accepted binding by itself.

# Handoff to Path Resolution
[Handoff to Path Resolution]: #handoff-to-path-resolution

After verification, the root document is the one designated by `certificate.root_doc`. Remaining segments resolve per [Onomancy Path Resolution]; nothing in this specification affects the walk.

Resolution of DNS-anchored names is always **live**. The certificate's `heads` field is advisory — an attested known-good state at issuance, usable as a sync-expectation hint ("is my replica at least here?") or a document-layer staleness signal — and MUST NOT pin resolution. Two reasons: certificates are immutable and replayable by design (an old certificate with a re-attached fresh chain verifies fully fresh ✓), so certificate-pinned resolution would be a state-freeze mechanism that survives freshness; and pinning is a _user-visible_ property of a name's spelling (`automerge:…#heads`) — the `@` grammar deliberately carries no heads, and a publisher-injected invisible pin would break that.

# Error Conditions
[Error Conditions]: #error-conditions

| Tag  | Condition                                                                                                                                                                                                        | Requirement                                                                                                                                                                                                                   |
|------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| D1   | Dotless `@` name, IP literal, or malformed DNS name                                                                                                                                                              | MUST be a parse error; no fallback                                                                                                                                                                                            |
| D2   | (Reserved: proven absence is outside v0; tag not reused)                                                                                                                                                         | —                                                                                                                                                                                                                             |
| D3   | TXT record absent                                                                                                                                                                                                | MUST treat as possible downgrade; MUST NOT conclude "no binding" (absence is never provable at v0)                                                                                                                            |
| D4   | Same-document record whose zone-state key does not exceed the accepted record's, chain stale ⚠                                                                                                                   | Replay: dominated — contributes to no derivation output (bytes remain storable)                                                                                                                                               |
| D4a  | Fresh ✓ record with serial lower than the effective serial                                                                                                                                                       | Wins rung 0 (deterministic, not discretionary); MUST surface as a ratchet-reset event — additionally a surfaced binding change if the document differs                                                                        |
| D4b  | TXT serial reads more than 5 minutes in the future                                                                                                                                                               | SHOULD defer (retry later); MUST NOT treat as malformed                                                                                                                                                                       |
| D5   | Unknown `k=` algorithm                                                                                                                                                                                           | MUST reject that record only — siblings in the RRset are still processed; SHOULD surface as a possible downgrade/unsupported-algorithm signal (rejection differs from skipping in the surfacing, not the scope)               |
| D6   | Certificate signature or delegation chain invalid                                                                                                                                                                | MUST reject                                                                                                                                                                                                                   |
| D7   | TXT `p=` ≠ certificate `root_doc`, or hostname mismatch                                                                                                                                                          | MUST reject                                                                                                                                                                                                                   |
| D8   | DNSSEC chain valid but window lapsed                                                                                                                                                                             | MUST yield stale ⚠, not invalid ✗                                                                                                                                                                                             |
| D9   | Chain does not verify from the baked-in KSK                                                                                                                                                                      | MUST yield invalid ✗                                                                                                                                                                                                          |
| D10  | The TXT `g=` key does not lie on the delegation path as an authority-carrying hop, chain fresh ✓                                                                                                                 | MUST reject — signer's generation is no longer attested (revoked-signer defense)                                                                                                                                              |
| D11  | The TXT `g=` key does not lie on the delegation path as an authority-carrying hop, chain stale ⚠                                                                                                                 | Provisional: MUST warn, MAY proceed per offline policy                                                                                                                                                                        |
| D12  | Attested `g=` lies in the lineage's **protected prefix**, on a stale ⚠ chain — or on a fresh ✓ chain with the rewind **corroborated** (any held record attests a lineage-later generation; [Generation Lineage]) | MUST reject — rewind attack; forks elsewhere in the lineage do not disarm this; the corroborated-fresh case additionally surfaces a fork (the zone is publishing a retired key)                                               |
| D12a | Fresh ✓ chain attests a protected-prefix generation with **no** corroborating record for any lineage-later generation — or valid statements otherwise compete over the same generation                           | Fork: MUST surface as equivocation; MUST NOT silently resolve or hard-reject in either direction; the document derives **contested** until repair, stronger evidence, or an explicit acceptance                               |
| D13  | Chain validation requires a signature algorithm the verifier does not implement                                                                                                                                  | MUST yield invalid ✗ — no algorithm-downgrade path                                                                                                                                                                            |
| D14  | Wildcard-synthesized answer without a validating no-closer-match proof                                                                                                                                           | MUST yield invalid ✗                                                                                                                                                                                                          |
| D15  | Successor proof names a predecessor for which the verifier's store holds no record bound to this hostname                                                                                                        | MUST confer nothing; MUST surface as an ordinary binding change ([Proofs Are Relative Evidence])                                                                                                                              |
| D16  | Two successor statements claim to succeed the same document                                                                                                                                                      | Provable equivocation: MUST surface; MUST NOT auto-resolve in either direction ([Bridging History Gaps])                                                                                                                      |
| D17  | Rotation or successor statement fails [statement validity][Generation Lineage] (bad decode, wrong document, missing/invalid/non-admin authority carriage)                                                        | MUST ignore as malformed evidence; MUST NOT advance lineage memory; MUST NOT count as fork evidence                                                                                                                           |
| D18  | Valid rotation statements violate the confluent-chain shape (double-replace or cycle; a double-successor over distinct replaced keys is a legal convergence merge)                                               | Fork, set-wise: all involved statements surface (D12a/D16); no order-dependent invalidation; D12 stays armed for the protected prefix and is suspended only for the fork-implicated suffix ([Heads and the Protected Prefix]) |

# FAQ
[FAQ]: #faq

## Why no expiration on the binding record?

Expiry is at odds with local-first operation: a binding that silently dies offline punishes exactly the users the system is for. Freshness is graded instead ([Graded Freshness]), and revocation is explicit — a delegation revocation inside the document, with `p=` changes reserved for genuine migration.

## Why does the certificate embed the whole DNSSEC chain?

So the record is self-contained. A receiver with no network access — or no trust in their resolver — re-derives the binding from their own baked-in KSK and nothing else. This is what makes record-first gossip safe among mutually untrusting peers.

## Why can't the document ID sign the certificate directly?

Nobody holds that key: [Keyhive] destroys the doc-root signing key at creation. The document ID roots a delegation graph, and the certificate carries the standard Keyhive proof from that root to the actual signer.

## Why not sign with the doc-ID key and skip the delegation chain?

Nobody can: [Keyhive] destroys the doc-root signing key at creation (`EphemeralSigner`) — the ID roots a delegation graph, not a held key. And if a held root were offered, the prudent move would be to sign one delegation to a rotatable keyset and destroy it anyway — holding the one unrotatable, identity-equated key forever is pure downside after its first signature. That is exactly what Keyhive does; the delegation chain is the deliberate price of a custody model with no permanent single point of failure.

## How does revocation work without a revocation list?

By rotation, not enumeration: revoking a signer rotates the [Generation Key], and verifiers check that a chain passes through the currently attested generation — a positive path-membership test. Nobody ships, syncs, or stores a list of the revoked; the zone attests the one key that vouches for the living.

## Why not put the certificate in DNS and skip the fetch?

The "one round trip" premise is false: validating from the baked-in KSK requires walking the DNSSEC tree regardless (the endpoint fetch is already the single-round-trip option — cert + complete chain in one GET). Large TXT records are amplification-attack fodder, hit registrar input limits, and the delegation chain is unbounded. Gossip would still require the self-contained form, so cert-in-DNS would add a second wire form of the security-critical artifact to optimize a path that was never the slow one.

<!-- External Links -->

[Automerge]: https://automerge.org/
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[ICANN SAC053]: https://itp.cdn.icann.org/en/files/security-and-stability-advisory-committee-ssac-reports/sac-053-en.pdf
[IDNA]: https://www.rfc-editor.org/rfc/rfc5890
[Keyhive]: https://github.com/inkandswitch/keyhive
[Binding Cache spec]: ./binding-cache.md
[Onomancy Name Grammar]: ../name-grammar.md
[Onomancy Path Resolution]: ../path-resolution.md
[Petname Anchoring]: ./petname-anchor.md
[RFC 4035]: https://www.rfc-editor.org/rfc/rfc4035
[RFC 5011]: https://www.rfc-editor.org/rfc/rfc5011
[RFC 8552]: https://www.rfc-editor.org/rfc/rfc8552
[RFC 9460]: https://www.rfc-editor.org/rfc/rfc9460
[Serialization]: ../serialization.md
[Zooko's triangle]: https://en.wikipedia.org/wiki/Zooko%27s_triangle
[hickory]: https://github.com/hickory-dns/hickory-dns
