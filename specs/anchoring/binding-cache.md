# Onomancy Binding Cache Specification
## Version 0.1.0

## Dependencies
[Dependencies]: #dependencies

- [DNS Anchoring] — defines the records, verdicts, ladder, succession, and lineage rules whose verifier-side conclusions this document derives
- [Petname Anchoring] — defines the introductions that produce claims and the divergence flow that consumes them

## Language
[Language]: #language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14] when, and only when, they appear in all capitals, as shown here.

# Abstract
[Abstract]: #abstract

The binding cache is a grow-only **store** of self-authenticating protocol records, paired with a user-private **decision document** carrying the user's decisions. Every piece of verifier state is a deterministic **derivation** — `derive(store, now, decisions)` — so record synchronization is plain set union, decision synchronization is ordinary document replication, and arrival order is never an input. This document defines the store, the decision document, the derivation, surfacing, and pruning.

# Introduction
[Introduction]: #introduction

Every verdict is a deterministic function of **what evidence you hold**, never of when it arrived. The store is the only state; there is no incremental ingestion machine whose memory moves as records land. Step-by-step ingestion rules can depend on arrival order without anyone noticing, and arrival order is attacker-influenced (gossip) — while the protocol's own instruments (the serial ratchet, generation lineage, chain freshness, succession proofs) already order evidence _without clocks or coordination_. Recomputing verdicts from the full store leans on those instruments and closes the arrival-order channel. Consequences:

- **Sync is set union.** Any transport that unions records is a valid sync protocol — gossip already is one. Pooling records with a group needs no new trust analysis: records carry their own proof, and decisions never travel with them — they live in their own access-controlled document.
- **No derived state ever crosses a boundary.** There are no ratchet counters or "I saw X" marks on the wire; every device derives its own conclusions by running the same rules over its own store. Asserted-conclusion poisoning is impossible by construction.
- **Gossip races decide nothing.** Where evidence is genuinely ambiguous, the output is _contested_ and surfaced. First-arrival rules (TOFU included) quietly reward whoever gossips fastest; a derived view cannot, because arrival is not an input.
- **Local-first is preserved.** Nothing below requires connectivity: freshness is a property of a record (its RRSIG windows cover `now`), and fresh chains travel by gossip and courier like everything else.

# The Store
[The Store]: #the-store

The store holds **records** — append-only, merged by set union, accepted from **anyone**: certificates with their attached regions (including superseded ones), refreshed DNSSEC chains and the TXT records they carry, and rotation and successor statements (usually carried inside certificates). The user's own decisions live elsewhere: in [the Decision Document], not the store. There are no absence items: negative proofs are outside the protocol at v0 — unbinding awaits a future owner-signed unbind statement.

- Items are exact byte strings, identified by [content hash][Serialization]. Ingestion is **closed under extraction**: statements carried inside another item (a certificate's lineage or predecessor field) become independent store items too. A deferred carrier never suppresses the statements it carried — but an **excluded** carrier does: excluding an item excludes everything extracted from it, except statements independently carried by a non-excluded item. (Resets must be able to clear the succession and lineage evidence a poisoned certificate smuggled in, or the escape hatch under-clears.)
- A **record**, for ladder purposes, is one (certificate, attached chain) item as ingested: re-attaching a fresher chain produces a new item with its own zone-state key, and the old item is dominated. A bare chain refresh ingested without its certificate is an item whose `issued_at` key component is zero (it sorts below an equal-window, equal-serial certificate item). A bare refresh corroborates the freshness of a document that some certificate record already attests for the hostname; it MUST NOT make a document a candidate on its own ([Conditions] B14) — it carries the zone's word only, and neither direction alone is a binding ([DNS Anchoring], Verification). Successor statements are **hostname-scoped** items (their hostname is inside the signature); rotation statements are document-scoped.
- Records are self-authenticating: the derivation re-verifies everything, so accepting them from any source costs no trust. Records may be pooled at any scope — peers, group shelves, mirrors.

# Derivation
[Derivation]: #derivation

`derive(store, now, decisions)` computes, per hostname: the **accepted binding** (document + generation key + grade), the **effective serial**, **tenure**, **lineage** (with forks), the **pending** and **contested** sets, and **divergence** badges. Its inputs are three — the store, the clock reading, and the state of [the Decision Document] — plus the user's pinned targets, read by stage 8's divergence badges only. It MUST be deterministic: the same inputs yield the same outputs on any device, in any implementation; the decision document's state converges across devices by CRDT replication, so verdicts converge with it.

The stages below are a **normative evaluation order**: each stage reads only the outputs of earlier stages, so the derivation is acyclic and total by construction.

1. **Validate and extract.** Discard undecodable items and invalid statements ([DNS Anchoring] statement validity, D17); extract carried statements as items ([The Store]); read the decision document's entries (authenticity and privacy are the document's own access control — nothing to filter here). Chains that never verify from the KSK are invalid ✗ and discarded. Lineage chain-shape violations (double-replace, double-successor, cycles — including generation-key reuse) are NOT discarded here: they are set-wise **forks**, evaluated at stage 3 ([DNS Anchoring] D18).
2. **Exclude and defer.** Items named in a reset entry's `excluded` set — together with everything extracted solely from them ([The Store]) — contribute to **no derivation output**, at the item's natural scope: binding records are excluded for the reset's hostname; rotation statements are document-scoped items and are excluded for their `root_doc` wherever it appears. (Excluded items remain in the store: other names, other users' bridging, and re-sharing are untouched.) Records whose serial reads more than 5 minutes past `now`, and records whose chain window has **not yet begun**, are deferred — not considered until the clock reaches them ([Serial Ratchet] rule 4; deferral precedes everything, including freshness).
3. **Lineage.** Per document: the valid rotation statements. Competing valid statements over the same generation — and any chain-shape violation (double-replace, double-successor, cycle; [DNS Anchoring] D18) — are a **fork**: surfaced, never auto-resolved, never order-dependently discarded ([DNS Anchoring] D12a/D16). This stage also computes the lineage's **heads**, its **protected prefix** (generations superseded by individually uncontested statements below any fork point), and its **fork-implicated suffix** ([DNS Anchoring], Heads and the Protected Prefix).
4. **Grade chains.** Grade each surviving record's chain at `now` (fresh ✓ / stale ⚠); a chain whose RRSIG windows have an **empty intersection** is invalid ✗ and discarded. Apply the generation rules using stage 3: a fresh record whose delegation path lacks the attested `g=` is rejected (D10); a record whose attested `g=` lies in the **protected prefix** is rejected (D12) — fork-locally, never document-wide: a fork suspends D12 only for its fork-implicated suffix, and a record attesting a suffix generation survives with the fork surfaced (D12a). A document has **fresh support** when any surviving record for it grades fresh ✓ — the predicate later stages and bridging-hop grading use.
5. **Resolve the document.** Candidates are the documents of surviving **certificate-attested** records — a surviving bare chain refresh contributes freshness, window, and serial evidence for a document that is already a candidate, but MUST NOT create candidacy by itself ([The Store]; [Conditions] B14). Candidates are compared by the [comparison ladder][DNS Anchoring]: freshness, then succession proofs (bridged chains included — computed, not optional), then the **zone-state key** `(window_end, serial, issued_at)` — a total order, so "the maximal record" is always defined.

   **Incumbency is decision-backed** — derived from the decision document and the store, never from device history: the incumbent document is (i) the document of the winning acceptance entry, extended along valid succession proofs **up to the first fork** (a forked proof graph stops the extension and surfaces, D16); or, with no acceptance in the decision document, (ii) the **ladder-maximal** candidate — proofs rung included — graded provisional. Because incumbency must be derivable, **acceptance-on-use is a MUST**, and it re-fires: implementations MUST record an acceptance (citing the relied-on record) whenever the user acts on a binding whose document differs from the current acceptance-backed document — first use _and_ re-reliance after any change. (One-shot recording would leave the reversion target pointing at a superseded — possibly hostile — incumbent.) Acting on a binding whose **unproven change was surfaced** MUST first present the use-time prompt ([Conditions] B4, extended to surfaced-unproven changes): proceeding through it _is_ the deliberate act the acceptance records — so cementing a capture-window binding requires clicking through its warning, the documented tripwire shape, and remains reversible by editing the decision document. Proceeding under a pending or contested badge is a risk decision, not an adjudication: it MUST NOT record an acceptance — acceptance in those states is only the explicit resolution choice. Resolution through a petname pin consumes no DNS binding and never fires acceptance-on-use. The pending doctrine thereby protects exactly the bindings the user has relied on; never-used candidates have no incumbent to defend, and a provisional winner among never-used evidence is harmless — pins and divergence protect relationships.

   **Eligibility** is where the pending doctrine lives: displacing the incumbent requires fresh evidence, a valid succession proof chaining from it, or an acceptance that out-ranks the incumbent's (receipts with a greater zone-state key, or later in the same device chain). A stale, unproven cross-document challenger is **pending** ([Conditions] B1) however late its zone-state key reads — it proves the zone moved during a _past_ window, not that its word is current, and quarantine-until-corroboration is what protects a verifier from capture-era gossip. Succession proofs determine _continuity_ (routine vs surfaced change); the zone-state key determines _currency_ but never continuity — an unproven winner is always a surfaced binding change.

   **Acceptance conflicts** are resolved by receipts: the acceptance whose `cited` records carry the greatest zone-state key wins; the loser is surfaced. Evidence supersedes an acceptance only when a ladder-stronger record attests a **different** document _and is eligible_ — same-document evidence (e.g. a community chain refresh) never disturbs an acceptance, and an ineligible stronger challenger leaves the acceptance standing with the challenger pending. "Superseded" is a per-derivation classification, recomputed every time — new evidence or statements can change it. **Contested** is what remains: acceptances with zone-state-equal receipts for different documents, or eligible candidates with fully equal keys (zone equivocation) — surfaced, resolved only by stronger evidence or a new acceptance, never by arrival order. The `issued_at` key component breaks ties only **within a single document**: cross-document equality at `(window_end, serial)` is zone equivocation regardless of `issued_at`, which is signer-claimed and MUST NOT resolve an equivocation event. While contested, the accepted-binding output is empty — resolution falls back to pins and the use-time prompt.

   An **unproven fresh** binding change is durable via acceptance-on-use (the user acting on it records the acceptance); if the user never acts and the window lapses, the accepted document reverts to the decision-backed incumbent — surfaced as a reversion event, never silent.
6. **Grade the binding.** Supported by fresh evidence: confirmed. Supported only by stale evidence (including sole-candidate first contact) or by provisional bridge hops: **provisional** — it MUST NOT anchor a fully-checked bridge hop, and carries the opportunistic re-check obligation. Demotion needs no rule: when a fork or competing statement enters the store, this stage's output changes by itself.
7. **Effective serial and tenure.** The effective serial is the accepted record's serial — the one definition ([Serial Ratchet] rule 1); a downward move relative to the prior derivation is a ratchet-reset event in the diff. **Tenure** is a span: from the earliest chain-window inception to the latest window end among the accepted document's surviving records — derived history that grades the severity of a later unproven displacement ([DNS Anchoring], Succession) and that a capture-era newcomer cannot fake or remove. It is a span deliberately, not a union: two records carry it (the earliest-inception one and the latest), so pruning dominated records between them never changes it ([Pruning]).
8. **Divergence.** Claims and pinned targets are compared against the accepted binding; mismatches yield badges per [Petname Anchoring][Divergence and Re-Pin]. (There is no unbound state to derive: negative proofs are outside the protocol at v0.)

# Surfacing
[Surfacing]: #surfacing

State is what `derive` returns; **events are diffs**. When a store update or the passage of time changes the derivation output, implementations MUST surface the difference, following the events-vs-states doctrine ([DNS Anchoring], Staleness in Practice): binding changes, serial regressions, and forks are events (shown, possibly prompting); badge appearances and clearances (pending, contested, provisional, staleness) are visible state changes that MUST NOT prompt — "silently" anywhere in this document means "without a prompt," never "invisibly." The only prompt the pending or contested condition may generate is at use time — proceed on the accepted/pinned binding, or wait — a risk decision about the user's own action, never an invitation to adjudicate evidence (B4).

# The Decision Document
[the Decision Document]: #the-decision-document

The user's decisions live in a **decision document**: a user-private [Keyhive] document, linked from the root document, with access delegated to exactly the user's devices. It is not a new mechanism — it is the substrate doing what the substrate does, and every property the decisions need is inherited structurally:

| Property                                           | Provided by                                                                                                                     |
|----------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| Authentication (only your devices write decisions)  | The document's write delegation — what "enrolled device keys" meant, enforced by Keyhive rather than by verifier-side filtering |
| Privacy (decisions never reach peers or groups)   | E2EE + device-only read access — structural, not a behavioral MUST                                                              |
| Sync (decisions follow the person, not the device) | Ordinary document replication — the private channel decisions always needed                                                      |
| Ordering and undo                                  | CRDT causal history — a mistaken entry is edited or removed; no hash chains, no revocation sets                                 |
| Stolen or retired device                           | Keyhive device revocation cuts its write access; no bespoke retroactive-voiding or re-issue rules                               |
| Concurrent conflicting entries                     | Ordinary CRDT conflicts, resolved by the receipts rule (stage 5), loser surfaced — the same doctrine as everywhere else         |

The entry kinds:

- **Claim** `{hostname, document, note}` — recorded at introduction ([Petname Anchoring]). Feeds divergence badges only; MUST NOT affect acceptance. Claims are immutable provenance: a verified record for the same hostname takes display precedence, but the claim MUST be retained (B6).
- **Acceptance** `{hostname, document, cited}` — records a deliberate user choice of binding.
  - **When one is written**: confirming a first contact, resolving a contested state, re-pinning through the divergence flow, or — the MUST case — **acceptance-on-use**: whenever the user acts on a binding whose document differs from the currently accepted one. (Stage 5: acceptance-on-use is what makes incumbency derivable, and re-firing keeps the reversion target current.)
  - **What `cited` must satisfy**: it names the records relied on, by [content hash][Serialization] — the receipts. It MUST be non-empty, every cited item MUST be a record for this hostname, and at least one MUST attest this `document`.
  - **Conflicts**: concurrent acceptances are resolved by comparing receipts on the zone-state key (stage 5), loser surfaced.
  - **Supersession**: only _eligible_ evidence for a _different_ document supersedes an acceptance. Same-document evidence (e.g. a community chain refresh) never disturbs it.
  - **Inertness**: an acceptance is inert if any cited item is excluded by a reset, and not-yet-evaluable if a cited record is absent from the store (until sync delivers it).
- **Reset** `{hostname, excluded}` — the manual "reset trust" action mandated by [DNS Anchoring].
  - The named items — explicit content hashes, with their extraction closure — contribute to no derivation output at their natural scope (stage 2).
  - Evidence outside the exclusion set survives and is surfaced, including a concurrent acceptance citing other records.
  - Resets MUST be user-initiated and MUST NOT be automatic. Undo is editing the decision document — the fat-finger path is ordinary document editing.
  - Because rotation statements are document-scoped, excluding one through a single name's reset weakens D12 for every sibling name bound to the same document: implementations SHOULD warn when an exclusion's scope reaches beyond the reset's hostname — surfaced, never silent.

## Schema
[Decision Schema]: #schema

The entry schema is a **data-shape contract**, not a wire codec — the substrate carries the bytes — and it exists so a user's devices may run different implementations against one decision document. The document MUST contain a map at the top-level key `.well-known/onomancy/decisions`, shaped:

The key follows the `.well-known/<owner>/<artifact>` convention ([Onomancy Path Resolution], Namestore Layout) so that a decision document is an ordinary document: a top-level key like any other, holding a value that is not a reference and therefore absent from name matching. Nothing stops a writer from binding a name there instead — the prefix is a writers' convention, not an enforced reservation — and a writer who does so has broken their own decision document.

```
".well-known/onomancy/decisions": {
  "v": 0,                          // schema version; unknown versions: read nothing, write nothing
  "claims": [                      // append-only; entries are never deleted (B6)
    { "hostname": <string>, "document": <bytes 32>, "note": <string, optional> }
  ],
  "acceptances": {                 // one register per hostname
    <hostname>: { "document": <bytes 32>, "cited": [ <bytes 32> ] }
  },
  "resets": {                      // one exclusion set per hostname
    <hostname>: [ <bytes 32> ]     // content hashes of excluded items
  }
}
```

- Hostnames (as keys and fields) MUST be in canonical form per [DNS Anchoring] (A-labels, lowercase, no trailing dot). `document` fields are raw 32-byte document IDs; all other 32-byte values are [content hashes][Serialization] of store items.
- `acceptances` is a per-hostname register: writing a new acceptance replaces the old one in ordinary causal history; concurrent writes are the substrate's MV conflict, resolved by receipts (stage 5) with the loser surfaced. `resets` accumulate; removing a hash is the undo. `claims` only grow.
- All evidence references are by content hash: entries MUST be evaluable from content alone, never by reference to what the writing device "had seen." An entry that does not match this shape contributes nothing and SHOULD be surfaced as malformed — the derivation never guesses.
- Extension is by version bump: within `v: 0`, unknown keys inside entries MUST be ignored on read and preserved on write (devices with different implementation versions share this document).

> [!NOTE]
> A decision document shared beyond one user's devices — a team accepting bindings together — is expressible with the same mechanism and deliberately out of scope at v0: it is delegated trust with real UX consequences, and it changes nothing in the derivation, which simply reads whatever decision document it is given.

# Pruning
[Pruning]: #pruning

The store grows forever unless pruned. Pruning is a local storage decision bounded by one rule: it MUST NOT change any output of `derive` — a record may be dropped only when nothing (a ripening deferral, a potential fork, an acceptance's cited receipt, a bridging chain — but not a reset's excluded items: exclusion is by hash and needs no lookup, so excluded items are freely prunable) can ever make it relevant again. Superseded certificates SHOULD be retained regardless: other verifiers' gap-bridging needs exactly those bytes ([Bridging History Gaps]).

Permanent irrelevance is decidable from static data, because a record's chain window is fixed when the chain is attached: for records of the same document, Y permanently dominates X when `window_end(Y) ≥ window_end(X)`, `n(Y) ≥ n(X)`, `issued_at(Y) ≥ issued_at(X)` (the final tiebreak rung must agree too), and Y's generation is not lineage-superseded relative to X's — no future `now` can then make X win. One class escapes domination indefinitely: a far-future-serial record "ripens" only when the clock reaches its serial, which for an absurd serial is never in practice — implementations MAY drop at pruning — never refuse at ingestion, union sync accepts any bytes — records whose serials exceed `now` by more than the **deferral horizon**, a fixed protocol constant of **one year**. This is the one sanctioned exception to the pruning invariant: dropping such a record could in principle change a derivation more than a year out, and that is accepted — an honest publisher's clock is never a year fast, and the record would have contributed nothing until then anyway. The minimal sufficient store per hostname is therefore the Pareto frontier of records per candidate document (over the zone-state key; typically one or two records — a chain refresh strictly dominates the copy it refreshes), **the earliest-inception record per document** (tenure's left endpoint — retained despite being dominated; one more record, still ceremony-bounded), plus the statements — rotation statements, successor statements (statements suffice; the certificates that carried them are re-share generosity, not derivation inputs) — **and every record cited by an acceptance still present in the decision document**: pruning a cited receipt would render the acceptance not-yet-evaluable and change the derivation, violating this section's own rule. (Decisions themselves live in their document, not the store, and are not the pruner's concern.) Necessary storage grows with **ceremonies and introductions** — candidate documents observed, rotations, migrations, deliberate user acts — never with time, resolution count, or refresh churn.

# Prompt Grading
[Prompt Grading]: #prompt-grading

Prompts and badges that cite store evidence MUST convey both the **direction** and the **grade** of that evidence. In particular, a divergence prompt where a stale ⚠ once-valid certificate contradicts a claim from an in-person introduction MUST NOT be rendered with the authority of a fresh ✓ contradiction — "a once-valid record from some past window disagrees with your introduction" and "the current verified owner disagrees with your introduction" are different situations, and collapsing them lets capture-era artifacts argue with the authority of the present.

# Conformance
[Conformance]: #conformance

- `derive` is a pure function of `(store, now, decisions)`. Determinism — same inputs, same verdicts — is a conformance and formal-verification target (it extends [design/verification.md](../../design/verification.md) target 7 from pooled-evidence verdicts to the full derivation).
- Implementations MAY keep incremental caches for performance. Caches are memoization: their contents MUST equal recomputation from the store, and testing that equality is an implementation concern, not a design obligation.

# Conditions
[Conditions]: #conditions

Consequences of the derivation, tagged for cross-reference:

| Tag | Condition | Derivation consequence |
|-----|-----------|------------------------|
| B1  | Stale ⚠ record attests a document other than the decision-backed incumbent, no valid succession proof | Pending: badge, no prompt; never displaces the incumbent |
| B2  | Pending candidate becomes eligible (fresh evidence, valid proof, or acceptance) | Output changes; binding-change event in the diff (serials reconcile automatically — the ladder sees all records) |
| B3  | Pending candidate refuted by fresh evidence for the accepted binding | Pending badge clears without a prompt |
| B4  | Resolution attempted while pending or contested, or through a surfaced-unproven binding change | SHOULD prompt proceed-vs-wait (MUST, for the surfaced-unproven case, before acceptance-on-use records anything); MUST NOT ask the user to adjudicate evidence; proceeding under pending/contested records no acceptance |
| B6  | Verified record arrives for a claimed hostname | Takes display precedence; claim retained as provenance |
| B7  | Prompt cites contradicting evidence | MUST state direction and grade ([Prompt Grading]) |
| B8  | Reset entry | Its excluded items (with their extraction closure) contribute to no derivation output at their natural scope; MUST be manual; undone by editing the decision document; evidence outside the excluded set survives and is surfaced |
| B9  | Invalid rotation/successor statement ([DNS Anchoring] D17) | Discarded at validation; no lineage effect, never fork evidence |
| B10 | Sole or ladder-maximal candidate, no acceptance in the decision document, only stale evidence | Incumbent, graded provisional |
| B11 | Fork or competing statement implicating provisional support | Output demotes automatically; surfaced |
| B12 | (Reserved: proven absence is outside v0; tag not reused) | — |
| B13 | Multiple unconnected candidates, no incumbent, no fresh record, zone-state keys fully equal — or acceptances with zone-state-equal receipts for different documents | Contested: surfaced; accepted-binding output empty; resolved only by fresh evidence, a proof, or an acceptance — gossip order never decides |
| B14 | Bare chain refresh attests a document with no surviving certificate record for the hostname | Contributes to no derivation output: the zone's word alone is one direction, and neither direction alone is a binding |

<!-- Internal Links -->

[Bridging History Gaps]: ./dns-anchor.md#bridging-history-gaps
[Conditions]: #conditions
[DNS Anchoring]: ./dns-anchor.md
[Keyhive]: https://github.com/inkandswitch/keyhive
[Serialization]: ../serialization.md
[Divergence and Re-Pin]: ./petname-anchor.md#divergence-and-re-pin
[Onomancy Path Resolution]: ../path-resolution.md
[Petname Anchoring]: ./petname-anchor.md
[Serial Ratchet]: ./dns-anchor.md#serial-ratchet

<!-- External Links -->

[BCP 14]: https://www.rfc-editor.org/info/bcp14
