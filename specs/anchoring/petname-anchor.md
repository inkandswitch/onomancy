# Onomancy Petname Anchoring Specification
## Version 0.1.0

## Dependencies
[Dependencies]: #dependencies

- [Onomancy Name Grammar]
- [Onomancy Path Resolution]

## Language
[Language]: #language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14] when, and only when, they appear in all capitals, as shown here.

# Abstract
[Abstract]: #abstract

This specification defines how a name spelled `~[/segments]` is rooted: in the user's **own** signed root document. It covers the `~` grammar, the local-only property, petname edge contents, divergence detection and re-pin, and the upgrade path from an offline introduction to a chain-rooted name. Once the root document is established (trivially — it is the user's own), resolution proceeds per [Onomancy Path Resolution].

# Introduction
[Introduction]: #introduction

[Petnames][petname system] occupy the local-and-memorable corner of [Zooko's triangle]: private labels bound to global identities, meaningful only to the party that assigned them. In Onomancy, the petname namespace is the `~` anchor — the one trust anchor that requires no network, no certificate, and no third party, because the anchor is the user themself.

## Trust Statement
[Trust Statement]: #trust-statement

A `~` name proves exactly this:

> _You_ (whoever controls the signing keys of this device's root document) previously bound this label to this document reference.

The trust anchor is the user. No global namespace is consulted — and correspondingly, a `~` name has no meaning on any other device.

# Grammar
[Grammar]: #grammar

``` abnf
local-name = "~" *( "/" segment )
```

- `~` means the user's own root document and nothing else. There is no fallback to any other anchor family.
- `~` alone (no segments) resolves to the root document itself.
- `#` is reserved in segments, as in every family; names carry no version pins.
- Segment hygiene (non-empty, no `.`/`..`, no `#` or control characters) follows the shared [Onomancy Name Grammar]. Dots are permitted within labels: since anchor discrimination is entirely by sigil/scheme, a dotted label like `bmann.ca` carries no grammatical meaning — and no verification connotation (see [Choosing Labels]).

# Local-Only by Construction
[Local-Only by Construction]: #local-only-by-construction

`~` names MUST NOT appear in any wire format, gossip payload, certificate, or namestore value.

- Serializers MUST reject `~` names rather than encode them; there is deliberately no wire encoding for the local anchor.
- Receiving software MUST treat any `~` spelling arriving over the wire as malformed input.
- Sharing a `~` binding means sharing what it points **to** — the target's [Automerge URL] (plus, for DNS-bound identities, the certificate per the [Binding Cache]) — never the label. The receiver assigns their own petname.

This is why `~` does not violate the "no protocol info in shareable names" rule: `~` names are not shareable, by construction.

# Petname Store
[Petname Store]: #petname-store

The petname store is the user's own root [namestore][Namestore Layout] — the flat key-value map that path resolution walks. It is ordinary document data — replicated, merged, and versioned like any other [Automerge] content — with the following additional requirements.

## Writes
[Writes]: #writes

- Petname edges MUST only be writable under the user's own signing authority (a delegation in the root document's graph). Forged edges require local key compromise, which is out of scope.
- Local rename and edit are free: trust never flows through the label, so relabeling `~/bob` to `~/robert` changes nothing but display.

## Edge Contents
[Edge Contents]: #edge-contents

A petname edge is a **bare document reference**: the namestore maps the label directly to the referent's [Automerge URL], with no wrapping record.

```
{
  "bob":      "automerge:2nBeEM…",
  "bmann.ca": "automerge:9QxTf3…"
}
```

- The value MUST be a self-certifying document reference and nothing else (per [References]). Resolution reads the value directly; a value that is not a bare reference MUST be treated as absent and SHOULD be surfaced as malformed.
- Edges carry no metadata. The name the referent was introduced under — the **alleged name**, e.g. `@bob.example` or a QR-code display name — is recorded as an unverified claim in the [Binding Cache], never on the edge. Two reasons: a mutable target and frozen evidence inside one field-wise-merging object invite _torn_ CRDT states (one device's target beside another device's evidence), and the claim is a per-observer record about a third party, not document data the user should replicate to everyone they sync with.
- An edge MUST NOT be a symlink: it MUST NOT hold a name (of any anchor family) that would be re-parsed and re-resolved (see [References]).

In petname-system terms, Stiegler's classic trio survives the layout — relocated, not reduced: the value is the _key_, the map key is the _petname_ (trusted, local, yours), and the _alleged name_ is an untrusted claim stored alongside the other binding claims in the cache. The model's anti-spoofing property rests on never letting an alleged name occupy a petname slot without deliberate human action.

## Choosing Labels
[Choosing Labels]: #choosing-labels

At introduction time the label MAY default from the alleged name — meeting `@bmann.ca` suggests `~/bmann.ca` — subject to segment hygiene and user edit. Two rules keep this safe:

- The label and the recorded claim MUST remain independent even when initially equal: renaming `~/bmann.ca` to `~/boris` is the petname system's core feature, and it MUST NOT sever divergence detection — the alleged name is frozen evidence in the [Binding Cache], with a different lifetime than the label, untouched by namestore edits.
- A label's shape conveys nothing: `~/bmann.ca` does not mean "DNS-verified." Verification status is displayed from the binding cache, never inferred from spelling.
- Defaulting automates an attacker-chosen string into the namespace, so the badge doctrine extends to defaulted labels: implementations SHOULD display the corroboration status of the label's originating claim (unverified allegation · verified · diverged), computed from the [Binding Cache] — one QR scan can plant `~/wellsfargo.com`, and the only honest thing a UI can say about it is what the cache knows.

## Authority Boundary
[Authority Boundary]: #authority-boundary

The petname store holds the user's _own_ attestations only. Third-party attestations — notably verified DNS bindings — MUST NOT be written into the petname store, because the root document is signed: publishing `expede.wtf → K` under the user's signature is an attestation the user has no basis to make, and local malware could forge "verified" edges. Verified DNS bindings belong in the [Binding Cache], which confers no authority.

# Divergence and Re-Pin
[Divergence and Re-Pin]: #divergence-and-re-pin

The [Binding Cache] records what each hostname attested — verified certificates and unverified introduction claims alike — so drift is detected by a **document-ID join**, with no per-edge metadata: remember what was seen, compare on every use (the SSH `known_hosts` model).

- When a hostname's current binding attests a **different** document ID than its last-known (verified or claimed) one, implementations MUST surface divergence for every petname edge whose target is the superseded document. Surfacing follows the events-vs-states doctrine ([Prompt Grading]): a **fresh ✓** contradiction is an event and MAY prompt; a claim-only or stale ⚠ contradiction is a badge, with the interactive re-pin flow offered at use time or on user initiative — the weakest evidence must not be able to schedule prompts that stronger evidence deliberately cannot.
- Divergence MUST NOT be silently accepted (auto-repointing the edge) and SHOULD NOT hard-fail resolution; the pinned target keeps resolving while the user is prompted.
- Implementations MUST provide an explicit re-pin flow that updates the edge only on user confirmation.
- Divergence prompts MUST state the **direction and grade of the evidence** ([Prompt Grading]). A pin backed only by an unverified introduction claim, contradicted by a verified binding ("your pin came from an unverified introduction; the hostname's verified owner is a different document") is a different situation from a verified binding that has since changed ("bob's domain points somewhere new") — and a **stale ⚠** contradiction MUST NOT be rendered with the authority of a fresh ✓ one: a once-valid capture-era certificate must not out-argue an in-person introduction by borrowing the word "verified."

```
introduce:  ~/bob → automerge:2nBe…
            cache claim: @bob.example ⇒ automerge:2nBe… (unverified)
later:      @bob.example's verified cert names automerge:9QxT…
            → join on 2nBe… finds ~/bob
            → surface: "bob's domain points somewhere new" → re-pin?
```

# Offline Introduction and Upgrade
[Offline Introduction and Upgrade]: #offline-introduction-and-upgrade

Fully-offline introductions (QR code, verbal exchange, Bluetooth) root as petnames immediately:

1. The introduction payload carries the referent's [Automerge URL] and a suggested display name. It MUST NOT carry a `~` spelling (see [Local-Only by Construction]).
2. The receiver writes `~/<chosen-label> → <Automerge URL>` under their own authority; any alleged name in the payload is recorded as a claim entry in the user-private decision document ([Binding Cache spec]). The name works immediately, offline, forever.
3. If a certificate for a DNS binding to the **same** document ID later arrives (fetched or gossiped) and verifies per [DNS Anchoring], the identity gains a second spelling:

```
day 0 (field, no internet):  ~/bob            → automerge:2nBe…
day 30 (cert arrives):       @bob.example/…   → same document
```

The upgrade adds a spelling; it MUST NOT migrate identity, rewrite the petname edge, or re-key anything. `~/bob` and `@bob.example` simply converge on the same document ID.

# Handoff to Path Resolution
[Handoff to Path Resolution]: #handoff-to-path-resolution

The root store for a `~` name is the user's own petname store — always locally present, no verification step. Segments resolve per [Onomancy Path Resolution], starting with a greedy longest-key match in the user's own petname store; subsequent hops walk _other_ people's stores under exactly the same rules.

# Error Conditions
[Error Conditions]: #error-conditions

| Tag | Condition | Requirement |
|-----|-----------|-------------|
| P1 | Divergence detection severed by rename or edge edit | MUST NOT happen: the alleged-name claim lives in the [Binding Cache] and is untouched by namestore edits; renames move only the label |
| P2 | `~` name encountered in wire input | MUST be rejected as malformed |
| P3 | Serialization of a `~` name requested | MUST fail; no wire encoding exists |
| P4 | Divergence: a hostname's binding (verified or claimed) attests a different document ID than a pinned target | MUST surface for each affected edge (fresh ✓: event, MAY prompt; stale/claim-only: badge + use-time flow); MUST NOT auto-repoint; SHOULD keep resolving the pinned target |
| P5 | Concurrent edits to the same petname label | Deterministic winner, loser SHOULD be surfaced, per [Conflicting Updates] |
| P6 | Edge with a name in place of `target` (symlink) | MUST reject, per path-resolution E5 |

# Security Considerations
[Security Considerations]: #security-considerations

- _Compromise scope._ Petname integrity reduces to local signing-key custody. Malware **without** key access can read or corrupt caches but cannot forge edges; malware **with** key access is out of scope (game over).
- _Phishing surface._ Petnames never appear under `@`, so no petname can be confused with a DNS-anchored name at the grammar level — discrimination is by sigil, not spelling. A label that _resembles_ a DNS name (dots permitted) conveys no verification status; that is a display-layer concern, like confusable-label defenses generally (e.g. Cyrillic lookalikes chosen by the user).
- _Privacy._ `~` names never hit the wire, so the petname store leaks nothing by construction — but the store is replicated document data; its confidentiality is inherited from the document sync layer, not from this specification. The store contains only labels and targets: introduction provenance (alleged names) lives in the user-private decision document ([Binding Cache spec]) — E2EE, device-delegated, structurally unreadable by sync peers or groups.

# FAQ
[FAQ]: #faq

## Why can't I share a `~` name?

Because it doesn't denote anything outside your device: `~` is an index into _your_ root document. What you share is the referent (its [Automerge URL], or a certificate for its DNS binding); the receiver chooses their own label. This is the classic petname-system introduction pattern.

## Why don't edges carry a `met_as` field?

The alleged name lives in the [Binding Cache], not on the edge: an edge is a mutable, field-wise-merging, replicated object — the wrong home for frozen per-observer evidence (torn merges, provenance leaked to sync peers, foreign-field ambiguity) — and the tripwire never needs it there: the cache already keeps each hostname's last-known document ID, so [Divergence and Re-Pin] falls out of a join. An alleged name _is_ an unverified binding claim; it lives with the other binding claims.

## What happens to `~/bob` if Bob rotates keys?

Nothing. `target` is a document ID, and document IDs are stable forever ([Keyhive] identity keys are immutable; rotation happens in the delegation graph). Upstream key rotation flows through without touching your petname.

<!-- External Links -->

[Automerge]: https://automerge.org/
[Automerge URL]: https://automerge.org/docs/under-the-hood/document_urls/
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[Binding Cache]: ./dns-anchor.md#binding-cache
[Binding Cache spec]: ./binding-cache.md
[Prompt Grading]: ./binding-cache.md#prompt-grading
[Conflicting Updates]: ../path-resolution.md#conflicting-updates
[DNS Anchoring]: ./dns-anchor.md
[References]: ../path-resolution.md#references
[Namestore Layout]: ../path-resolution.md#namestore-layout
[Keyhive]: https://github.com/inkandswitch/keyhive
[Onomancy Name Grammar]: ../name-grammar.md
[Onomancy Path Resolution]: ../path-resolution.md
[Zooko's triangle]: https://en.wikipedia.org/wiki/Zooko%27s_triangle
[petname system]: http://www.skyhunter.com/marcs/petnames/IntroPetNames.html
