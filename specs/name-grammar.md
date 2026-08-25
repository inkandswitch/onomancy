# Onomancy Name Grammar Specification
## Version 0.1.0

## Dependencies
[Dependencies]: #dependencies

None. The anchoring specifications ([DNS Anchoring], [Petname Anchoring]) and [Onomancy Path Resolution] depend on _this_ document, not the other way around.

## Language
[Language]: #language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14] when, and only when, they appear in all capitals, as shown here.

# Abstract
[Abstract]: #abstract

This specification defines the textual grammar of Onomancy names: the three spelling families, parse-time anchor discrimination, the shared segment rules, and the doc-anchor payload. The anchoring specifications define what each family's anchor _means_; this document defines what parses.

# Introduction
[Introduction]: #introduction

Onomancy names are _edgenames_: a trust anchor followed by path segments. The anchor is decided _syntactically at parse time_ — parsing returns a structured value, never a string to be interpreted later, and there is no fallback or precedence between families. A name's trust root therefore can never shift with connectivity, lookup order, or domain-registration state.

# Grammar
[Grammar]: #grammar

``` abnf
name         = local-name / dns-name-ref / doc-name
local-name   = "~" *( "/" segment )
dns-name-ref = "@" dns-name *( "/" segment )
doc-name     = "automerge:" doc-id *( "/" segment )
dns-name     = label 1*( "." label )      ; ≥ one dot, post-normalization
doc-id       = bs58check-key              ; 32-byte ed25519 vk + checksum
segment      = 1*segment-char             ; see Segments
```

`dns-name` normalization and constraints (IDNA/A-labels, lowercasing, trailing-dot stripping, dotless rejection, IP-literal rejection, length limits) are normative in [DNS Anchoring]. The `~` anchor's semantics (local-only, no wire encoding) are normative in [Petname Anchoring].

# Anchor Disjointness
[Anchor Disjointness]: #anchor-disjointness

Each spelling family is exactly one anchor kind, discriminated by its first token:

| Leading token | Family        | Defined by                    |
|---------------|---------------|-------------------------------|
| `~`           | Local petname | [Petname Anchoring]           |
| `@`           | DNS name      | [DNS Anchoring]               |
| `automerge:`  | Doc anchor    | This document ([Doc Anchors]) |

- Parsers MUST NOT fall back between families: an input that fails to parse in its own family is a parse error, never reinterpreted as another family.
- Any input beginning with none of the three tokens MUST be rejected.
- Disjointness is the anti-phishing theorem: no string parses as more than one anchor class (see [design/verification.md](../design/verification.md), theorem 1).

# Segments
[Segments]: #segments

Segments are the path components after the anchor, shared by all three families:

- A segment MUST be non-empty. Empty segments (`@x.y//a`) MUST be rejected — there is no silent normalization.
- A segment MUST NOT be `.` or `..` — no traversal semantics exist to exploit.
- A segment MUST NOT contain `/` (the separator) or `#` (reserved in every family; see [No Version Pinning]).
- A segment MUST NOT contain control characters.
- Dots within a segment carry no meaning: anchor discrimination is entirely by the leading token, so `~/bmann.ca` is a legal label with no verification connotation.
- Segments compare byte-for-byte. Unicode normalization (NFC) and case policy at input boundaries are display-layer concerns and not yet fixed by this specification (see [design/names.md](../design/names.md#hygiene-rules)); implementations MUST NOT normalize during comparison.

An overall name-length budget (e.g. for QR-code introductions) is not yet fixed by this specification. DNS length limits (253 octets total, 63 per label) apply to `dns-name` per [DNS Anchoring].

# Doc Anchors
[Doc Anchors]: #doc-anchors

A doc anchor is a full [Automerge URL]: the payload encoding is upstream [automerge-repo]'s, not Onomancy's.

- `doc-id` MUST be the upstream text encoding of a key-based document ID: bs58check over the 32-byte ed25519 verifying key. Onomancy defines no encoding of its own; algorithm agility is upstream's concern.
- A payload whose checksum fails MUST be rejected as a parse error — transcription typos fail loudly rather than silently denoting a different valid key.
- A payload that decodes to a **16-byte legacy** Automerge document ID MUST be rejected with an error _distinct_ from a generic parse failure: it is a valid Automerge URL but not self-certifying, so it cannot anchor a name.
- A payload that decodes to any other length MUST be rejected.

# No Version Pinning
[No Version Pinning]: #no-version-pinning

Names are always LIVE: the grammar carries no version pins, and `#` is a reserved character rejected everywhere it could appear.

Pinning is data, not grammar. A party that wants a pinned reference writes an edge whose target addresses a pinned document state — the pin then lives in a replicated, authored document rather than an ephemeral string. (Whether a reference encoding supports pinned targets is profile-defined; see [Onomancy Path Resolution].)

A trailing `#` fragment was deliberately removed from the grammar: RFC 3986 intuition reads a fragment as the state of the RESOLVED resource, while segments resolve through documents at every hop — any single pin position is either misleading or incomplete. Reserving `#` keeps every extension option open.

# The Parsed Type
[The Parsed Type]: #the-parsed-type

Parse-don't-validate: no string name exists downstream of the parser. Every consumer receives a structured value whose invariants are already established:

``` rust
pub enum Anchor {
    /// `~` — your signed root doc. Local-only; no wire encoding exists.
    Local,
    /// `@name.tld` — DNSSEC-attested, post-normalization.
    Dns(DnsName),
    /// `automerge:…` — the doc ID IS an ed25519 vk. Self-certifying.
    Doc(DocAnchor),
}

pub struct Name<A: Anchor> {
    anchor: A,
    segments: Vec<Segment>, // each non-empty, validated at parse
}
```

# Error Conditions
[Error Conditions]: #error-conditions

| Tag | Condition                                                               | Requirement                                                   |
|-----|-------------------------------------------------------------------------|---------------------------------------------------------------|
| N1  | Input begins with none of `~`, `@`, `automerge:`                        | MUST reject; no family fallback                               |
| N2  | Segment empty, `.`, `..`, or containing `/`, `#`, or control characters | MUST reject                                                   |
| N3  | Doc-anchor payload fails its bs58check checksum                         | MUST reject (parse error)                                     |
| N4  | Doc-anchor payload decodes to a 16-byte legacy document ID              | MUST reject with a distinct legacy-ID error                   |
| N5  | Doc-anchor payload decodes to any length other than 32 bytes            | MUST reject                                                   |
| N6  | `#` anywhere in the input                                               | MUST reject (reserved; see [No Version Pinning])              |
| N8  | Dotless `@` name, IP literal, or malformed DNS name                     | MUST reject per [DNS Anchoring] (its D1)                      |

# Conformance
[Conformance]: #conformance

The reference implementation is `onomancy_core::name`; the Lean model and extracted conformance vectors (see [design/verification.md](../design/verification.md)) check the implementation against this grammar. Where this document and the implementation disagree, this document is normative.

<!-- Internal Links -->

[DNS Anchoring]: ./anchoring/dns-anchor.md
[Onomancy Path Resolution]: ./path-resolution.md
[Petname Anchoring]: ./anchoring/petname-anchor.md

<!-- External Links -->

[Automerge URL]: https://automerge.org/docs/under-the-hood/document_urls/
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[automerge-repo]: https://github.com/automerge/automerge-repo
