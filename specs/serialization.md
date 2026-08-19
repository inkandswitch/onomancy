# Onomancy Serialization Specification
## Version 0.1.0

## Dependencies
[Dependencies]: #dependencies

- [bijou64] — bijective variable-length integers (the [bijoux] crate)
- [DNS Anchoring] — defines the records this document gives byte layouts for
- [Keyhive] — defines the `Signed<Delegation>` encoding, carried verbatim

## Language
[Language]: #language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14] when, and only when, they appear in all capitals, as shown here.

# Abstract
[Abstract]: #abstract

This specification defines the wire encodings for Onomancy's proof records: the canonical binary encoding of the Onomancy certificate (the signature target), the framing of the embedded DNSSEC and delegation chains, and the grammar of the TXT binding record.

# Introduction
[Introduction]: #introduction

Signatures attest bytes, so the meaning of signed bytes must be beyond dispute. Three properties carry that: decoding is **deterministic and strict** (one byte string has at most one reading, in every implementation — the parser-differential attack class dies here), encoding **round-trips** (`decode(encode(cert)) = cert`: what the signer meant is exactly what verifiers decode), and the leading format tag **domain-separates** certificate bytes from every other signed artifact. Together these make the encoding injective and canonical — each certificate has exactly one wire form and vice versa — which caches, test vectors, and the formal model also rely on.

Rather than enforcing these properties against a general-purpose codec, Onomancy uses encodings that satisfy them by construction: fixed field order, fixed-width cryptographic material, and [bijou64] varints — every integer has exactly one byte representation and every representation decodes to exactly one integer.

Determinism and roundtrip of the composite encoding are formal-verification targets, with injectivity as their corollary (see [design/verification.md](../design/verification.md)).

# Integers
[Integers]: #integers

All variable integers — lengths, counts, versions, and timestamps — MUST be encoded as [bijou64]: a tag-byte-prefixed, big-endian, per-tier-offset encoding of `u64` in 1–9 bytes, canonical by construction. This document does not restate the format; the [bijou64 SPEC] is normative, and the [bijoux] crate is the reference implementation.

Consequences relied on by this specification:

- One encoding per value (no overlong forms to reject)
- The tag byte alone determines total length (no lookahead)
- Lexicographic byte order matches numeric order

Fixed-width cryptographic material (keys, hashes, signatures) is encoded raw, without length prefixes, at the widths given below.

# Certificate Encoding
[Certificate Encoding]: #certificate-encoding

## Layout
[Layout]: #layout

Fields MUST be encoded in exactly this order, with no padding between fields. Within the signed region, fixed-width fields come first (constant byte offsets: a parser reads the tag and keys without decoding a single varint), then variable-width fields; the signature closes the signed region, and everything after it is the attached region (see [Signature Target]):

| #  | Field              | Width (bytes) | Encoding                                                                                                                                                       | Signed |
|----|--------------------|---------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|--------|
| 0  | Format tag         | 4             | ASCII schema `ONC` + version byte `0x00` (`ONC\x00`)                                                                                                           | yes    |
| 1  | `root_doc`         | 32            | raw bytes (ed25519 verifying key = document ID)                                                                                                                | yes    |
| 2  | `signer`            | 32                   | raw bytes (ed25519 verifying key)                                                                                                                | yes |
| 3  | `issued_at`         | variable             | bijou64: seconds since the Unix epoch (UTC)                                                                                                      | yes |
| 4  | `hostname_len`      | variable             | bijou64: byte length of `hostname`                                                                                                               | yes |
| 5  | `hostname`          | `hostname_len`       | ASCII bytes: the FULL DNS name from the `@` anchor, subdomains included (A-labels, lowercase, no trailing dot)                                   | yes |
| 6  | `heads_count`       | variable             | bijou64: number of heads; 0 = live (unpinned) name                                                                                               | yes |
| 7  | `heads`             | `heads_count` × 32   | raw 32-byte change hashes, sorted ascending bytewise, no duplicates                                                                              | yes |
| 8  | `predecessor_count`   | variable             | bijou64: byte length of `predecessor`; 0 = none                                                                                                  | yes |
| 9  | `predecessor`       | `predecessor_len`    | one [Successor Statement] unit (`ONS\x00`, authority carriage included)                                                                          | yes |
| 10 | `signature`         | 64                   | raw bytes (ed25519 signature by `signer` over fields 0–9)                                                                                        | —   |
| 11 | `delegation_count`  | variable             | bijou64: number of delegation-chain entries                                                                                                      | no  |
| 12 | `delegation_chain`  | variable             | `delegation_count` entries, ordered doc root → signer; each entry = `entry_len` as bijou64 + `entry_len` verbatim [Keyhive] `Signed<Delegation>` bytes | no |
| 13 | `lineage_count`     | variable             | bijou64: number of lineage entries; 0 = never rotated                                                                                            | no  |
| 14 | `lineage`           | variable             | `lineage_count` entries, oldest first; each entry = `entry_len` as bijou64 + one [Rotation Statement] unit (`ONR\x00`, authority carriage included) | no |
| 15 | `chain_count`       | variable             | bijou64: number of DNSSEC chain links                                                                                                            | no  |
| 16 | `chain`             | variable             | `chain_count` links per [DNSSEC chain framing](#dnssec-chain-framing); each link = `link_len` as bijou64 + `link_len` DNS wire-format bytes      | no  |

Splitting convention: every top-level length or count is its own field (`hostname_len`, `heads_count`, …) so offsets and field boundaries are explicit; the per-entry `entry_len`/`link_len` prefixes _inside_ repeating groups remain part of the group's field, since their positions depend on the preceding entries.

- A `heads_count` of zero means a live (unpinned) name. There is no separate "absent" encoding: `None` and "empty" MUST encode identically — the distinction does not exist on the wire.
- `predecessor` follows the same rule: `predecessor_len` 0 IS the absent case, with no separate flag. The statement bytes are the [Successor Statement] encoding defined below — self-contained (signature and authority carriage included); the certificate codec treats the unit as a length-prefixed blob.
- `predecessor` is inside the signature: a successor proof cannot be stripped or grafted without invalidating the certificate.
- `heads` MUST be sorted and MUST NOT contain duplicates; decoders MUST reject unsorted or duplicated heads.
- `hostname` is the full DNS name from the `@` anchor — subdomains included, not necessarily a zone apex; it matches the TXT owner name minus the `_onomancy` label. It MUST already be in canonical form per [DNS Anchoring] (A-labels, lowercase, no trailing dot); decoders MUST reject non-canonical bytes rather than normalizing.

## Signature Target
[Signature Target]: #signature-target

The signature covers the concatenated encoding of fields 0–9 — including the format tag, which provides domain separation and format versioning in four bytes (the schema convention shared with [subduction], e.g. its `SUE\x00`; a future certificate format is `ONC\x01`, and other onomancy artifacts get their own three-letter schemas — rotation and successor statements use `ONR\x00` and `ONS\x00` ([Statement Encodings])) — and excludes everything after the signature.

Fields 11–16 form the **attached region**: independently verifiable evidence, deliberately outside the signature because each item has its own lifecycle and can be replaced by a keyless machine without invalidating the certificate:

- `delegation_chain` is self-authenticating (every hop is signed); any valid chain from the document root to the same `signer` is interchangeable proof, so after a generation rotation a surviving signer's certificate is repaired by **re-attaching** a chain through the new generation key — no re-signing.
- `lineage` (rotation statements, see [DNS Anchoring]) grows by one self-authenticating entry per rotation and is refreshed the same way. It SHOULD be complete from the first rotation — partial lineage weakens offline comparison to exactly the span it covers.
- `chain` (DNSSEC) is verified against the verifier's own trust anchor and refreshed as RRSIG windows lapse.

Two certificates differing only in attached fields are the _same_ certificate carrying different evidence.

Verifiers MUST NOT accept a signature over any other byte sequence, and signers MUST NOT sign decoded/re-encoded structures — the wire bytes of fields 0–9 are the target.

## Delegation Chain Bytes
[Delegation Chain Bytes]: #delegation-chain-bytes

Each `Signed<Delegation>` is carried as the **verbatim** [Keyhive] wire encoding, length-prefixed and otherwise treated as an opaque blob by this codec. Onomancy does not re-encode, canonicalize, or introspect these bytes at the serialization layer; they are interpreted only by Keyhive verification.

> [!WARNING]
> This makes the certificate format normatively dependent on Keyhive's wire encoding remaining stable. The depended-upon Keyhive version MUST be pinned and tracked; a Keyhive encoding change is a certificate format change (new format tag).

# Statement Encodings
[Statement Encodings]: #statement-encodings

Rotation statements and successor statements are signed artifacts in their own right, and everything the [Introduction] demands of the certificate — strict deterministic decoding, roundtrip, format-tag domain separation, injectivity — applies to them identically. A statement whose bytes are ambiguous is a statement whose signature is ambiguous, and these two statements are the inputs to the lineage ratchet and the succession check.

Each statement travels as one self-contained unit: signed fields, signature, then its [Authority Carriage] — the delegation-chain proof that its signer speaks for the document it makes claims about. A statement without a valid carriage is not a weaker statement; it is malformed evidence ([DNS Anchoring]'s statement-validity rules).

## Rotation Statement
[Rotation Statement]: #rotation-statement

| # | Field       | Width (bytes) | Encoding                                                       | Signed |
|---|-------------|----------|-----------------------------------------------------------------|--------|
| 0 | Format tag  | 4        | `ONR\x00`                                                      | yes    |
| 1 | `root_doc`  | 32       | raw bytes (document whose generation is rotating)              | yes    |
| 2 | `replaced`  | 32       | raw bytes (Gₙ, the generation key being retired)               | yes    |
| 3 | `successor` | 32       | raw bytes (Gₙ₊₁; also the statement's signer)                  | yes    |
| 4 | `signature` | 64       | raw bytes (ed25519 by `successor` over fields 0–3)             | —      |
| 5 | `authority_count` | variable | bijou64: number of carriage entries ([Authority Carriage]) | no     |
| 6 | `authority` | variable | `authority_count` entries: each = `entry_len` as bijou64 + `entry_len` verbatim `Signed<Delegation>` bytes, for `successor` in `root_doc` | no |

No hostname appears, deliberately: a revoked generation must die across every name bound to the document in one ceremony, and `root_doc` inside the signature prevents cross-document lineage replay under key reuse ([DNS Anchoring], Generation Lineage).

## Successor Statement
[Successor Statement]: #successor-statement

| # | Field             | Width (bytes) | Encoding                                                                      | Signed |
|---|-------------------|----------|--------------------------------------------------------------------------------|--------|
| 0 | Format tag        | 4        | `ONS\x00`                                                                     | yes    |
| 1 | `predecessor_doc` | 32       | raw bytes                                                                     | yes    |
| 2 | `successor_doc`   | 32       | raw bytes                                                                     | yes    |
| 3 | `signer`          | 32       | raw bytes (the delegated admin key of `predecessor_doc` that signed this)     | yes    |
| 4 | `hostname_len`    | variable | bijou64: byte length of `hostname`                                            | yes    |
| 5 | `hostname`        | `hostname_len` | ASCII bytes, canonical form per [DNS Anchoring]                         | yes    |
| 6 | `signature`       | 64       | raw bytes (ed25519 by `signer` over fields 0–5)                               | —      |
| 7 | `authority_count` | variable | bijou64: number of carriage entries ([Authority Carriage])                    | no     |
| 8 | `authority`       | variable | `authority_count` entries: each = `entry_len` as bijou64 + `entry_len` verbatim `Signed<Delegation>` bytes, for `signer` in `predecessor_doc` | no |

The hostname is inside the signature, deliberately: migration is per-name, and an unscoped proof could be replayed under a different name to disguise capture as continuity ([DNS Anchoring], Succession).

## Authority Carriage
[Authority Carriage]: #authority-carriage

```
authority_count as bijou64
repeat authority_count times:
    entry_len as bijou64
    entry_len bytes: verbatim Keyhive Signed<Delegation>
```

The same framing and verbatim-[Keyhive] treatment as the certificate's `delegation_chain`. The carried chain MUST root at the statement's document (`root_doc` / `predecessor_doc`), MUST terminate at the statement's signer, and the hop that delegates to the signer MUST be held at admin access — naming authority sits above collaboration authority for statements exactly as for certificates. Unlike the certificate's attached region, the carriage rides _inside_ the statement unit (and thus inside whatever region carries the statement): it is frozen history — the document's graph as of the ceremony — and never needs the keyless-refresh lifecycle.

# Content Addressing
[Content Addressing]: #content-addressing

Store items (see the [Binding Cache spec]) are exact byte strings: a certificate unit, a statement unit, a framed chain refresh. The **content hash** of an item is BLAKE3-256 over those exact bytes. Judgment-document entries reference store items by content hash, so hashes MUST be computed over the item's verbatim wire bytes — never over re-encoded or normalized forms.

Judgment itself — acceptances, resets, claims — has **no wire encoding in this specification**: it lives in the user-private judgment document, whose replication, authentication, and privacy are the document substrate's job; the [Binding Cache spec] defines its entry schema as a data-shape contract. Only _records_ need canonical bytes here, because only records are content-addressed and gossiped.

# DNSSEC Chain Framing
[DNSSEC Chain Framing]: #dnssec-chain-framing

The chain is a sequence of links, root to leaf:

```
chain_count as bijou64
repeat chain_count times:
    link_len as bijou64
    link_len bytes: DNS wire format
```

- Each link MUST be the [RFC 4034] canonical wire form of one RRset together with its RRSIG(s) — the same bytes DNSSEC signature validation is defined over. This codec adds framing only; it never re-encodes DNS data.
- Links MUST be ordered from the root zone toward the owner name (`_onomancy.<name>`), covering every zone cut and indirection en route.
- NSEC/NSEC3 denial-of-existence records, where present, are links like any other.

# TXT Record Grammar
[TXT Record Grammar]: #txt-record-grammar

The binding record at `_onomancy.<name>` (see [DNS Anchoring]) MUST match:

``` abnf
binding    = format ";" keyalg ";" serial ";" genkey ";" pubkey
format     = "v=ONO" 1*DIGIT              ; self-identifying format tag; "ONO0" here
keyalg     = "k=" "ed25519"               ; only value at v=ONO0
serial     = "n=" ( "0" / %x31-39 *19DIGIT ) ; decimal u64: no leading zeros,
                                          ; at most 20 digits; decoders MUST
                                          ; reject values exceeding 2^64 - 1
genkey     = "g=" b64-32                  ; the 32-byte generation key
pubkey     = "p=" b64-32                  ; the 32-byte document ID
b64-32     = 43base64char "="             ; RFC 4648 §4 (standard, padded)
                                          ; encoding of exactly 32 bytes:
                                          ; 43 alphabet chars + one pad
base64char = ALPHA / DIGIT / "+" / "/"
```

- Field order is fixed (`v`, `k`, `n`, `g`, `p`); there is no whitespace; the separator is a single `;`.
- A conforming `ONO0` record is at most 133 octets (7 + 10 + 23 + 47 + 46) and MUST fit in a single TXT character-string; the multi-string concatenation rule below exists only for tolerance of splitting tooling.
- Within a recognized format tag, decoders MUST reject records with unknown fields, reordered fields, non-canonical integers (leading zeros), or malformed base64. Extension happens by format-tag bump (`ONO1`), not by field tolerance — the record is a trust root, and parser leniency is attack surface.
- Records with an unrecognized `ONO`-prefixed tag are skipped; TXT records without a `v=ONO…` tag are foreign and ignored (see [DNS Anchoring] on format evolution).
- Multiple strings within one TXT RDATA MUST be concatenated before parsing, per standard TXT semantics.

# Size Limits
[Size Limits]: #size-limits

- A certificate or statement unit larger than **1 MiB** (2²⁰ bytes) MUST be rejected at decode. The cap is deliberately generous — honest certificates run 10–100 KB, dominated by the DNSSEC chain, so 1 MiB is one to two orders of magnitude of headroom — because its job is bounding adversarial memory (a gossiped "certificate" a verifier must chew through before any signature check rejects it), not constraining honest growth. It is part of the format contract: raising it is a specification revision, since a conforming verifier rejects units beyond it.
- Decoders MUST validate every declared length and count against the remaining input **before allocating**: a bijou64 length or count that implies bytes beyond the end of the unit is a decode failure, never an allocation. With the unit cap, this bounds all collection sizes implicitly — no per-field count limits are needed.
- The TXT record is already bounded by its own grammar (≤ 133 octets); the judgment document is bounded by its substrate.

# Test Vectors
[Test Vectors]: #test-vectors

Golden vectors — encoded bytes with their decoded structures — live in `onomancy_core/tests/vectors/` and are consumed by bolero conformance tests. Vectors are extracted from the Lean reference model (see [design/verification.md](../design/verification.md)); the encoding-injectivity theorem (theorem 5) is stated against the model of this document.

At minimum the vector set MUST cover: zero and maximal `heads` counts, absent and present `predecessor` (length 0 vs non-zero), empty and non-empty `lineage`, delegation chains that do and do not pass through an attested generation key, a chain re-attach (same signed bytes, different attached region — same certificate), bijou64 tier boundaries within lengths and timestamps, a multi-link DNSSEC chain crossing a zone cut, and mutation cases (unsorted heads, duplicated heads, non-canonical hostname, overlong-adjacent integers) that MUST fail decoding.

Statement vectors MUST additionally cover: valid `ONR\x00` and `ONS\x00` units; statements with empty, wrong-root, wrong-terminus, and non-admin authority carriages (all MUST fail validation, not merely warn); a rotation statement replayed under a different `root_doc` and a successor statement replayed under a different `hostname` (both MUST fail); lineage chain-shape violation sets — double-successor, double-replace, and a cycle from generation-key reuse — which MUST derive as surfaced forks ([DNS Anchoring] D18), never as order-dependent validity failures; and cross-tag confusion cases (certificate bytes offered where a statement is expected and vice versa — the format tags MUST make these fail at decode).

Content-addressing vectors MUST cover hash stability: the hash of a certificate unit changes when its attached region changes — two hashes, one certificate identity — and hashes over verbatim bytes never match hashes over re-encoded forms.

# Security Considerations
[Security Considerations]: #security-considerations

- _Deterministic parsing is the point._ Every rule above that forbids a second spelling or a second reading (bijou64, fixed field order, sorted heads, no absent-vs-empty distinction, canonical hostnames, strict TXT grammar) exists so that one byte string means one thing and one certificate has one byte string — no parser differentials, no re-encode mismatches.
- _Decoders are strict, never normalizing._ Any input that is not the canonical encoding MUST be rejected. Accept-then-canonicalize would reintroduce exactly the aliasing these rules remove (the bug class behind DER-malleability incidents: verify received bytes, act on re-encoded ones).
- _The attached region is not a loophole._ Every attached item is independently verifiable: the DNSSEC chain against the verifier's own KSK (cross-checked against signed `hostname` and `root_doc`), the delegation chain by its own signatures (terminating at the signed `signer`, threading the TXT-attested generation key), and lineage entries by keys on the document's own chain. An attacker who swaps attachments can only cause rejection or staleness, never a false bind.

<!-- External Links -->

[BCP 14]: https://www.rfc-editor.org/info/bcp14
[Binding Cache spec]: ./anchoring/binding-cache.md
[DNS Anchoring]: ./anchoring/dns-anchor.md
[Keyhive]: https://github.com/inkandswitch/keyhive
[RFC 4034]: https://www.rfc-editor.org/rfc/rfc4034
[bijou64]: https://github.com/inkandswitch/bijou/blob/main/bijou64/SPEC.md
[subduction]: https://github.com/inkandswitch/subduction
[bijou64 SPEC]: https://github.com/inkandswitch/bijou/blob/main/bijou64/SPEC.md
[bijoux]: https://crates.io/crates/bijoux
