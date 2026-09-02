# Onomancy Specifications

Normative specifications for **Onomancy**, a local-first edgename protocol, written in the [BCP 14] keyword convention. _Onomancy_ is the protocol (grammar, records, certificate, and resolution semantics) and _Onomancer_ is the reference implementation (the tool that helps you practice onomancy). The [design](../design/) directory holds the rationale and threat model these specifications are derived from.

| Spec                       | Scope                                                                                                                                                                         |
|----------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Onomancy Name Grammar]    | The textual grammar: three spelling families, parse-time anchor disjointness, shared segment rules, doc-anchor payload, and the no-version-pinning rule.                      |
| [Onomancy Path Resolution] | Resolving segments across documents: flat edge maps, greedy longest-key matching, hops, termination, error conditions. Anchor-agnostic.                                       |
| [DNS Anchoring]            | Rooting `@` names in DNSSEC: TXT binding record, the Onomancy certificate and its in-document location, generation key, chain validation, graded freshness, succession.                 |
| [Binding Cache]            | The verifier's store and its derived view: `derive(store, now, decisions)`: union-merge record sync, the user-private decision document (claims, acceptances, resets), surfacing-as-diff, pruning.        |
| [Petname Anchoring]        | Rooting `~` names in the user's own root document: local-only property, petname store, divergence/re-pin, offline-introduction upgrade path.                                  |
| [Serialization]            | Wire encodings for the proof records: canonical certificate encoding (the signature target), DNSSEC/delegation chain framing, TXT record grammar. Built on [bijou64] varints. |

## Anchors vs Edges

|                   | Anchor                                                                                                                                  | Edges (path segments)                          |
|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------|
| Question answered | Where does trust start?                                                                                                                 | Where does the walk go?                        |
| Appears in a name | Once, at the front (`~`, `@expede.wtf`, `automerge:2nBe…`)                                                                              | Zero or more, after the anchor (`/bob/pics`)   |
| Decided by        | The name's spelling, at parse time                                                                                                      | The contents of namestores, at resolution time |
| Specified in      | [Onomancy Name Grammar] (spelling), then [DNS Anchoring], [Petname Anchoring] (doc anchors need no anchoring step: the URL is the root) | [Onomancy Path Resolution]                     |

### Anchors

The **anchor** establishes the _root namestore_ and is the only place trust enters: `~` roots in your own signed namestore, `@` roots in a DNSSEC chain from the IANA KSK, and `automerge:` roots in a self-certifying document ID. Which family applies is a parse-time fact — no fallback, no precedence rules — so a name's trust root can never shift with network state.

### Edges

The **edges** are what path resolution walks after the root is established: each matched key in a namestore yields a reference to the next namestore, one hop per match, terminating in at most `len(segments)` hops. Edges hold references, never names — they cannot re-enter anchoring (no symlinks), and they confer no authority of their own. Whoever controls a namestore controls only which references its keys map to, not how much the walker trusts them.

## Resolution

``` mermaid
flowchart TD
    P["~/bob/pics"] --> PA["root = your own namestore"]
    D["@expede.wtf/bob/pics"] --> DA["root = cert.root_doc,<br/>verified from IANA KSK"]
    A["automerge:2nBe…/bob/pics"] --> AA["no anchoring step:<br/>the URL names the root"]

    PA --> R
    DA --> R
    AA --> R

    R["greedy namestore walk, one hop per<br/>matched key, ≤ len(segments) hops"]
```

<!-- Internal Links -->

[Binding Cache]: ./anchoring/binding-cache.md
[DNS Anchoring]: ./anchoring/dns-anchor.md
[Onomancy Name Grammar]: ./name-grammar.md
[Onomancy Path Resolution]: ./path-resolution.md
[Petname Anchoring]: ./anchoring/petname-anchor.md
[Serialization]: ./serialization.md

<!-- External Links -->

[BCP 14]: https://www.rfc-editor.org/info/bcp14
[bijou64]: https://github.com/inkandswitch/bijou/blob/main/bijou64/SPEC.md
