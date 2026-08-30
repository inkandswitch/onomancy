# Onomancy Path Resolution Specification
## Version 0.1.0

## Dependencies
[Dependencies]: #dependencies

None. This specification is anchor-agnostic and substrate-agnostic: the anchoring specifications ([DNS Anchoring], [Petname Anchoring]) depend on _this_ document, not the other way around, and any substrate satisfying the [Namestore Model] can host the walk.

## Language
[Language]: #language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14] when, and only when, they appear in all capitals, as shown here.

# Abstract
[Abstract]: #abstract

This specification defines how a sequence of path segments are resolved against a graph of namestores: the namestore layout, the greedy matching rule, hop mechanics, termination, and error conditions.

# Introduction
[Introduction]: #introduction

Onomancy names are _edgenames_: a trust anchor followed by path segments, where segments match edges in a namestore[^gns] and each matched edge lands in another namestore. This document specifies the walk itself; it confers no authority and assumes none. How a resolver obtains the _root namestore_ that resolution starts from is the concern of the anchoring specifications — path resolution takes some root namestore as given and behaves identically regardless of which anchor family produced it.

[^gns]: The term is borrowed from the [GNU Name System], whose per-zone record database is called the namestore. GNS resolution is likewise a walk over linked local namespaces via delegation records; Onomancy generalizes the term to every node in the walked graph, not only the resolver's own zones.

# Terminology
[Terminology]: #terminology

| Term                | Meaning                                                                      |
|---------------------|------------------------------------------------------------------------------|
| Namestore           | A flat key-value map, addressed by a namestore reference                     |
| Namestore reference | A self-certifying identifier that designates exactly one namestore           |
| Path                | A key in a namestore: one or more segments joined by `/`                     |
| Reference           | A value in a namestore, yielding exactly one target namestore reference      |
| Hop                 | Following one reference from the current namestore to its target namestore   |
| Segment             | A non-empty path component, as produced by the name parser                   |

# Namestore Model
[Namestore Model]: #namestore-model

Path resolution is defined over any substrate providing:

| Property                          | Requirement Level                | Description                                                                                                                                                                |
|-----------------------------------|----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Self-certifying references        | REQUIRED                         | A namestore reference MUST designate exactly one namestore, independent of who supplies the bytes (e.g. an identifier that is or commits to a verifying key)               |
| Flat string-keyed maps            | REQUIRED                         | A namestore is a map from strings to values; nothing more is assumed about what a namestore contains                                                                       |
| Deterministic conflict resolution | REQUIRED (replicated substrates) | Concurrent writes to the same key MUST resolve to one deterministic winner, with the losing value(s) still observable                                                      |

A namestore MAY be embedded in a larger document (e.g. as one field among other application data). The namestore is the map itself, not its container: path resolution reads only the map, and a namestore reference designates the map's location within the containing document, however the substrate expresses that.

# Namestore Layout
[Namestore Layout]: #namestore-layout

- Namestores MUST be flat: resolvers MUST NOT descend into nested values during path resolution. Multi-segment reach within one namestore is expressed by multi-segment _keys_, not by nesting.
- Keys MUST be paths: one or more valid segments joined by `/`.
- Keys containing empty segments (`foo//bar`), `.` or `..` segments, or `#` MUST be rejected outright — there is no normalization for these.
- Writers MUST NOT add leading or trailing `/` to keys (`/foo/bar/`); `foo/bar` is the only spelling of that path. Resolvers MUST ignore non-conforming keys during matching (treat them as absent) and SHOULD surface them as malformed.
- A namestore MAY contain both a key and a longer key that extends it (e.g. `foo` and `foo/bar/baz`). This is not a conflict; the [Resolution] section defines which one a given lookup selects.
- Keys under `.well-known/` are conventionally used for protocol and application data rather than names, namespaced by owner: `.well-known/<owner>/<artifact>`. This is a **writers' convention only** — resolvers apply no special rule to the prefix, because such entries carry values that are not references and are already absent from matching ([E8][Error Conditions]). An entry under the prefix whose value *is* a reference resolves like any other. This specification assigns `.well-known/onomancy/` to the Onomancy protocol and reserves no other owner.

Namestore (flat):

```
{
  "foo":          <reference>,
  "foo/bar/baz":  <reference>,
  "pics":         <reference>
}
```

NOT this (nested):

```
{
  "foo": {
    "bar": { "baz": … }
  }
}
```

## References
[References]: #references

This specification does not define an encoding for references; that belongs to the profile or substrate that writes them. Whatever the encoding, a reference MUST yield exactly one _target_: a namestore reference (self-certifying, per the [Namestore Model]) that carries no path segments of its own. A profile MAY define reference encodings that pin the target to a version — pinning is edge data, never name grammar.

The RECOMMENDED encoding is a **bare reference** — the value _is_ the target, nothing more (e.g. [Petname Anchoring] maps labels directly to Automerge URLs). Richer values are permitted but discouraged: field-wise CRDT merges can tear a composite value (one writer's target beside another's metadata), and unknown fields become parsing policy. Metadata *about a reference* (display names, timestamps, provenance) SHOULD live in a sidecar outside the walked map, keyed by label or target. Metadata, wherever it lives, MUST NOT affect resolution.

A value that is not a reference under any encoding the profile defines is not an edge: it is absent from matching ([E8][Error Conditions]) and carries no resolution meaning. Namestores MAY therefore hold non-reference data — see the `.well-known/` convention in [Namestore Layout] — without that data participating in the walk.

> [!IMPORTANT]
> **No symlinks.** A reference MUST NOT contain a name (of any anchor family) that would be re-parsed and re-resolved. Namestore values hold namestore references only. This invariant is what makes [Termination] structural rather than policed by a hop limit.

# Resolution
[Resolution]: #resolution

Input: a root namestore `S` and a segment list `segments`.

1. If `segments` is empty, resolution succeeds with `S` itself.
2. Otherwise, perform a **greedy longest-key match**: among the keys of `S`, select the key `k` with the greatest number of segments such that `k`'s segments are a prefix of `segments` _at segment boundaries_.
3. If no key matches, resolution ends `Partial` with reason `DanglingSegment` (see [Error Conditions]).
4. Consume `len(k)` segments and load the namestore designated by the matched reference's target. If that namestore is unavailable (e.g. not yet replicated), resolution ends `Partial` with reason `UnsyncedTarget` — the data is unavailable, not wrong. Otherwise repeat from step 1 with the remaining segments.

``` mermaid
flowchart TD
    N["Name { anchor, segments }"] --> A["root namestore S<br/>(per anchoring spec)"]
    A --> E{"segments empty?"}
    E -->|yes| R["Resolved(S)"]
    E -->|no| M{"longest key<br/>matching a segment prefix?"}
    M -->|none| P["Partial(DanglingSegment)"]
    M -->|"key k"| H["consume len(k) segments,<br/>load target namestore"]
    H --> E
```

## Greedy Matching
[Greedy Means Greedy]: #greedy-matching

Matching MUST select the longest matching key and MUST NOT backtrack: if the selected edge later leads to a `Partial` or `Failed` outcome, the resolver MUST NOT retry with a shorter key.

Given the namestore `{ "foo": doc_a, "foo/bar/baz": doc_b }`:

| Resolve            | Match                                                                   | Result                                 |
|--------------------|-------------------------------------------------------------------------|----------------------------------------|
| `foo/bar/baz/quux` | `foo/bar/baz` (3 segments)                                              | hop to `doc_b`, continue with `[quux]` |
| `foo/bar`          | `foo` (1 seg) — `foo/bar/baz` is not a prefix of the remaining segments | hop to `doc_a`, continue with `[bar]`  |
| `foo/bar/baz`      | `foo/bar/baz`                                                           | hop to `doc_b`, done                   |

Segment-boundary matching means `foo/bar` MUST NOT match the key `foo/ba`; keys and segments compare as whole segments, byte-for-byte after parse-time normalization.

## Conflicting Updates
[Conflicting Updates]: #conflicting-updates

[CRDT] merges can produce conflicting values for the same key. Resolvers MUST pick the substrate's deterministic conflict winner, but SHOULD surface the losing value(s) to the caller.

# Termination
[Termination]: #termination

Each hop consumes at least one segment (paths are non-empty), so resolution performs at most `len(segments)` hops. Cycles in the namestore graph are harmless: in `~/alice/bob/alice`, the two `alice` edges live in different namestores, and the walk still strictly consumes segments.

Resolvers MUST NOT impose a hop limit as a substitute for the no-symlink invariant (see [References]); the invariant is the termination proof.

# No Version Pinning
[Heads]: #no-version-pinning

Names carry no version pins: every namestore in a walk is read LIVE, at its current state. A party that wants a pinned reference writes an edge whose target addresses a pinned document state (where the profile's reference encoding supports it) — the pin then lives in a replicated, authored document, is scoped to exactly one hop, and composes per-edge instead of freezing states its author never saw.

This specification does not define pinned-target behavior. A profile that adds pinned targets must answer two questions this document leaves open: what the resolver reads when it follows a pinned edge (the target at the pinned state, by whatever mechanism the substrate provides), and what happens when the local replica has not yet synced that state (a `Partial`, like any unsynced target — unavailable is not wrong).

# Results
[Results]: #results

``` rust
pub enum Resolution {
    Resolved(Namestore),
    Partial { resolved_prefix: Vec<Segment>, reason: PartialReason },
    Failed(ResolveError),
}
```

`Partial` outcomes are the designed norm under partition, not errors: the walked prefix was valid, and the reason says what is missing. `Failed` is reserved for inputs or namestores that are _wrong_, not merely unavailable.

# Error Conditions
[Error Conditions]: #error-conditions

| Tag | Condition                                                                         | Requirement                                                                                                           |
|-----|-----------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| E1  | No key in the current namestore matches the remaining segments                    | MUST end `Partial(DanglingSegment)`; MUST NOT backtrack to a shorter key (see [Greedy Matching][Greedy Means Greedy]) |
| E2  | The matched edge's target namestore is unavailable (not replicated, not loadable) | MUST end `Partial(UnsyncedTarget)` — unavailable, not wrong                                                           |
| E5  | Value carrying a name (of any anchor family) in place of a namestore reference    | MUST be rejected as a symlink; MUST NOT be re-parsed or re-resolved (see [References])                                |
| E6  | Non-conforming key (empty, `.`, or `..` segments; `#`; leading/trailing `/`)      | MUST be ignored during matching (treated as absent); SHOULD be surfaced as malformed (see [Namestore Layout])         |
| E7  | Conflicting values for the matched key                                            | MUST resolve to the substrate's deterministic winner; SHOULD surface the loser(s) (see [Conflicting Updates])         |
| E8  | Value that is not a reference under any encoding the profile defines              | MUST be ignored during matching (treated as absent); SHOULD be surfaced as malformed (see [References])               |

# Security Considerations
[Security Considerations]: #security-considerations

- _No authority in the walk._ Path resolution confers no trust; every namestore is designated by a self-certifying reference carried as the value. Who vouched for the _root_ is entirely the anchoring specification's concern.
- _Greedy matching is deterministic and local._ The selected key depends only on the current namestore and the remaining segments — never on network state, connectivity, or lookup order.
- _No traversal semantics._ `.` and `..` are excluded at the grammar layer and MUST additionally be rejected in keys, so no namestore can alias its ancestors.

# FAQ
[FAQ]: #faq

## Why longest-match instead of shortest-match?

Longest-match keeps authority with the namestore closest to the name's owner: if you publish `foo/bar/baz` explicitly, a shorter `foo` edge (possibly controlled by someone else's namestore downstream) cannot shadow it. It also makes vanilla flat-map lookups of a full path string coincide with onomancy resolution for exact keys.

## Why no backtracking?

Backtracking would make resolution outcomes depend on the availability of downstream namestores: the same name could resolve to different targets depending on which replicas happen to be synced. Deterministic-and-local beats maximally-permissive here; a dead end is surfaced as `Partial`, not papered over.

<!-- External Links -->

[Automerge]: https://automerge.org/
[Automerge URL]: https://automerge.org/docs/under-the-hood/document_urls/
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[CRDT]: https://en.wikipedia.org/wiki/Conflict-free_replicated_data_type
[DNS Anchoring]: ./anchoring/dns-anchor.md
[GNU Name System]: https://www.rfc-editor.org/rfc/rfc9498
[Keyhive]: https://github.com/inkandswitch/keyhive
[Petname Anchoring]: ./anchoring/petname-anchor.md
[automerge-repo]: https://github.com/automerge/automerge-repo
