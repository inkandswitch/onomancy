# Formal Verification

Machine-checked proofs for the small, security-critical kernels of the design,: a Lean 4 reference model developed _alongside_ the Rust implementation (Rust lands first with bolero properties; proofs follow). The model stays tiny — grammar, codec, ratchet — with crypto and Keyhive semantics axiomatized.

## Pipeline

```
Lean 4 reference model ──proofs──► disjointness, termination,
        │                          injectivity, ratchet safety
        └──extract test vectors──► bolero conformance tests
                                   (Rust impl ≡ Lean model)
```

The Rust implementation is never verified directly; it is checked against the Lean model by property tests over extracted vectors. If Rust-level proofs are ever wanted, Kani (bounded) or Verus are the candidates — post-v0 at the earliest.

## Targets

| # | Theorem | Design source | Status |
|---|---------|---------------|--------|
| 1 | Anchor disjointness | [names.md](./names.md) | modeled below |
| 2 | Parse/print roundtrip + `print` injective | names.md | modeled below |
| 3 | Normalization idempotence | names.md | modeled below |
| 4 | Resolution termination (no symlink edges) | [resolution.md](./resolution.md#termination) | sketched |
| 5 | Canonical encoding injectivity (certificate, TXT record, rotation + successor statements) | [certificate.md](./certificate.md#canonical-encoding) | pending codec |
| 6 | Ratchet safety + fresh-heals (stale-path monotone; fresh-path reset) | [dns-binding.md](./dns-binding.md) | sketch predates the zone-state key — restate over `(window_end, serial, issued_at)` and fold into 7 |
| 7 | Derivation determinism: `derive(store, now, decisions)` is a pure function — same inputs ⇒ same verdicts, ladder (incl. zone-state key), bridging, and decision-document entries included (subsumes pooled-evidence verdict determinism) | [binding-cache spec](../specs/anchoring/binding-cache.md#conformance) | pending |

Later/maybe: chain-validation soundness (symbolic crypto), graded-freshness monotonicity, petname-store CRDT merge laws.

## Model Signatures (Lean 4)

### Grammar

```lean
/-- Mirrors `onomancy_core::name::anchor::Anchor`. -/
inductive Anchor where
  | local
  | dns (name : DnsName)
  | doc (vk : Ed25519Vk)     -- opaque 32-byte value; validity axiomatized

structure Name where
  anchor   : Anchor
  segments : List Segment
  heads    : List Head       -- doc anchors only; [] = live name

def parse : String → Option Name
def print : Name → String

/-- Theorem 1: the anti-phishing theorem. Each spelling family yields
    exactly one anchor kind: `@` is DNS and nothing else,
    `automerge:` is a doc anchor and nothing else, `~` is local. -/
theorem anchor_disjoint (s : String) (n : Name) (h : parse s = some n) :
    match n.anchor with
    | .dns _   => s.startsWith "@"
    | .doc _   => s.startsWith "automerge:"
    | .local   => s.startsWith "~"

/-- Theorem 1b: heads only pin doc anchors. -/
theorem heads_doc_only (n : Name) (h : Wf n) :
    n.heads ≠ [] → ∃ vk, n.anchor = .doc vk

/-- Theorem 2a: printed names reparse to themselves. -/
theorem parse_print (n : Name) (h : Wf n) : parse (print n) = some n

/-- Theorem 2b: printing is injective on well-formed names. -/
theorem print_inj (a b : Name) (ha : Wf a) (hb : Wf b) :
    print a = print b → a = b

/-- Theorem 3: DNS normalization is a projection. -/
theorem norm_idem (s : String) : norm (norm s) = norm s
```

### Resolution Termination

```lean
/-- Edges hold document references, never names — the no-symlink
    invariant is enforced by this type: there is no `Name` payload
    to re-resolve. Keys are non-empty segment lists (multi-segment
    paths, per the greedy matching in the path-resolution spec). -/
structure Namestore where
  edges : List Segment → Option Ed25519Vk   -- domain: non-empty keys only

/-- Greedy longest-key match; each hop consumes ≥ 1 segment, so the
    remaining-segment list strictly decreases. -/
def resolve (load : Ed25519Vk → Option Namestore) : Namestore → List Segment → Result

/-- Theorem 4: termination is structural — `resolve` is total by
    well-founded recursion on segment count, in at most
    `segments.length` hops. Lean's totality checker IS the proof;
    the theorem documents the invariant. -/
```

> [!NOTE]
> If an edge type ever gains a name-valued variant, `resolve` stops being structurally recursive and the model fails to compile — the invariant breaks loudly, which is the point.

### Monotone Ratchet

The model distinguishes stale-path steps (must exceed) from fresh-path steps (may reset in either direction); clocks stay axiomatized, so the 5-minute deferral bound is modeled as a predicate parameter, not proved about real time.

```lean
/-- Stale-chain path: strictly increasing. -/
def stepStale (highest : Nat) (incoming : Nat) : Option Nat :=
  if incoming > highest then some incoming else none

/-- Fresh-chain path: any serial is accepted (surfacing is a UI
    obligation outside the model). -/
def stepFresh (_highest : Nat) (incoming : Nat) : Nat := incoming

/-- Theorem 6a: replay safety — stale-accepted serials strictly increase. -/
theorem ratchet_monotone : stepStale h v = some h' → h < h'

/-- Theorem 6b: stale-path poisoning is sticky — after accepting `v`,
    no `w ≤ v` is stale-accepted again… -/
theorem ratchet_burned (h v w : Nat) : stepStale h v = some v → w ≤ v → stepStale v w = none

/-- Theorem 6c: …but any fresh step heals: the ratchet after a fresh
    step equals the fresh serial, regardless of prior poison. -/
theorem fresh_heals (h v : Nat) : stepFresh h v = v
```

## Axiomatization Boundary

Assumed, never proved:

- Ed25519 unforgeability; key bytes decode to valid curve points
- BLAKE3/DNSSEC hash collision resistance
- Keyhive delegation-graph semantics (external dependency)
- Anything involving clocks, networks, or UI

## Repository Layout (when the toolchain lands)

```
onomancer/
└── lean/                 # Lake package, NOT in the cargo workspace
    ├── lakefile.lean
    └── Onomancy/
        ├── Name.lean     # grammar model + theorems 1–3
        ├── Resolve.lean  # termination model, theorem 4
        ├── Ratchet.lean  # theorems 6a/6b
        └── Vectors.lean  # #eval-driven test-vector extraction → JSON
```

Extracted vectors land in `onomancy_core/tests/vectors/` and are consumed by bolero conformance tests. Lean enters the Nix dev shell (`lean4` + `lake`) only when this directory is created — it is not a build dependency of the Rust workspace.
