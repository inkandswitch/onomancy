# onomancy_publish

Publisher ceremonies: **Plans that verify by construction.**

A ceremony (bind · refresh · rotate · migrate) turns intent into a `Plan` — the DNS ops to apply, the artifacts to serve or gossip, and the postconditions that hold once the zone reflects the ops. Sans-IO throughout: applying a Plan is a `ZoneEditor`'s job (dashboard-human, RFC 2136, provider adapter — the planner never knows which), and checking postconditions is the ordinary verifier.

```text
ceremony (intent + Signer)
   │ plan(now) ── runs the REAL 8-stage derivation against a
   │              simulated zone before emitting anything
   ▼
Plan { dns_ops · artifacts · postconditions }
```

## Verified by construction

`plan()` fakes a zone that says exactly what the plan's ops publish, runs `VerifierState::compute` over it, and refuses to emit unless the derivation accepts *precisely* the ceremony's intent:

- a `Rotate` that would fork your own lineage (generation reuse, a hidden double-replace) fails at plan time — the derivation's set-wise fork detection is the checker, not a reimplementation;
- a `Migrate` must win its dual-publish window **via the succession proof** (rung-1 continuity), never by zone-state luck;
- a `Plan`'s existence is the witness (parse, don't validate).

## Ceremony cheat sheet

| Ceremony  | Keys needed                          | DNS ops        |
|-----------|--------------------------------------|----------------|
| `Bind`    | certificate signer                   | publish TXT    |
| `Refresh` | **none** (keyless re-attach)         | none           |
| `Rotate`  | Gₙ₊₁ (signs the statement) + signer | replace TXT    |
| `Migrate` | predecessor authority + signer       | dual-publish   |

Delegation carriages are empty until `onomancy_keyhive` lands — the same loudly-documented gap as the verifier's (`design/keyhive-coordination.md`).
