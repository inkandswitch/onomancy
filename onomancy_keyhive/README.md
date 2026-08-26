# onomancy_keyhive

> [!WARNING]
> Alpha software. Interfaces, wire formats, and specifications change
> without notice — use at your own risk.

Keyhive-backed authority verification for the Onomancy protocol: the real implementation of the `AuthorityVerifier` seam.

## What it answers

| Question                                               | Rule                                                                                                                                    |
|--------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| May `signer` speak for `root_doc`?                     | `signer == root` (identity), or the carriage's graph shows a delegation to the signer whose DELEGATING hop held `Admin` (root grants count) — dns-anchor §Who Signs |
| Is `generation` on the delegation path?                | Any graph the carriage proves delegates to the generation key, at any access level                                                      |
| Is a walked-to document authorized to be in its state? | Every op in the doc was authored under transitive `Edit` access on that doc's own graph                                                 |

The third check is Keyhive's native job: auth-enabled sync verifies ops against the delegation graph at _ingestion_, so documents the resolve walk hops into (via the greedy matcher's cross-document edges) are state-authorized before they are ever held. This crate's seam covers the first two — naming authority; a resolve-time re-check of held-doc state is possible future work if docs ever arrive outside authenticated sync (e.g. raw gossip).

Verification is a _replay_: each question ingests the carriage's events into a throwaway [`keyhive_core`] instance (every event is signature-checked by Keyhive on receipt), then queries membership on the materialized graph. All failure modes — unreadable entries, dangling dependencies, absent membership, insufficient access — refuse; nothing fails open.

## Carriage encoding

Each `SignedDelegationBytes` entry in a `DelegationChain` is `kh0` + one bincode-encoded `StaticEvent`: a delegation, revocation, or prekey operation (prekeys ride along because Keyhive resolves delegates against known individuals). Keyhive 0.5 is pre-alpha and its encoding may churn — absorbed by design: carriages ride the certificate's _unsigned attached region_, so a re-encode re-attaches evidence without touching signatures, and the version tag makes drift a loud parse error rather than a misread.

## Scope

Host-only (drives Keyhive's async API to completion on the current thread; no IO — the futures are state-machine-only). Not `no_std`: this crate quarantines the Keyhive dependency tree the same way `onomancy_dnssec` quarantines its crypto stack.
