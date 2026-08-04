# GNS (GNU Name System)

**System:** [GNU Name System](https://www.rfc-editor.org/rfc/rfc9498), RFC 9498; part of the GNUnet P2P framework.
**Relationship:** Closest living relative. Both are SDSI-descended petname systems over self-certifying keys; nearly every layer _around_ that shared core made the opposite bet. The [path-resolution spec](../../specs/path-resolution.md) borrows the term _namestore_ from GNS.

## How GNS Works

- A _zone_ is a key pair; the public key is the zone's identity. No registrars, no imposed hierarchy.
- Zone owners put labeled records into their local _namestore_. `PKEY`/`EDKEY` records delegate a label to another zone's public key — the edge primitive.
- Records are signed by the zone key and published to a DHT (R5N), encrypted, stored under `H(label, zone-key)`. DHT nodes cannot read records or enumerate zones; resolvers reveal nothing they didn't already know (query privacy).
- Resolution starts in the resolver's own start zone (a pure petname anchor) and follows one label per zone: label → delegation record → next zone key → DHT query, until a terminal record set.
- Names are inherently relative (`bob.gnu` is _your_ Bob). Global names exist only as zTLDs — the zone key itself as a top-level label: secure and global, not memorable.
- Records carry mandatory expiration times. Zone revocation is a flooded, proof-of-work-backed revocation message.

## Concept Map

| GNS | Onomancy |
|-----|-----------|
| Zone (key pair) | Namestore reference (Keyhive doc ID = ed25519 vk) |
| Namestore (your zones' record DB) | Namestore (every node in the walked graph) |
| `PKEY`/`EDKEY` delegation record | Edge record (`target` reference) |
| Start zone | `~` (your root namestore) |
| zTLD | `automerge:` doc anchor |
| Record expiration | None — graded freshness instead |
| DHT publication | CRDT replication |
| Zone-key revocation flood | Delegation revocation inside the doc |

## Shared Ground

- Linked local namespaces; trust never flows through a label
- Self-certifying identities; anyone can verify records regardless of the transport that delivered them
- Petname-first: offline introductions work immediately and upgrade later
- Resolution = one delegation-follow per label (our greedy multi-segment match generalizes this)

## Deliberate Divergences

1. _Data layer._ GNS resolves via live DHT queries; Onomancy resolves via local reads over replicated documents. This drives most other differences: GNS needs expiry and DHT liveness; we get offline resolution and `Partial(UnsyncedTarget)` instead of timeouts.
2. _Expiry._ GNS records expire (DHT hygiene). We rejected expiry as anti-local-first; freshness is graded metadata on the DNS chain, never a death clock on a binding.
3. _DNS posture._ GNS is a DNS _replacement_ and deliberately non-interoperable with DNS naming authority; its memorable-global corner is unfilled (zTLDs are not memorable). Onomancy's distinguishing move is the DNSSEC bridge: `@expede.wtf` is memorable, global, and verifiable from the IANA KSK. GNS treats DNS as the adversary; we treat it as one optional trust anchor among three.
4. _Redirects vs structural termination._ GNS has `CNAME`, `REDIRECT`, and `GNS2DNS` — symlink-style indirection with procedural loop handling. We forbid symlink edges outright and get termination in `len(segments)` hops as a theorem.
5. _Privacy._ GNS's crown jewel — encrypted records, unenumerable zones, oblivious queries — has no analogue here. Our namestores are plaintext to anyone we sync with; confidentiality is delegated to the document access-control layer (Keyhive), not the naming layer. Different threat model; recorded in [security.md](../security.md).
6. _Authority._ GNS zone keys are held keys; ours are unheld delegation-graph roots, so revocation is finer-grained (cut off one server, keep the identity) and needs no network flood.
7. _Multi-segment matching._ GNS resolves strictly one label per zone. Our longest-key match over flat multi-segment keys has no GNS analogue; it exists for Automerge-URL path compatibility.

## The DNSSEC Disagreement

GNS's founding critique (the 2014 GNS paper; the MORECOWBELL analysis of NSA DNS surveillance; RFC 9498's introduction) is that DNSSEC solves the wrong problem: it authenticates a hierarchy whose power structure is the threat. The specific charges, and where Onomancy stands on each:

| GNS critique of DNSSEC                                                                                                                            | Onomancy's position                                                                                                                                                                                                                                                                                                                                                                          |
|---------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| The hierarchy remains the naming authority; a single, jurisdictionally-concentrated root is a coercion point                                      | Agreed — which is why `@` is one _optional_ anchor of three; `~` and `automerge:` owe DNS nothing, and identity never lives in the domain (the doc ID is the identity, so seizure cannot take it)                                                                                                                                                                                            |
| DNSSEC faithfully authenticates seizures and coerced rebindings                                                                                   | Agreed, and scoped: a seizure can repoint `@evil.example`, but divergence detection (the alleged-name tripwire) surfaces the change, and the old identity keeps its `automerge:` name unharmed                                                                                                                                                                                                     |
| No query privacy — who-asked-for-what is visible to resolvers and networks; DoH only relocates the trust to megaresolvers rather than removing it | Agreed for DNS at large, but the critique is scoped for us: exposure is per-binding-refresh, not per-resolution ([security.md](../security.md#privacy)). Record-first verification makes resolution after the first fetch _local_ (no query stream to observe), and gossiped certificates never query anything — only the initial fetch/refresh of a binding is visible to a resolver at all |
| Signing a zone publishes it: NSEC zone walking enumerates signed zones; NSEC3 is offline-dictionary-attackable                                    | Partially inherited, but bounded: `_onomancy.<name>` is one predictable label, so enumeration reveals only "does this name participate", not a namespace                                                                                                                                                                                                                                     |
| The root KSK is a political trust anchor, not a purely technical one                                                                              | Agreed, and accepted _with eyes open_: the IANA KSK is the only anchor on Earth that makes names memorable + global + verifiable today. GNS's purism leaves that corner of Zooko's triangle empty (zTLDs are not memorable); we fill it with a clearly-labeled, user-revocable trust decision                                                                                                |

In one line: GNS says "DNSSEC secures a system whose power structure is the problem." Onomancy says "yes — so make that power structure opt-in, scoped to one spelling, and unable to hold identity hostage, rather than pretending memorable global names can exist without any shared authority at all."

## What to Keep Watching

- GNS's revocation flood is a solved answer to "revoke while partitioned" — worth revisiting if delegation-revocation propagation proves too slow in practice.
- RFC 9498's record-type registry and crypto-agility story (multiple zone types) is the template if we ever outgrow ed25519-only.
