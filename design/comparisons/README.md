# Comparisons

How Onomancy relates to prior and contemporary naming systems. Each document summarizes the other system honestly, maps its concepts onto ours, and notes what we deliberately borrowed, diverged from, or should keep watching.

| Document | System | One-line relationship |
|----------|--------|-----------------------|
| [`GNS`](./GNS.md) | GNU Name System (RFC 9498) | Closest living relative: same linked-local-namespace walk, opposite bets on data layer, expiry, and DNS |

Other systems appear in the chart and summary below for orientation, without dedicated write-ups: SDSI/SPKI (the common ancestor — local names over keys), ATProto handles (the same DNS-to-key binding shape without DNSSEC or offline verifiability — and Onomancy's [generation key](../../specs/anchoring/dns-anchor.md#generation-key) is the decentralized cousin of PLC's rotation-key hierarchy: a more-powerful key gating the working keys, attested by the publisher's own DNSSEC-signed zone instead of a central directory, with generation rotation in place of the sequencer's 72-hour history rewrite), DANE (keys in DNS under DNSSEC, binding TLS endpoints rather than identities), IPNS + DNSLink (key-anchored mutable pointers, one per key rather than a namespace), and the blockchain namespaces (Namecoin, ENS, Handshake — new global consensus instead of reusing DNS).

## The Short Version

``` mermaid
quadrantChart
    title Naming systems by trust root and DNS posture
    x-axis Replaces DNS --> Cooperates with DNS
    y-axis Global consensus --> Petname lineage
    quadrant-1 Petnames with a DNS bridge
    quadrant-2 Petname purists
    quadrant-3 New global roots
    quadrant-4 DNS-anchored keys
    Onomancy: [0.85, 0.9]
    GNS: [0.15, 0.85]
    SDSI-SPKI: [0.3, 0.7]
    Namecoin: [0.1, 0.15]
    ENS: [0.2, 0.1]
    Handshake: [0.15, 0.25]
    DANE: [0.9, 0.2]
    ATProto: [0.75, 0.35]
    IPNS-DNSLink: [0.6, 0.45]
```

Onomancy sits alone in the top-right: linked local namespaces (petname lineage) plus a DNSSEC bridge (DNS cooperation), over local-first replicas.

Onomancy's distinguishing combination: petname-system semantics (like GNS/SDSI), a DNSSEC-rooted global anchor (like DANE, unlike GNS), self-certifying document identities as ground truth (like IPNS keys, unlike ATProto's mutable directory), and fully offline, record-first verifiability (unlike all of them except GNS's cached records).
