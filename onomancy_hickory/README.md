# onomancy_hickory

The host DNSSEC chain courier: `ChainProvider` over real DNS, built
on [hickory-proto]'s message types with a deliberately minimal stub
transport (UDP, TCP fallback on truncation, `RD` + `CD` + EDNS `DO`).

```text
HickoryProvider::chain(hostname)
  │  DNSKEY(.)                      → link 0
  │  per suffix with a DS RRset:
  │    DS(zone), DNSKEY(zone)       → links…
  │  TXT(_onomancy.hostname)        → CNAME links…, TXT link
  ▼
DnssecChain ──► onomancy_dnssec::validator::Validator (sans-IO)
```

## Trust model: a courier, not a judge

Nothing this crate returns is trusted. Query IDs are weak, the
transport is spoofable, and the upstream resolver may lie — all of
that is *in* the threat model, because the verifier's own DNSSEC
validation (against its baked-in trust anchor) is the only trust
boundary. A forged or corrupted response can produce staleness or a
chain that fails validation, never a false bind. `CD` is set
precisely because judging is not the resolver's job here: the
verifier wants the bytes even when the upstream's validator calls
them bogus.

## Known limitations

- CNAME hops that leave the already-descended zone hierarchy are
  framed but will fail validation (their zone cuts are not fetched).
  Cross-zone alias support means descending the target's cuts too —
  tracked, not yet built.
- One upstream, no failover, no cookies/0x20 — a stub, not a
  full-service resolver.

[hickory-proto]: https://github.com/hickory-dns/hickory-dns
