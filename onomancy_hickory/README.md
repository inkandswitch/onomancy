# onomancy_hickory

The host DNSSEC chain courier: `ChainProvider` over real DNS, built on [hickory-proto]'s message types with a deliberately minimal stub transport (UDP, TCP fallback on truncation, `RD` + `CD` + EDNS `DO`).

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

Nothing this crate returns is trusted. Query IDs are weak, the transport is spoofable, and the upstream resolver may lie — all of that is *in* the threat model, because the verifier's own DNSSEC validation (against its baked-in trust anchor) is the only trust boundary. A forged or corrupted response can produce staleness or a chain that fails validation, never a false bind. `CD` is set precisely because judging is not the resolver's job here: the verifier wants the bytes even when the upstream's validator calls them bogus.

## Cross-zone aliases

A CNAME hop out of the descended subtree triggers a fresh root-down cut descent for the target's branch, mirroring the validator's re-root rule: the chain reads *root keys → source cuts → CNAME → target cuts → TXT*, every link verified from the same trust anchors.

## Upstreams

`HickoryProvider::system()` discovers resolvers from `/etc/resolv.conf` (falling back to a public resolver when none parse); explicit constructors take one server, `.or(addr)` appends fallbacks. Assembly tries upstreams in order and returns the last failure only when all fail.

## Known limitations

- No cookies/0x20 — a stub, not a full-service resolver (deliberate: transport is untrusted; DNSSEC is the boundary).

[hickory-proto]: https://github.com/hickory-dns/hickory-dns
