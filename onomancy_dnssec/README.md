# onomancy_dnssec

> [!WARNING]
> Alpha software. Interfaces, wire formats, and specifications change
> without notice — use at your own risk.

Sans-IO DNSSEC chain validation for [Onomancy]: RFC 4034/4035 signature validation over _supplied bytes_, behind `onomancy_protocol`'s `ChainValidator` seam.

This crate never fetches anything. Chains arrive as framed wire bytes (gossip, courier, or a `ChainProvider` backend such as `onomancy_hickory` or a browser DoH fetcher); validation walks them from a caller-supplied trust-anchor set and reports what the zone proved — a TXT binding `RRset` with its validity window, or an NSEC/NSEC3 proven absence. Verification time is a value, which is what makes graded freshness work offline.

Providers confer nothing: they are untrusted byte couriers, and every signature is checked here, locally, against the verifier's own anchors.

[Onomancy]: ../README.md
