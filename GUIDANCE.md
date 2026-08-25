# Guidance

## For Publishers

1. **DNSSEC-sign your zone** — an unsigned zone cannot anchor a binding; algorithms 8, 13, and 15 are supported
2. **Bind, then refresh** — `onomancer bind` publishes the TXT record; `onomancer refresh` attaches the live chain to the certificate
3. **Keep superseded certificates retrievable** — they are immutable static files; verifiers returning after multiple migrations bridge through them
4. **Rotate on suspicion** — a leaked generation key is healed by rotation: fresh records under the old key are rejected once the zone moves
5. **Never rely on wildcard bindings** — wildcard-synthesized answers are rejected by verifiers

## For Verifier and App Developers

1. **Validate locally, always** — never delegate to a resolver's AD bit; the baked-in IANA anchors are the only trust root
2. **Framability is not validity** — a fetched chain is unverified input until your own validator accepts it
3. **The clock enters once** — grade freshness at your own instant; no other step reads time
4. **Surface, don't suppress** — divergence badges and ratchet resets exist so users can act on them
5. **Treat transport as hostile** — DoH narrows who sees your queries; it adds no trust

## Further Reading

See [`specs/`](./specs/) for the normative rules and [`design/`](./design/) for the threat model and rationale.
