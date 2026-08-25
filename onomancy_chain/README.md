# onomancy_chain

Sans-IO DNSSEC chain assembly: a state machine that turns recursive-resolver answers into the framed links the validator walks — without performing any IO itself.

```text
Assembly::start(hostname) ──► Question ──► driver (any IO)
       ▲                                       │
       └───────── answer(records) ◄────────────┘
                       │
                       ├─► Step::Ask(machine, question)   (loop)
                       └─► Step::Done(DnssecChain)
```

The machine mirrors the validator's expected grammar — root DNSKEY, DS + child DNSKEY per signed cut, CNAME hops, TXT leaf — but PROVES nothing: it selects and frames bytes, and `onomancy_dnssec` renders every verdict. Framability is not validity.

## Drivers

The machine never queries anything: each step yields the next `Question`, the driver answers it however it likes, and transport failure stays on the driver's side of the seam.

- `onomancy_hickory` — OS sockets (UDP with TCP fallback) against recursive resolvers
- `onomancy_wasm` — RFC 8484 DNS-over-HTTPS via `fetch()` in browsers and workers

A driver is a loop:

```rust,ignore
let (mut assembly, mut question) = Assembly::start(&hostname)?;
loop {
    let records = transport.query(&question).await?; // driver's IO, driver's error
    match assembly.answer(records)? {
        Step::Ask(next, asked) => (assembly, question) = (next, asked),
        Step::Done(chain) => break chain,
    }
}
```

## Trust model: a courier's brain, not a judge

Nothing framed here is trusted. Answers may be spoofed, resolvers may lie — all of that is *in* the threat model, because the verifier's own DNSSEC validation (against its baked-in trust anchors) is the only trust boundary. A forged answer can produce a chain that fails validation, never a false bind.
