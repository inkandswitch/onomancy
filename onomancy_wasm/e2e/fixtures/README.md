# e2e fixtures

- `real_brooklynzelenka_carriage.onc` — a **byte copy** of the frozen
  production capture at
  `onomancy_dnssec/tests/fixtures/real_brooklynzelenka_carriage.onc`
  (see that directory's README: do not regenerate). Copied because the
  Playwright server's root is `onomancy_wasm/`, so the original is
  unreachable from the browser. If the original ever changes (it must
  not), this copy drifts loudly: the spec asserts exact field values.
