<!--
Thanks for the PR! A few notes to keep things smooth:

- Title: use imperative mood, no trailing period
  (e.g. "Add cross-zone CNAME re-root" — not "Added cross-zone...")
- One logical change per PR. Big refactors are easier to review when
  split into a series.
- For protocol changes, update the normative spec in `specs/` and the
  rationale in `design/` alongside the code — they land together.
- Delete sections that don't apply.
-->

## Summary

<!--
What does this PR change, and why? Lead with the motivation — the
"what" is visible in the diff; the "why" is what reviewers need.
1–3 bullet points is ideal.
-->

-

## Related issues

<!--
Link issues this addresses. Use `Fixes #123` to auto-close on merge,
or `Refs #123` for related-but-not-closing.
-->

-

## Type of change

<!-- Check all that apply. -->

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (API, wire format, or spec behavior)
- [ ] Performance improvement
- [ ] Refactor / cleanup (no behavior change)
- [ ] Documentation / specs
- [ ] CI / build / tooling
- [ ] Dependency bump

## How was this tested?

<!--
Concrete steps: which tests / property suites / live runs. If you
added new test cases, mention them; if behavior is hard to test,
explain why.
-->

-

## Breaking changes

<!--
If you checked "Breaking change" above, describe the break and the
migration path here. Wire-format changes must update the golden
vectors deliberately — never regenerate them to make a diff pass.
Delete this section otherwise.
-->

## Checklist

- [ ] **I have personally reviewed every line of this diff.** I have read the code, understand what each change does, and am willing to defend it on its merits. AI-assisted authoring is welcome; unreviewed AI output is not.
- [ ] `nix run .#ci` succeeds (fmt, clippy, test, wasm, no-std, deny — local run ≡ CI run)
- [ ] Formatted via the flake's rustfmt (`nix run .#ci-fmt`), not an ambient one
- [ ] Public API changes have doc comments
- [ ] Protocol changes update `specs/` (normative) and `design/` (rationale)
- [ ] User-visible changes are reflected in the relevant `README.md`
