import { expect, test } from "./harness";

// Certificate verification through the PUBLISHED npm build — the
// wasm-bodge pipeline has broken exports independently of the crate
// before (the -O4 closure-shim incident), and until this spec nothing
// exercised the verify surface through dist at all.

/** A byte copy of the frozen production capture (see fixtures/README.md). */
const CAPTURE = "/e2e/fixtures/real_brooklynzelenka_carriage.onc";

/** Well after the chain's RRSIG windows lapsed: stale, never invalid. */
const YEARS_LATER = 1_788_100_000;

test("the frozen capture verifies through the dist build", async ({ page }) => {
  const verdict = await page.evaluate(
    async ([capture, yearsLater]) => {
      const bytes = new Uint8Array(
        await (await fetch(capture)).arrayBuffer(),
      );
      return window.onomancy.verifyCertificate(
        bytes,
        "brooklynzelenka.com",
        yearsLater,
      );
    },
    [CAPTURE, YEARS_LATER] as const,
  );

  // The same exact values the in-crate wasm test pins — through the
  // packaged module instead.
  expect(verdict.hostname).toBe("brooklynzelenka.com");
  expect(verdict.document).toBe(
    "automerge:VDTcixKK9uxrREEENGJUPLNLqJnx63hXYDA9gJ14gjVrLHosj",
  );
  expect(verdict.serial).toBe("1787291588428");
  expect(verdict.freshness).toBe("stale");
  expect(verdict.generation).toBe("on-path");
});

test("a refusal carries its reason code through the dist build", async ({
  page,
}) => {
  const outcome = await page.evaluate(
    async ([capture, yearsLater]) => {
      const bytes = new Uint8Array(
        await (await fetch(capture)).arrayBuffer(),
      );
      try {
        await window.onomancy.verifyCertificate(
          bytes,
          "example.com",
          yearsLater,
        );
        return { threw: false, reason: "" };
      } catch (error) {
        return {
          threw: true,
          reason:
            typeof error === "object" && error !== null && "reason" in error
              ? String((error as { reason: unknown }).reason)
              : "",
        };
      }
    },
    [CAPTURE, YEARS_LATER] as const,
  );

  // The certificate binds one hostname and says so in its signature;
  // the machine-readable code must survive the packaging pipeline.
  expect(outcome.threw).toBe(true);
  expect(outcome.reason).toBe("hostname-mismatch");
});
