import { expect, test } from "./harness";

// The name grammar: sigil-anchored, slash-separated edge hops.

test("parses a DNS-anchored name", async ({ page }) => {
  const parsed = await page.evaluate(() => {
    const name = new window.onomancy.Name("@brooklynzelenka.com/team/john");
    return {
      anchor: name.anchor,
      anchorKind: name.anchorKind,
      segments: name.segments,
      value: name.value,
    };
  });

  expect(parsed).toEqual({
    anchor: "@brooklynzelenka.com",
    anchorKind: "dns",
    segments: ["team", "john"],
    value: "@brooklynzelenka.com/team/john",
  });
});

test("rejects a malformed name", async ({ page }) => {
  const outcome = await page.evaluate(() => {
    try {
      new window.onomancy.Name("no sigil, not a name");
      return { threw: false, isError: false, message: "", hasReason: false };
    } catch (error) {
      // A real Error with prose — not a wasm trap, and not a missing
      // export's TypeError masquerading as a rejection — with no
      // `reason`: a parse failure is a caller error, not a finding
      // (reason-absence is the published discriminator).
      return {
        threw: true,
        isError: error instanceof Error,
        message: error instanceof Error ? error.message : "",
        hasReason:
          typeof error === "object" && error !== null && "reason" in error,
      };
    }
  });

  expect(outcome.threw).toBe(true);
  expect(outcome.isError).toBe(true);
  expect(outcome.message).toMatch(/sigil|name/i);
  expect(outcome.hasReason).toBe(false);
});
