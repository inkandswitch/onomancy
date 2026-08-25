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
      return "accepted";
    } catch {
      return "rejected";
    }
  });

  expect(outcome).toBe("rejected");
});
