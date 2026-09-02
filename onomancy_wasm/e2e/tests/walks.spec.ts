import { expect, test } from "./harness";

// Resolution walks across held documents: full resolution and the
// partial-walk-is-not-an-error contract.

test("resolves a two-hop walk across held documents", async ({ page }) => {
  const verdict = await page.evaluate(async () => {
    const held = new window.onomancy.HeldDocuments();
    const root = held.createDocument();
    const team = held.createDocument();
    const john = held.createDocument();
    held.bind(root, "team", team);
    held.bind(team, "john", john);
    const outcome = await held.resolve("~/team/john", root);
    return { john, outcome };
  });

  // `toMatchObject` rather than field access: the published
  // `WalkOutcome` is a union, and these assertions must typecheck
  // without narrowing. Authority is the dev bridge's grade, and the
  // warning says what the grade does not establish.
  expect(verdict.outcome).toMatchObject({
    status: "resolved",
    document: verdict.john,
    authority: "trusted-substrate",
    warning: expect.stringContaining(""),
  });
});

test("reports a partial walk instead of failing", async ({ page }) => {
  const outcome = await page.evaluate(async () => {
    const held = new window.onomancy.HeldDocuments();
    const root = held.createDocument();
    return await held.resolve("~/nowhere", root);
  });

  // WHERE it stopped and WHY — the declared `WalkOutcome` fields, and
  // the only e2e assertion of the dangling-vs-unsynced distinction.
  expect(outcome).toMatchObject({
    status: "partial",
    total: 1,
    consumed: 0,
    reason: "dangling segment",
  });
});
