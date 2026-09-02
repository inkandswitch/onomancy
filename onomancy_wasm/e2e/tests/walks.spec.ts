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

  expect(verdict.outcome.status).toBe("resolved");
  expect(verdict.outcome.document).toBe(verdict.john);
});

test("reports a partial walk instead of failing", async ({ page }) => {
  const outcome = await page.evaluate(async () => {
    const held = new window.onomancy.HeldDocuments();
    const root = held.createDocument();
    return await held.resolve("~/nowhere", root);
  });

  expect(outcome.status).toBe("partial");
  expect(outcome.total).toBe(1);
});
