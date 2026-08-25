import { expect, test } from "./harness";

// Held documents: minting, notes, and namestore edges.

test("mints documents the name grammar accepts", async ({ page }) => {
  const minted = await page.evaluate(() => {
    const held = new window.onomancy.HeldDocuments();
    const anchor = held.createDocument();
    const name = new window.onomancy.Name(anchor);
    return {
      anchor,
      anchorKind: name.anchorKind,
      anchors: held.anchors,
    };
  });

  expect(minted.anchor).toMatch(/^automerge:/);
  expect(minted.anchorKind).toBe("doc");
  expect(minted.anchors).toEqual([minted.anchor]);
});

test("round-trips a document note", async ({ page }) => {
  const note = await page.evaluate(() => {
    const held = new window.onomancy.HeldDocuments();
    const anchor = held.createDocument();
    held.setNote(anchor, "John's document");
    return held.note(anchor);
  });

  expect(note).toBe("John's document");
});

test("binds namestore edges and reads them back", async ({ page }) => {
  const edges = await page.evaluate(() => {
    const held = new window.onomancy.HeldDocuments();
    const root = held.createDocument();
    const team = held.createDocument();
    const john = held.createDocument();
    held.bind(root, "team", team);
    held.bind(team, "john", john);
    return { fromRoot: held.edges(root), fromTeam: held.edges(team), john, team };
  });

  expect(edges.fromRoot).toEqual([{ path: "team", target: edges.team }]);
  expect(edges.fromTeam).toEqual([{ path: "john", target: edges.john }]);
});
