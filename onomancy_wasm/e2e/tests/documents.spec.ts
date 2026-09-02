import { expect, test } from "./harness";

// Held documents: minting, saving, and namestore edges.

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

// A saved Automerge document holding BOTH a reference edge and a
// plain value at another root key — generated once with the
// onomancy_automerge writer (`pics` → the anchor below; `note` →
// prose). The exclusion half cannot be staged through `bind`, which
// only writes references.
const MIXED_DOC_HEX =
  "856f4a831715302600d0010110a5d81a65b1a4904d995a71172a95f9c101be041b5bf618" +
  "51a89f5cca86482953621c63b9e4f15458c533f2e22c5e5fccc30601020302130223024" +
  "002560208150b2102230334014202560557578001027f007f017f027f007f007f077e04" +
  "6e6f7465047069637302007e027f0202017ec603b6076a7573742061206e6f74652c206" +
  "e6f742061207265666572656e63656175746f6d657267653a5644546369784b4b397578" +
  "72524545454e474a55504c4e4c714a6e783633685859444139674a3134676a56724c486" +
  "f736a020000";

const MIXED_DOC_TARGET =
  "automerge:VDTcixKK9uxrREEENGJUPLNLqJnx63hXYDA9gJ14gjVrLHosj";

test("a document's own keys do not become names unless they are references", async ({
  page,
}) => {
  const edges = await page.evaluate(
    ([hex, target]) => {
      const bytes = new Uint8Array(
        (hex.match(/../g) ?? []).map((pair) => parseInt(pair, 16)),
      );
      const held = new window.onomancy.HeldDocuments();
      held.hold(target, bytes);
      return held.edges(target);
    },
    [MIXED_DOC_HEX, MIXED_DOC_TARGET] as const,
  );

  // A namestore is the document's own top-level map, so a name is a
  // root key. Only reference-valued keys are edges: `pics` (a bare
  // reference) appears with its target, and `note` (prose) does not
  // appear at all.
  expect(edges).toEqual([{ path: "pics", target: MIXED_DOC_TARGET }]);
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
