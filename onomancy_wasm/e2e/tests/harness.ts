import { test as base } from "@playwright/test";

// Every spec drives the real compiled package: the harness page imports
// the wasm-bodge build (`/dist/esm/web.js`, wasm embedded) and exposes
// it on `window.onomancy`. This fixture navigates there and waits for
// the wasm to initialize before each test.

declare global {
  interface Window {
    onomancy: typeof import("../../dist/index");
    onomancyReady: boolean;
  }
}

export const test = base.extend({
  page: async ({ page }, use) => {
    await page.goto("/e2e/index.html");
    await page.waitForFunction(() => window.onomancyReady === true);
    await use(page);
  },
});

export { expect } from "@playwright/test";
