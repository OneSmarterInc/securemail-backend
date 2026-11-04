// Ephemeral test CA only. Server-side checks establish the negotiated group.
import { chromium } from '../frontend/node_modules/playwright/index.mjs';
import assert from 'node:assert/strict';
let input = '';
for await (const chunk of process.stdin) input += chunk;
const config = JSON.parse(input);
const browser = await chromium.launch({ channel: process.env.E2E_BROWSER === 'chromium' ? undefined : 'msedge', headless: true });
try {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    clientCertificates: [{ origin: config.origin, certPath: config.cert, keyPath: config.key }],
  });
  const page = await context.newPage();
  await page.goto(config.origin);
  assert.equal(await page.locator('body').innerText(), 'PQ verified');
  await context.close();
} finally {
  await browser.close();
}
