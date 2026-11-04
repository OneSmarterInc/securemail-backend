// Synthetic browser regression. Credentials arrive through stdin, never argv or logs.
import { chromium } from '../frontend/node_modules/playwright/index.mjs';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
let input = '';
for await (const chunk of process.stdin) input += chunk;
const config = JSON.parse(input);
input = '';
const browser = await chromium.launch({ channel: 'msedge', headless: true });
try {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true, // Ephemeral synthetic CA only.
    clientCertificates: config.cert ? [{ origin: config.origin, certPath: config.cert, keyPath: config.key }] : [],
  });
  const page = await context.newPage();
  await page.goto(config.origin);
  await page.locator('#username').fill('custodian');
  await page.locator('#password').fill(config.password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.locator('#enrollment').waitFor({ state: 'visible' });
  assert.equal((await page.locator('#setup-key').inputValue()).length, 32);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const mac = createHmac('sha1', Buffer.from(config.totp_seed, 'hex')).update(counter).digest();
  const offset = mac[mac.length - 1] & 15;
  const code = ((mac.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
  await page.locator('#password').fill(config.password);
  await page.locator('#totp-code').fill(code);
  await page.locator('#first-password').fill(config.new_password);
  await page.locator('#first-password-confirm').fill(config.new_password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.locator('#state').filter({ hasText: 'Sealed' }).waitFor();
  await page.locator('#recovery').fill(config.secret);
  await page.getByRole('button', { name: 'Unseal key service', exact: true }).click();
  await page.locator('#state').filter({ hasText: 'Ready' }).waitFor();
  assert.equal(await page.locator('#recovery').inputValue(), '');
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.equal(await page.locator('#setup-key').inputValue(), '');
  assert.equal(await page.locator('.notice').count(), 0);
  await page.locator('#tab-audit').click();
  await page.locator('#audit-rows').getByText('unseal', { exact: true }).waitFor();
  await page.locator('#audit-actor').selectOption('custodian');
  await page.locator('#audit-query').fill('unseal');
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await page.locator('#audit-summary').filter({ hasText: '1 matching event' }).waitFor();
  await page.locator('[data-sort="actor"]').click();
  await page.locator('th[aria-sort="ascending"]').waitFor();
  await page.screenshot({ path: config.screenshot, fullPage: true });
  await page.setViewportSize({ width: 360, height: 800 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.screenshot({ path: config.screenshot.replace('.png', '-mobile.png'), fullPage: true });
  await page.locator('#tab-service').click();
  await page.locator('#seal-confirm').check();
  await page.getByRole('button', { name: 'Seal key service', exact: true }).click();
  await page.locator('#state').filter({ hasText: 'Sealed' }).waitFor();
  await page.locator('#logout').click();
  await page.locator('#signin').waitFor({ state: 'visible' });
  console.log('Custodian TOTP enrollment/login, unseal, audit filters/sort, 360px layout, secret clearing, seal and logout passed.');
} finally {
  await browser.close();
}
