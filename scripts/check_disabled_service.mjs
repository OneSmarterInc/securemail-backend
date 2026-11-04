// UI fixture only: no real account login, upload, message or email is performed.
import { chromium } from '../frontend/node_modules/playwright/index.mjs';
import assert from 'node:assert/strict';
const browser = await chromium.launch({ channel: 'msedge', headless: true });
try {
  const page = await browser.newPage();
  let simulatedReady = null;
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/document-service') {
      if (simulatedReady === null) return route.continue();
      return route.fulfill({ json: { ready: simulatedReady, message: simulatedReady ? '' : 'Service is disabled.' } });
    }
    if (path === '/api/auth/session') return route.fulfill({ json: {
      csrf: 'synthetic', synthetic_mode: true, dev_tools: false, setup_required: false,
      user: { id: 1, name: 'UI fixture', email: 'fixture@example.test', role: 'staff', organization: 'fixture', can_nophi: false, can_manage_privileges: false, can_export_audit: false, sender_addresses: ['fixture@example.test'], mfa_confirmed: true },
    } });
    if (path === '/api/routing/preview') return route.fulfill({ json: { protected: true, reason: 'secure_conversation' } });
    if (route.request().method() === 'POST') throw new Error('Unexpected write during read-only UI verification');
    return route.fulfill({ json: {} });
  });
  await page.goto('http://localhost:5173/#/request');
  await page.getByText('Service is disabled.', { exact: true }).waitFor();
  const file = page.getByLabel('Upload attachments');
  const send = page.getByRole('button', { name: 'Send secure request', exact: true });
  assert.equal(await file.isDisabled(), true);
  assert.equal(await send.isDisabled(), true);
  await page.getByPlaceholder('recipient@example.com').first().fill('sara@example.test');
  await page.getByPlaceholder('recipient@example.com').first().press('Tab');
  simulatedReady = true;
  await page.waitForFunction(() => !document.querySelector('input[type=file]').disabled && !document.querySelector('input[type=file]').closest('fieldset').disabled);
  await page.waitForFunction(() => [...document.querySelectorAll('button')].some(b => b.textContent.includes('Send secure request') && !b.disabled));
  simulatedReady = false;
  await page.getByText('Service is disabled.', { exact: true }).waitFor();
  assert.equal(await file.isDisabled(), true);
  assert.equal(await send.isDisabled(), true);
  console.log('Live sealed status blocked sending/upload; simulated readiness transitions updated controls. No writes sent.');
} finally {
  await browser.close();
}
