// Real deployed page/backend only. No HTTP interception, synthetic auth or DB seed.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { parts, acceptedTask, advanceDetail } from './backup-live-contract.mjs';

const help = `Real backup page click (creates ONE real backup on the supplied installation).
Required: BACKUP_LIVE_URL (frontend origin), BACKUP_LIVE_STORAGE_STATE (private real authenticated Playwright state).
Optional: BACKUP_LIVE_TIMEOUT_MS (default 600000), PLAYWRIGHT_CHANNEL (default chrome).
Run from repository: node e2e/backup-live-click.mjs
No retries, auto-cancel, database writes or server startup. TLS verification stays enabled.
Writes an allowlisted receipt under .tmp-backup-live-click-<unique>/receipt.json.
Exit 1: rejected/failed/timeout/dependency missing; exit 2: public artifact ready, independent full evidence still required.
Never reports full acceptance from the public projection alone.`;
if (process.argv.includes('--help')) { console.log(help); process.exit(0); }

const root = fileURLToPath(new URL('../', import.meta.url));
const receipt = { schema_version: 'backup-live-click.v1', started_at: new Date().toISOString(),
  transport: 'real-browser-no-interception', full_acceptance: false, outcome: 'preflight', requests: [], observations: [] };
let browser, directory, fault = 'dependency_missing', stop = false;
const save = () => {
  if (directory) fs.writeFileSync(path.join(directory, 'receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
};
// Only closed enums are retained. Never write arbitrary response bodies/errors/URLs/tokens.
const tasks = new Set();
try {
  const target = new URL(process.env.BACKUP_LIVE_URL);
  if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password || target.search || target.hash || target.pathname !== '/') throw new Error();
  const state = path.resolve(process.env.BACKUP_LIVE_STORAGE_STATE || '');
  if (!process.env.BACKUP_LIVE_STORAGE_STATE || !fs.statSync(state).isFile()) throw new Error();
  const timeout = Number(process.env.BACKUP_LIVE_TIMEOUT_MS || 600000);
  if (!Number.isSafeInteger(timeout) || timeout < 1000 || timeout > 3600000) throw new Error();
  // Validate configuration before importing/launching a browser or touching a service.
  directory = fs.mkdtempSync(path.join(root, '.tmp-backup-live-click-'));
  save();
  const { chromium } = await import('@playwright/test');
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome', headless: true });
  const context = await browser.newContext({ storageState: state, serviceWorkers: 'block' });
  const page = await context.newPage();
  let accepted = null, ready = false, snapshot = null, listenerFailure = false;
  page.on('request', request => {
    if (request.method() !== 'POST' || new URL(request.url()).pathname !== '/api/v1/admin/system-backups') return;
    let body;
    try { body = request.postDataJSON(); } catch { listenerFailure = true; return; }
    const key = request.headers()['idempotency-key'];
    const valid = body?.task_purpose === 'acceptance' && JSON.stringify(body.requested_parts) === JSON.stringify(parts) && /^[A-Za-z0-9._:-]{16,128}$/.test(key || '');
    receipt.requests.push({ valid, idempotency_key: valid ? key : null,
      body_sha256: createHash('sha256').update(request.postData() || '').digest('hex') });
    if (!valid || receipt.requests.length !== 1) listenerFailure = true;
    save(); // Preserve original key even if the response is lost. Never click again automatically.
  });
  page.on('response', response => {
    const job = (async () => {
      if (stop) return;
      const request = response.request(), url = new URL(response.url());
      const create = request.method() === 'POST' && url.pathname === '/api/v1/admin/system-backups';
      const detail = request.method() === 'GET' && /^\/api\/v1\/admin\/system-backups\/sbk_[0-9a-f-]+$/.test(url.pathname);
      if (!create && !detail) return;
      // Historical selections / other tasks are not this click's evidence.
      if (detail && (!accepted || url.pathname !== `/api/v1/admin/system-backups/${accepted.public_id}`)) return;
      const headers = response.headers(), live = headers['x-system-backup-data-source'] === 'live';
      if (create) {
        receipt.create_http_status = response.status(); receipt.create_live = live; save();
        if (response.status() !== 202 || !live) { fault = 'create_rejected_or_not_live'; listenerFailure = true; return; }
      }
      if (!response.ok() || !live) { listenerFailure = true; return; }
      const data = await response.json();
      if (create) {
        accepted = acceptedTask(response.status(), headers, data, receipt.requests[0]?.idempotency_key);
        receipt.task = accepted; receipt.outcome = 'accepted_not_complete'; save(); return;
      }
      const next = advanceDetail(snapshot, accepted, headers, data);
      if (next === snapshot) return;
      snapshot = next;
      receipt.observations.push({ ...snapshot, at: new Date().toISOString() });
      if (snapshot.status === 'failed' || snapshot.status === 'canceled') { fault = 'task_failed_or_canceled'; listenerFailure = true; }
      ready = snapshot.ready;
      save();
    })().catch(() => { fault = 'live_contract_or_transport_invalid'; listenerFailure = true; });
    tasks.add(job); job.finally(() => tasks.delete(job));
  });
  fault = 'page_or_auth_unavailable';
  await page.goto(new URL('/admin/backups/records', target).href, { waitUntil: 'domcontentloaded', timeout: 30000 });
  // Use the actual page and its configured API. Auth redirects and preview fallback fail closed.
  const button = page.getByRole('button', { name: /^(创建备份|Create backup)$/ });
  await button.waitFor({ state: 'visible', timeout: 30000 });
  fault = 'create_disabled';
  if (!(await button.isEnabled())) throw new Error();
  receipt.outcome = 'clicking'; save();
  fault = 'create_result_unknown';
  await button.click({ timeout: 10000 });
  const until = Date.now() + timeout;
  while (!listenerFailure && !ready && Date.now() < until) await page.waitForTimeout(1000);
  if (listenerFailure) throw new Error();
  if (!ready) { fault = accepted ? 'same_task_timeout' : 'create_result_unknown'; throw new Error(); }
  receipt.outcome = 'public_artifact_ready_independent_evidence_required';
  receipt.missing_evidence = ['same-task six module results', 'nonempty Teams and Skills contents',
    'physical writer stop and original-state resume receipts', 'independent signed artifact/content verification'];
  process.exitCode = 2;
} catch {
  receipt.outcome = fault; process.exitCode = 1;
} finally {
  stop = true;
  await browser?.close();
  await Promise.allSettled([...tasks]);
  receipt.finished_at = new Date().toISOString(); save();
  console.log(JSON.stringify({ outcome: receipt.outcome, full_acceptance: false,
    receipt: directory ? path.join(directory, 'receipt.json') : null }));
}
