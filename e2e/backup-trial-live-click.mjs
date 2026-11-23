// Real browser and trial HTTP routes against an explicitly selected drill target.
const help = `Run one trial backup followed by one isolated restore from the admin page.
Set BACKUP_TRIAL_ORIGIN and BACKUP_TRIAL_ISOLATED_TARGET=confirmed.
Authenticate with BACKUP_TRIAL_STORAGE_STATE or BACKUP_TRIAL_USER and BACKUP_TRIAL_PASSWORD.
Optional BACKUP_TRIAL_REPLAY_ID restores an existing artifact without creating another.
Optional BACKUP_TRIAL_CAPTURE_ONLY=1 creates an artifact without restoring it.
Optional BACKUP_TRIAL_HERMES_HISTORY=required verifies the Hermes history receipt.
Optional BACKUP_TRIAL_WORKSPACE_FILES=required verifies the workspace file receipt.
Optional BACKUP_TRIAL_TIMEOUT_MS, PLAYWRIGHT_CHANNEL and PLAYWRIGHT_EXECUTABLE_PATH.
No automatic retries. Only task IDs, public status and aggregate row counts are reported.`;
if (process.argv.includes('--help')) {
  console.log(help);
  process.exit(0);
}

const trialPath = '/api/v1/admin/system-backup/trial';
const idPattern = /^[0-9a-f]{32}$/;
const terminal = new Set(['succeeded', 'failed']);
const tables = new Set([
  'users', 'user_quotas', 'instances', 'openclaw_injection_snapshots',
  'instance_desired_state', 'instance_config_revisions',
]);
const receipt = { outcome: 'preflight', backup: null, restore: null };
let browser;
let step = 'preflight';

function requireThat(condition) {
  if (!condition) throw new Error('Trial browser acceptance assertion failed');
}

function observe(response, origin, method, path) {
  const url = new URL(response.url());
  return url.origin === origin && url.pathname === path && response.request().method() === method;
}

async function execute(page, control, path, origin, timeout, result, required) {
  const pending = page.waitForResponse(response => observe(response, origin, 'POST', path), { timeout });
  const [accepted] = await Promise.all([pending, control.click({ timeout })]);
  requireThat(accepted.status() === 202);
  const acceptedTask = await accepted.json();
  requireThat(idPattern.test(acceptedTask.id) && acceptedTask.status === 'running');
  Object.assign(result, { task_id: acceptedTask.id, http_status: 202 });
  const finished = await page.waitForResponse(async response => {
    if (!observe(response, origin, 'GET', trialPath + '/task') || !response.ok()) return false;
    const { task } = await response.json();
    return task?.id === acceptedTask.id && terminal.has(task.status);
  }, { timeout });
  const { task } = await finished.json();
  result.status = task.status;
  if (/^[a-z_]+$/.test(task.stage)) result.stage = task.stage;
  if (/^[a-z_]+$/.test(task.error)) result.error_code = task.error;
  requireThat(task.status === 'succeeded' && task.stage === 'done' && task.readback_verified === true);
  requireThat(idPattern.test(task.backup_id) && task.counts && Object.keys(task.counts).length === tables.size);
  for (const [table, count] of Object.entries(task.counts)) {
    requireThat(tables.has(table) && Number.isSafeInteger(count) && count >= 0);
  }
  Object.assign(result, { backup_id: task.backup_id, readback_verified: true, counts: task.counts });
  if (required.history || task.hermes_history) {
    const history = task.hermes_history;
    requireThat(Number.isSafeInteger(history?.sessions) && history.sessions > 0 &&
      Number.isSafeInteger(history.messages) && history.messages >= 0 && /^[0-9a-f]{64}$/.test(history.transcript_sha256));
    result.hermes_history = { sessions: history.sessions, messages: history.messages, transcript_sha256: history.transcript_sha256 };
  }
  if (required.files || task.workspace_files) {
    const files = task.workspace_files;
    requireThat(Number.isSafeInteger(files?.entries) && files.entries > 0 &&
      Number.isSafeInteger(files.file_bytes) && files.file_bytes >= 0 && /^[0-9a-f]{64}$/.test(files.archive_sha256));
    result.workspace_files = { entries: files.entries, file_bytes: files.file_bytes, archive_sha256: files.archive_sha256 };
  }
}

try {
  const origin = new URL(process.env.BACKUP_TRIAL_ORIGIN);
  requireThat(['http:', 'https:'].includes(origin.protocol) && origin.href === origin.origin + '/');
  requireThat(origin.protocol === 'https:' || ['127.0.0.1', 'localhost', '[::1]'].includes(origin.hostname));
  requireThat(process.env.BACKUP_TRIAL_ISOLATED_TARGET === 'confirmed');
  const storageState = process.env.BACKUP_TRIAL_STORAGE_STATE || undefined;
  const user = process.env.BACKUP_TRIAL_USER;
  const password = process.env.BACKUP_TRIAL_PASSWORD;
  requireThat(storageState || (user && password));
  const replay = process.env.BACKUP_TRIAL_REPLAY_ID;
  const captureOnly = process.env.BACKUP_TRIAL_CAPTURE_ONLY === '1';
  const required = {
    history: process.env.BACKUP_TRIAL_HERMES_HISTORY === 'required',
    files: process.env.BACKUP_TRIAL_WORKSPACE_FILES === 'required',
  };
  requireThat(!replay || idPattern.test(replay));
  requireThat(!captureOnly || !replay);
  const timeout = Number(process.env.BACKUP_TRIAL_TIMEOUT_MS || 120000);
  requireThat(Number.isSafeInteger(timeout) && timeout >= 1000 && timeout <= 600000);

  step = 'launch_browser';
  const { chromium } = await import('playwright-core');
  const executablePath = process.env.PLAYWRIGHT_EXECUTABLE_PATH;
  browser = await chromium.launch({
    headless: true,
    channel: executablePath ? undefined : process.env.PLAYWRIGHT_CHANNEL || 'chrome',
    executablePath,
  });
  const context = await browser.newContext({ storageState, serviceWorkers: 'block' });
  const page = await context.newPage();
  if (!storageState) {
    step = 'login';
    await page.goto(new URL('/login', origin).href, { timeout });
    await page.locator('#username').fill(user, { timeout });
    await page.locator('#password').fill(password, { timeout });
    const [login] = await Promise.all([
      page.waitForResponse(response => observe(response, origin.origin, 'POST', '/api/v1/auth/login'), { timeout }),
      page.locator('button[type=submit]').click({ timeout }),
    ]);
    requireThat(login.ok());
  }
  step = 'page_readiness';
  const [ready] = await Promise.all([
    page.waitForResponse(response => observe(response, origin.origin, 'GET', trialPath + '/readiness'), { timeout }),
    page.goto(new URL('/admin/backups/records', origin).href, { waitUntil: 'domcontentloaded', timeout }),
  ]);
  requireThat(ready.ok());
  const checks = await ready.json();
  requireThat((checks.missing === null || Array.isArray(checks.missing)) &&
    (checks.restore_missing === null || Array.isArray(checks.restore_missing)));
  requireThat((captureOnly || !checks.restore_missing?.length) && (replay || !checks.missing?.length));
  const panel = page.getByRole('region', { name: /^(备份（试行版）|Backup \(trial\))$/ });
  const input = panel.getByLabel(/^(试行备份 ID|Trial backup ID)$/);
  const success = panel.getByRole('status').getByText(/· (成功 · 已完成|succeeded · done)$/);
  if (!replay) {
    step = 'backup_or_readback';
    receipt.backup = {};
    await execute(page,
      panel.getByRole('button', { name: /^(创建试行备份|Create trial backup)$/ }),
      trialPath + '/backups', origin.origin, timeout, receipt.backup, required);
    requireThat(receipt.backup.task_id === receipt.backup.backup_id);
    await panel.getByText(/^(独立读回校验通过|Independent readback verified)$/).waitFor({ timeout });
    await success.waitFor({ timeout });
    requireThat((await input.inputValue({ timeout })) === receipt.backup.backup_id);
  } else {
    await input.fill(replay, { timeout });
  }

  if (!captureOnly) {
    step = 'restore_or_reconcile';
    const id = replay || receipt.backup.backup_id;
    receipt.restore = {};
    await execute(page,
      panel.getByRole('button', { name: /^(恢复到隔离环境|Restore to isolated target)$/ }),
      trialPath + '/backups/' + id + '/restore', origin.origin, timeout, receipt.restore, required);
    requireThat(receipt.restore.backup_id === id && receipt.restore.task_id !== id);
    if (receipt.backup) {
      for (const [table, count] of Object.entries(receipt.backup.counts)) {
        requireThat(receipt.restore.counts[table] === count);
      }
      requireThat(JSON.stringify(receipt.backup.hermes_history) === JSON.stringify(receipt.restore.hermes_history));
      requireThat(JSON.stringify(receipt.backup.workspace_files) === JSON.stringify(receipt.restore.workspace_files));
    }
    await panel.getByRole('status').getByText(receipt.restore.task_id, { exact: true }).waitFor({ timeout });
    await success.waitFor({ timeout });
    await panel.getByText(/^(独立读回校验通过|Independent readback verified)$/).waitFor({ timeout });
  }
  receipt.outcome = 'verified';
} catch {
  receipt.outcome = step;
  process.exitCode = 1;
} finally {
  await browser?.close();
  console.log(JSON.stringify(receipt));
}
