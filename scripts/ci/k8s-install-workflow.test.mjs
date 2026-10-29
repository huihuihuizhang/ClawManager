import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const require = createRequire(new URL('../../frontend/package.json', import.meta.url));
const yaml = require('js-yaml');
const buildText = readFileSync(new URL('../../.github/workflows/build.yml', import.meta.url), 'utf8');
const build = yaml.load(buildText);
const manual = yaml.load(readFileSync(new URL('../../.github/workflows/k8s-install-smoke.yml', import.meta.url), 'utf8'));
const job = manual.jobs['k8s-smoke'];

test('ordinary CI keeps builds and offline fixtures without a storage configuration prerequisite', () => {
  assert.ok(Object.hasOwn(build.on, 'pull_request'));
  assert.ok(Object.hasOwn(build.on, 'push'));
  for (const name of ['Frontend Build', 'Backend Build', 'Docker Build', 'Browser Worker Build and Tests', 'Hermes Desktop Web Build']) {
    assert.ok(Object.values(build.jobs).some(value => value.name === name), name);
  }
  assert.ok(build.jobs.frontend.steps.some(step => step.run?.includes('test_k8s_smoke.py')));
  const fixtures = build.jobs.frontend.steps.find(step => step.run?.includes('test_k8s_smoke.py'));
  const root = fileURLToPath(new URL('../../', import.meta.url));
  const cwd = resolve(root, fixtures['working-directory'] ?? build.jobs.frontend.defaults?.run?.['working-directory'] ?? '.');
  assert.equal(cwd, resolve(root), 'offline fixtures must run from the repository root, not the frontend job default');
  assert.ok(readFileSync(resolve(cwd, 'scripts/ci/test_k8s_smoke.py'), 'utf8').includes('unittest'));
  assert.ok(build.jobs.frontend.steps.some(step => step.run?.includes('k8s-install-workflow.test.mjs')));
  assert.equal(build.jobs['k8s-smoke'], undefined);
  assert.doesNotMatch(buildText, /K8S_SMOKE_MINIO_IMAGE|kubectl|kind-action/);
});

test('installation is explicitly manual with a per-run image input and independent result', () => {
  assert.deepEqual(Object.keys(manual.on), ['workflow_dispatch']);
  assert.equal(manual.on.workflow_dispatch.inputs.minio_image.type, 'string');
  assert.equal(manual.on.workflow_dispatch.inputs.minio_image.required, true);
  assert.equal(job.env.K8S_SMOKE_MINIO_IMAGE, '${{ inputs.minio_image }}');
  assert.equal(job.needs, undefined);
  assert.equal(job['continue-on-error'], undefined);
  assert.deepEqual(manual.permissions, { contents: 'read' });
  const pull = job.steps.findIndex(step => step.run?.includes('docker pull "$K8S_SMOKE_MINIO_IMAGE"'));
  const cluster = job.steps.findIndex(step => step.uses?.startsWith('helm/kind-action@'));
  assert.ok(pull >= 0 && pull < cluster);
  assert.doesNotMatch(job.steps[pull].run, /\|\|\s*true/);
  for (const name of ['Verify health endpoint', 'Verify version endpoint', 'Verify web page is reachable']) {
    assert.ok(job.steps.some(step => step.name === name && !step['continue-on-error']), name);
  }
  assert.equal(job.steps.find(step => step.name === 'Remove disposable certificate manifest').if, 'always()');
  assert.ok(!job.steps.some(step => step.uses?.startsWith('actions/upload-artifact@')));
});

test('manual shell syntax is valid and cluster writes stay bound to disposable kind', () => {
  for (const step of job.steps.filter(step => step.run)) {
    const result = spawnSync(process.env.SMOKE_BASH ?? 'bash', ['-n'], { input: step.run, encoding: 'utf8' });
    assert.equal(result.status, 0, `${step.name}: ${result.error?.message ?? result.stderr}`);
    for (const line of step.run.split('\n').filter(line => line.includes('kubectl'))) {
      assert.match(line, /kubectl (?:--context=kind-clawmanager-ci |config current-context)/);
    }
  }
});
