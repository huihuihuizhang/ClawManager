import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { emptyTemplate, renderDeployment, requirements } from './system-backup-d-deployment.mjs';
const sha = 'a'.repeat(64);
function syntheticInput() {
  const input = emptyTemplate();
  input.image = `example.invalid/synthetic-test@sha256:${sha}`;
  for (const record of [input.runtime, input.bootstrap]) for (const key of Object.keys(record)) {
    if (record[key] === '') record[key] = key.endsWith('sha256') || key === 's3_identity_hash' ? sha : `synthetic-${key}`;
  }
  for (const record of [input.runtime, input.bootstrap]) {
    record.expected_server_uuid = '11111111-2222-3333-4444-555555555555';
    record.expected_database = 'synthetic_test'; record.installation_id = 'installation_synthetic';
  }
  input.runtime.transit_endpoint = 'https://transit.invalid'; input.runtime.s3_endpoint = 'https://s3.invalid';
  for (const name of Object.keys(input.bindings)) input.bindings[name] = `synthetic-${name.replaceAll('_', '-')}`;
  const kinds = JSON.parse(readFileSync(new URL('../contracts/system-backup/v12/admin-control-resources.schema.json', import.meta.url))).$defs.RegistryReference.properties.registry_kind.enum;
  input.registry_items = kinds.map((kind, index) => {
    const prefix = { provider_proof_issuers: 'provider', strong_auth_issuers: 'strong', rbac_bindings: 'rbac' }[kind];
    return { key: `registry-${index}.json`, path: `${kind}/${prefix ? input.runtime[`${prefix}_registry_version`] : 'v1'}/${sha}.json` };
  });
  input.nonce_items = [{ key: 'nonce-v1', path: `${sha}/v1` }];
  return input;
}
test('empty official template and missing owner inputs cannot render', () => {
  assert.throws(() => renderDeployment(emptyTemplate()));
  assert.equal(requirements().status, 'blocked');
  assert.equal(requirements().kubernetes_contacted, false);
  const template = JSON.parse(readFileSync(new URL('../deployments/k8s/system-backup-registration.template.json', import.meta.url)));
  assert.deepEqual(template, emptyTemplate(), 'template drift');
});
test('rendered bytes match executable digest pins and mount every runtime path', () => {
  const input = syntheticInput(), result = renderDeployment(input);
  const items = result.manifest.items;
  assert.equal(items.length, 7);
  const http = items.find(item => item.kind === 'Deployment');
  assert.equal(http.spec.replicas, 0);
  const pod = http.spec.template.spec, container = pod.containers[0];
  const imageDefinition = readFileSync(new URL('../Dockerfile', import.meta.url), 'utf8');
  for (const workload of items.filter(item => item.kind === 'Job' || item.kind === 'Deployment')) {
    const command = workload.spec.template.spec.containers[0].command[0];
    assert.ok(imageDefinition.includes(` ${command}\n`) || imageDefinition.includes(` ${command}\r\n`), `binary is not installed by the app image: ${command}`);
  }
  assert.equal(pod.automountServiceAccountToken, false);
  assert.ok(container.securityContext.readOnlyRootFilesystem);
  assert.ok(container.volumeMounts.every(mount => mount.readOnly));
  const runtime = items.find(item => item.kind === 'ConfigMap' && item.data['runtime.json']);
  assert.equal(createHash('sha256').update(runtime.data['runtime.json']).digest('hex'), container.env.find(item => item.name === 'SYSTEM_BACKUP_REGISTRATION_RUNTIME_SHA256').value);
  for (const [key, path] of Object.entries(input.runtime).filter(([key]) => key.endsWith('_file') || key.endsWith('_directory'))) {
    assert.ok(container.volumeMounts.some(mount => path === mount.mountPath || path.startsWith(`${mount.mountPath}/`)), `unmounted ${key}`);
  }
  const jobs = items.filter(item => item.kind === 'Job');
  assert.ok(jobs.every(job => job.spec.suspend && job.spec.backoffLimit === 0));
  const bootstrap = jobs.find(job => job.metadata.name.startsWith('sbk-bootstrap-'));
  const command = bootstrap.spec.template.spec.containers[0].command;
  const deployment = items.find(item => item.kind === 'ConfigMap' && item.data['deployment.json']);
  assert.equal(createHash('sha256').update(deployment.data['deployment.json']).digest('hex'), command.at(-1));
  assert.equal(result.report.provider_admission, 'not_run');
  assert.equal(result.report.image_catalog_verified, false);
  assert.equal(result.report.human_mfa_verified, false);
  assert.ok(!items.some(item => ['Secret', 'Role', 'ClusterRole', 'Namespace'].includes(item.kind)));
});
test('registry and nonce projections preserve required content-addressed paths', () => {
  const input = syntheticInput();
  const items = renderDeployment(input).manifest.items;
  for (const item of items.filter(item => ['Job', 'Deployment'].includes(item.kind))) {
    const pod = item.spec.template.spec;
    const registry = pod.volumes.find(volume => volume.name === 'registries');
    if (registry) assert.deepEqual(registry.configMap.items, input.registry_items);
    const nonce = pod.volumes.find(volume => volume.name === 'nonce');
    if (nonce) assert.deepEqual(nonce.secret.items, input.nonce_items);
  }
});

test('reviewed historical ledger inputs reach only the suspended migration job', () => {
  const input = syntheticInput();
  input.migration_history = { review_sha256: 'b'.repeat(64), review_configmap: 'reviewed-ledger', review_key: 'review.json', sources_configmap: 'original-sql', sources_items: [{ key: 'original.sql', path: '110_historical_source.sql' }] };
  const resources = renderDeployment(input).manifest.items;
  const migration = resources.find(item => item.kind === 'Job' && item.metadata.name.startsWith('sbk-migrate-'));
  const pod = migration.spec.template.spec;
  const command = pod.containers[0].command;
  for (const [flag, value] of [['--history-review-file', '/run/system-backup/migration-history-review/review.json'], ['--expected-history-review-sha256', input.migration_history.review_sha256], ['--historical-sql-dir', '/run/system-backup/migration-history-sources']]) assert.equal(command[command.indexOf(flag) + 1], value);
  assert.equal(migration.spec.suspend, true);
  assert.deepEqual(pod.volumes.find(item => item.name === 'migration-history-sources').configMap.items, input.migration_history.sources_items);
  assert.ok(pod.containers[0].volumeMounts.every(mount => mount.readOnly));
  for (const resource of resources.filter(item => ['Job', 'Deployment'].includes(item.kind) && item !== migration)) assert.ok(!resource.spec.template.spec.volumes.some(volume => volume.name.startsWith('migration-history-')));
  const original = structuredClone(input.migration_history);
  for (const mutate of [history => { history.review_sha256 = ''; }, history => { history.review_configmap = '../outside'; }, history => { history.sources_items[0].path = '../110_historical.sql'; }, history => { history.sources_items.push({ ...history.sources_items[0] }); }, history => { history.allow_missing_history = true; }]) {
    input.migration_history = structuredClone(original);
    mutate(input.migration_history);
    assert.throws(() => renderDeployment(input));
  }
});
test('wrong target, floating image, wrong paths, missing registries and shared privilege identities fail', () => {
  for (const mutate of [
    input => { input.image = 'example.invalid/app:latest'; },
    input => { input.bootstrap.expected_database = 'another_database'; },
    input => { input.bootstrap.expected_server_uuid = 'another_server'; },
    input => { input.runtime.jwt_secret_file = '/etc/unmounted-key'; },
    input => { input.migration_catalog_sha256 = '0'.repeat(64); },
    input => { input.bindings.runtime_credentials_secret = input.bindings.migration_credentials_secret; },
    input => { input.runtime.transit_endpoint = 'https://user:password@transit.invalid'; },
    input => { input.registry_items.pop(); },
    input => { input.registry_items[0].path = '../escape'; },
    input => { input.nonce_items[0].path += '/../escape'; },
    input => { input.runtime.provider_registry_sha256 = 'b'.repeat(64); },
    input => { input.runtime.dsn = 'never-inline-credentials'; },
  ]) {
    const input = syntheticInput(); mutate(input);
    assert.throws(() => renderDeployment(input));
  }
});
