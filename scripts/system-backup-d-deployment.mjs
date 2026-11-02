#!/usr/bin/env node
// Offline D composition only. Does not contact Kubernetes, read credentials,
// create owner inputs, enroll MFA, or claim that admission has passed.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeMigrationCatalog } from './system-backup-contract-check.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const read = path => readFileSync(resolve(root, path), 'utf8');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const bytes = value => `${JSON.stringify(value, null, 2)}\n`;
const dns = /^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/;
const sha = /^[0-9a-f]{64}$/;
const prefix = '/run/system-backup';
export const runtimePaths = {
  registry_directory: `${prefix}/registries`, nonce_directory: `${prefix}/nonce`, capacity_report_file: `${prefix}/capacity/report.json`,
  transit_ca_file: `${prefix}/ca/transit.crt`, s3_ca_file: `${prefix}/ca/s3.crt`,
  provider_token_file: `${prefix}/credentials/provider-token`, strong_token_file: `${prefix}/credentials/strong-token`,
  jwt_secret_file: `${prefix}/credentials/jwt`, totp_encryption_key_file: `${prefix}/credentials/totp-key`,
  s3_access_key_file: `${prefix}/credentials/s3-access-key`, s3_secret_key_file: `${prefix}/credentials/s3-secret-key`,
};
export const bootstrapPaths = {
  config_file: `${prefix}/bootstrap-data/config.json`, grant_file: `${prefix}/bootstrap-data/grant.json`,
  registry_directory: runtimePaths.registry_directory, nonce_directory: runtimePaths.nonce_directory,
  capacity_report_file: runtimePaths.capacity_report_file, dsn_file: `${prefix}/bootstrap-credentials/dsn`,
};
const bindingNames = ['runtime_credentials_secret', 'bootstrap_credentials_secret', 'migration_credentials_secret', 'nonce_secret', 'tls_secret', 'ca_configmap', 'registries_configmap', 'bootstrap_data_configmap', 'capacity_pvc'];
function fields(path, type) {
  const source = read(path);
  const body = source.match(new RegExp(`type ${type} struct \\{([\\s\\S]*?)\\n\\}`))?.[1];
  assert.ok(body, `missing Go deployment type ${type}`);
  return body.trim().split(/\r?\n/).map(line => {
    const match = line.trim().match(/^\w+\s+(string|int64)\s+`json:"([a-z0-9_]+)"`$/);
    assert.ok(match, `unsupported Go deployment field in ${type}`);
    return { type: match[1], name: match[2] };
  });
}
const runtimeFields = fields('backend/internal/systembackupsecurity/registration_runtime.go', 'RegistrationRuntimeConfig');
const bootstrapFields = fields('backend/internal/systembackupsecurity/bootstrap_deployment.go', 'BootstrapDeploymentConfig');
export function requirements() {
  return { status: 'blocked', required: ['image@sha256', 'runtime', 'bootstrap', 'bindings', 'registry_items', 'nonce_items'], optional: ['migration_history'], runtime_fields: runtimeFields.map(f => f.name), bootstrap_fields: bootstrapFields.map(f => f.name), bindings: bindingNames,
    runtime_paths: runtimePaths, bootstrap_paths: bootstrapPaths,
    stages: ['verify live database identity and migration catalog', 'run pinned migration Job', 'check compiled bootstrap requirements and full owner admission', 'run bootstrap Job creating disabled v1', 'start HTTPS runtime and verify readiness', 'administrator performs personal MFA', 'use reviewed config mutation/activation flow'],
    external_gates: ['actual registries and typed refs', 'linked owner adapters', 'live least-privilege identities and TLS', 'trusted DB-volume capacity collector', 'core logout hook', 'administrator personal MFA'],
    database_opened: false, kubernetes_contacted: false, configuration_activated: false };
}
export function emptyTemplate() {
  return { namespace: 'clawmanager-zhanghui08-system', image: '', migration_catalog_sha256: computeMigrationCatalog().hash,
    runtime: { ...Object.fromEntries(runtimeFields.map(f => [f.name, f.type === 'int64' ? 1 : ''])), ...runtimePaths },
    bootstrap: { ...Object.fromEntries(bootstrapFields.map(f => [f.name, ''])), schema_version: 'system-backup-bootstrap-deployment.v1', ...bootstrapPaths },
    bindings: Object.fromEntries(bindingNames.map(name => [name, ''])), registry_items: [], nonce_items: [] };
}
function closed(value, names, label) {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value), `${label}: object required`);
  assert.deepEqual(Object.keys(value).sort(), [...names].sort(), `${label}: missing or unknown fields`);
}
function validateRecord(record, definitions, paths, label) {
  closed(record, definitions.map(f => f.name), label);
  for (const field of definitions) {
    const value = record[field.name];
    assert.ok(field.type === 'int64' ? Number.isSafeInteger(value) && value > 0 : typeof value === 'string' && value.length > 0 && value.length <= 2048 && !/[\x00-\x1f]/.test(value), `${label}.${field.name}: invalid value`);
    if (field.name.endsWith('sha256') || field.name === 's3_identity_hash') assert.match(value, sha, `${label}.${field.name}: digest required`);
  }
  for (const [field, path] of Object.entries(paths)) assert.equal(record[field], path, `${label}.${field}: mount mismatch`);
}
export function renderDeployment(input) {
  const hasHistory = Object.hasOwn(input, 'migration_history');
  closed(input, ['namespace', 'image', 'migration_catalog_sha256', 'runtime', 'bootstrap', 'bindings', 'registry_items', 'nonce_items', ...(hasHistory ? ['migration_history'] : [])], 'deployment');
  assert.ok(typeof input.namespace === 'string' && dns.test(input.namespace) && input.namespace.length <= 63, 'invalid namespace');
  assert.match(input.image, /^[a-zA-Z0-9][a-zA-Z0-9./_:-]*@sha256:[0-9a-f]{64}$/, 'image must be digest-pinned');
  assert.equal(input.migration_catalog_sha256, computeMigrationCatalog().hash, 'image catalog must be checked against current source catalog');
  validateRecord(input.runtime, runtimeFields, runtimePaths, 'runtime');
  validateRecord(input.bootstrap, bootstrapFields, bootstrapPaths, 'bootstrap');
  assert.equal(input.bootstrap.schema_version, 'system-backup-bootstrap-deployment.v1');
  for (const field of ['installation_id', 'expected_server_uuid', 'expected_database']) assert.equal(input.runtime[field], input.bootstrap[field], `runtime/bootstrap ${field} mismatch`);
  assert.match(input.runtime.expected_server_uuid, /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/);
  assert.match(input.runtime.expected_database, /^[A-Za-z0-9_]{1,64}$/);
  assert.match(input.runtime.installation_id, /^[A-Za-z0-9_-]{1,128}$/);
  assert.equal(input.runtime.config_version, 1, 'initial deployment expects disabled bootstrap v1');
  for (const endpoint of ['transit_endpoint', 's3_endpoint']) {
    const url = new URL(input.runtime[endpoint]);
    assert.ok(url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash, `${endpoint}: credential-free HTTPS required`);
  }
  assert.notEqual(input.runtime.provider_transit_key, input.runtime.strong_transit_key, 'issuer signing keys must differ');
  closed(input.bindings, bindingNames, 'bindings');
  for (const value of Object.values(input.bindings)) assert.ok(typeof value === 'string' && dns.test(value) && value.length <= 63, 'invalid mounted resource name');
  assert.equal(new Set([input.bindings.runtime_credentials_secret, input.bindings.bootstrap_credentials_secret, input.bindings.migration_credentials_secret]).size, 3, 'runtime, bootstrap and migration credentials must be distinct');
  const registryKinds = JSON.parse(read('contracts/system-backup/v12/admin-control-resources.schema.json')).$defs.RegistryReference.properties.registry_kind.enum;
  const versionPattern = '[A-Za-z0-9][A-Za-z0-9._-]{0,127}';
  function items(values, pattern) {
    assert.ok(Array.isArray(values) && values.length > 0 && values.length <= 1000, 'explicit volume projections required');
    const paths = new Set();
    for (const item of values) {
      closed(item, ['key', 'path'], 'volume projection');
      assert.ok(typeof item.key === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/.test(item.key), 'invalid projection key');
      assert.ok(typeof item.path === 'string' && pattern.test(item.path) && !item.path.includes('..') && !paths.has(item.path), 'invalid or duplicate projection path');
      paths.add(item.path);
    }
    return paths;
  }
  const registryPaths = items(input.registry_items, new RegExp(`^(${registryKinds.join('|')})/${versionPattern}/[0-9a-f]{64}\\.json$`));
  assert.deepEqual([...new Set(input.registry_items.map(item => item.path.split('/')[0]))].sort(), [...registryKinds].sort(), 'all nine registry projections required');
  items(input.nonce_items, new RegExp(`^[0-9a-f]{64}/${versionPattern}$`));
  if (hasHistory) {
    const history = input.migration_history;
    closed(history, ['review_sha256', 'review_configmap', 'review_key', 'sources_configmap', 'sources_items'], 'migration_history');
    assert.match(history.review_sha256, sha, 'historical review digest required');
    for (const name of [history.review_configmap, history.sources_configmap]) assert.ok(typeof name === 'string' && dns.test(name) && name.length <= 63, 'invalid historical ConfigMap name');
    assert.ok(typeof history.review_key === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/.test(history.review_key), 'invalid historical review key');
    assert.ok(Array.isArray(history.sources_items) && history.sources_items.length <= 64, 'historical source limit');
    items(history.sources_items, /^[0-9]{3}_[A-Za-z0-9_]+\.sql$/);
  }
  for (const [kind, key] of [['provider_proof_issuers', 'provider'], ['strong_auth_issuers', 'strong'], ['rbac_bindings', 'rbac']]) {
    assert.ok(registryPaths.has(`${kind}/${input.runtime[`${key}_registry_version`]}/${input.runtime[`${key}_registry_sha256`]}.json`), `runtime ${kind} pin is not mounted`);
  }
  const runtimeRaw = bytes(input.runtime), bootstrapRaw = bytes(input.bootstrap);
  const runtimeHash = digest(runtimeRaw), bootstrapHash = digest(bootstrapRaw);
  const bundleHash = digest(bytes(input));
  const labels = { 'app.kubernetes.io/name': 'system-backup-registration', 'clawmanager.io/d-bundle': bundleHash.slice(0, 16) };
  const metadata = name => ({ name, namespace: input.namespace, labels });
  const runtimeName = `sbk-runtime-${runtimeHash.slice(0, 16)}`;
  const bootstrapName = `sbk-bootstrap-${bootstrapHash.slice(0, 16)}`;
  const saName = 'system-backup-registration';
  const securityContext = { runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532, seccompProfile: { type: 'RuntimeDefault' } };
  const containerSecurity = { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ['ALL'] } };
  const volume = (name, type, resource) => ({ name, [type]: type === 'persistentVolumeClaim' ? { claimName: resource, readOnly: true } : { [type === 'secret' ? 'secretName' : 'name']: resource, optional: false, defaultMode: 288 } });
  const volumes = {
    runtime: volume('runtime', 'configMap', runtimeName), bootstrap: volume('bootstrap', 'configMap', bootstrapName),
    credentials: volume('credentials', 'secret', input.bindings.runtime_credentials_secret),
    'bootstrap-credentials': volume('bootstrap-credentials', 'secret', input.bindings.bootstrap_credentials_secret),
    'migration-credentials': volume('migration-credentials', 'secret', input.bindings.migration_credentials_secret),
    nonce: volume('nonce', 'secret', input.bindings.nonce_secret), tls: volume('tls', 'secret', input.bindings.tls_secret),
    ca: volume('ca', 'configMap', input.bindings.ca_configmap), registries: volume('registries', 'configMap', input.bindings.registries_configmap),
    'bootstrap-data': volume('bootstrap-data', 'configMap', input.bindings.bootstrap_data_configmap),
    capacity: volume('capacity', 'persistentVolumeClaim', input.bindings.capacity_pvc),
  };
  volumes.registries.configMap.items = input.registry_items;
  volumes.nonce.secret.items = input.nonce_items;
  const migrationCommand = ['/usr/local/bin/system-backup-migrate', '--apply', '--dsn-file', `${prefix}/migration-credentials/dsn`, '--expected-server-uuid', input.runtime.expected_server_uuid, '--expected-database', input.runtime.expected_database, '--expected-catalog-sha256', input.migration_catalog_sha256];
  const migrationMounts = ['migration-credentials'];
  if (hasHistory) {
    const history = input.migration_history;
    volumes['migration-history-review'] = volume('migration-history-review', 'configMap', history.review_configmap);
    volumes['migration-history-review'].configMap.items = [{ key: history.review_key, path: 'review.json' }];
    volumes['migration-history-sources'] = volume('migration-history-sources', 'configMap', history.sources_configmap);
    volumes['migration-history-sources'].configMap.items = history.sources_items;
    migrationMounts.push('migration-history-review', 'migration-history-sources');
    migrationCommand.push('--history-review-file', `${prefix}/migration-history-review/review.json`, '--expected-history-review-sha256', history.review_sha256, '--historical-sql-dir', `${prefix}/migration-history-sources`);
  }
  function pod(command, mounts, extra = {}) {
    return { serviceAccountName: saName, automountServiceAccountToken: false, securityContext,
      containers: [{ name: 'process', image: input.image, imagePullPolicy: 'IfNotPresent', command,
        resources: { requests: { cpu: '50m', memory: '64Mi' }, limits: { cpu: '500m', memory: '256Mi' } },
        securityContext: containerSecurity, volumeMounts: mounts.map(name => ({ name, mountPath: `${prefix}/${name}`, readOnly: true })), ...extra }],
      volumes: mounts.map(name => volumes[name]) };
  }
  const runtimeCommand = ['/usr/local/bin/system-backup-registration', '--runtime', `${prefix}/runtime/runtime.json`];
  const env = [
    ['SYSTEM_BACKUP_REGISTRATION_RUNTIME_SHA256', runtimeHash], ['SYSTEM_BACKUP_REGISTRATION_DSN_FILE', `${prefix}/credentials/dsn`],
    ['SYSTEM_BACKUP_REGISTRATION_TLS_CERT_FILE', `${prefix}/tls/tls.crt`], ['SYSTEM_BACKUP_REGISTRATION_TLS_KEY_FILE', `${prefix}/tls/tls.key`],
  ].map(([name, value]) => ({ name, value }));
  const job = (name, command, mounts) => ({ apiVersion: 'batch/v1', kind: 'Job', metadata: metadata(name), spec: {
    suspend: true, backoffLimit: 0, activeDeadlineSeconds: 900,
    template: { metadata: { labels }, spec: { ...pod(command, mounts), restartPolicy: 'Never' } },
  } });
  const resources = [
    { apiVersion: 'v1', kind: 'ServiceAccount', metadata: metadata(saName), automountServiceAccountToken: false },
    { apiVersion: 'v1', kind: 'ConfigMap', metadata: metadata(runtimeName), immutable: true, data: { 'runtime.json': runtimeRaw } },
    { apiVersion: 'v1', kind: 'ConfigMap', metadata: metadata(bootstrapName), immutable: true, data: { 'deployment.json': bootstrapRaw } },
    job(`sbk-migrate-${bundleHash.slice(0, 16)}`, migrationCommand, migrationMounts),
    job(`sbk-bootstrap-${bundleHash.slice(0, 16)}`, ['/usr/local/bin/system-backup-bootstrap', '--apply', '--deployment-file', `${prefix}/bootstrap/deployment.json`, '--deployment-sha256', bootstrapHash], ['bootstrap', 'bootstrap-data', 'bootstrap-credentials', 'registries', 'nonce', 'capacity']),
    { apiVersion: 'apps/v1', kind: 'Deployment', metadata: metadata(saName), spec: {
      replicas: 0, selector: { matchLabels: { 'app.kubernetes.io/name': labels['app.kubernetes.io/name'], 'clawmanager.io/role': 'https' } },
      strategy: { type: 'Recreate' }, template: { metadata: { labels: { ...labels, 'clawmanager.io/role': 'https' }, annotations: { 'clawmanager.io/runtime-sha256': runtimeHash } },
        spec: pod([...runtimeCommand, '--listen', ':9443'], ['runtime', 'credentials', 'registries', 'nonce', 'tls', 'ca', 'capacity'], {
          env, ports: [{ name: 'https', containerPort: 9443 }],
          startupProbe: { tcpSocket: { port: 'https' }, periodSeconds: 5, failureThreshold: 24 },
          livenessProbe: { tcpSocket: { port: 'https' }, periodSeconds: 15, failureThreshold: 3 },
          readinessProbe: { exec: { command: [...runtimeCommand, '--check-activation'] }, periodSeconds: 30, timeoutSeconds: 30, failureThreshold: 1 },
        }) },
    } },
    { apiVersion: 'v1', kind: 'Service', metadata: metadata(saName), spec: {
      type: 'ClusterIP', selector: { 'app.kubernetes.io/name': labels['app.kubernetes.io/name'], 'clawmanager.io/role': 'https' }, ports: [{ name: 'https', port: 9443, targetPort: 'https' }],
    } },
  ];
  return { report: { status: 'renderable', scope: 'offline public composition only', runtime_sha256: runtimeHash, bootstrap_sha256: bootstrapHash,
    provider_admission: 'not_run', live_input_resources_checked: false, image_catalog_verified: false, configuration_activated: false, human_mfa_verified: false,
    initial_jobs_suspended: true, initial_http_replicas: 0 }, manifest: { apiVersion: 'v1', kind: 'List', items: resources } };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length === 3 && process.argv[2] === '--requirements') { console.log(bytes(requirements())); process.exitCode = 2; }
    else {
      assert.ok(process.argv.length === 4 || process.argv.length === 6, 'usage: --requirements | --input public.json [--output manifest.json]');
      assert.equal(process.argv[2], '--input');
      if (process.argv.length === 6) assert.equal(process.argv[4], '--output');
      const raw = readFileSync(resolve(process.argv[3]), 'utf8');
      assert.ok(Buffer.byteLength(raw) <= 65536, 'public input too large');
      const result = renderDeployment(JSON.parse(raw));
      if (process.argv.length === 6) writeFileSync(resolve(process.argv[5]), bytes(result.manifest), { flag: 'wx' });
      console.log(bytes(result.report));
    }
  } catch { console.error('Deployment input rejected; check required fields, identities, digest pins and mount paths. No cluster contacted.'); process.exitCode = 1; }
}
