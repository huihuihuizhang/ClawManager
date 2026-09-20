import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const contractDir = join(root, 'contracts/system-backup/v12');
const parseJSON = (path) => JSON.parse(readFileSync(path, 'utf8'));
const contractVersion = 'system-backup-plan.v12';

const enums = parseJSON(join(contractDir, 'status-failure-enums.schema.json'));
const taskSchema = parseJSON(join(contractDir, 'task-operation.schema.json'));
const openapi = parseJSON(join(contractDir, 'admin.openapi.json'));
const interfaces = parseJSON(join(contractDir, 'runner-data-interfaces.schema.json'));
const sourceWriter = parseJSON(join(contractDir, 'source-writer-check-state.schema.json'));
const hashAlgorithms = parseJSON(join(contractDir, 'hash-algorithms.json'));
const schemaRegistrySchema = parseJSON(join(contractDir, 'schema-registry.schema.json'));
const schemaRegistry = parseJSON(join(contractDir, 'schema-registry.json'));
const examples = parseJSON(join(contractDir, 'redacted-examples.json'));
const parity = parseJSON(join(contractDir, 'dto-parity.json'));
const reviews = parseJSON(join(contractDir, 'cross-owner-review-requests.json'));
const artifactCommonSchema = parseJSON(join(contractDir, 'artifact-common.schema.json'));
const manifestSchema = parseJSON(join(contractDir, 'manifest-system-backup-v1.schema.json'));
const artifactIndexSchema = parseJSON(join(contractDir, 'artifact-index.schema.json'));
const committedSchema = parseJSON(join(contractDir, 'committed-marker.schema.json'));
const acceptanceSchema = parseJSON(join(contractDir, 'acceptance-marker.schema.json'));
const finalizerSchema = parseJSON(join(contractDir, 'provider-finalizer-request.schema.json'));
const externalActionSchema = parseJSON(join(contractDir, 'external-action-payload.schema.json'));
const publicationExamples = parseJSON(join(contractDir, 'publication-redacted-examples.json'));
const installationStateSchema = parseJSON(join(contractDir, 'installation-state.schema.json'));
const compactTombstoneSchema = parseJSON(join(contractDir, 'compact-tombstone.schema.json'));
const verifierSchema = parseJSON(join(contractDir, 'verifier-contract.schema.json'));
const metricsAlertSchema = parseJSON(join(contractDir, 'metrics-alert-registry.schema.json'));
const metricsAlertRegistry = parseJSON(join(contractDir, 'metrics-alert-registry.json'));
const schemaHashObservationSchema = parseJSON(join(contractDir, 'schema-hash-observation.schema.json'));
const schemaHashResultSchema = parseJSON(join(contractDir, 'schema-hash-result.schema.json'));
const schemaHashLiveEvidenceSchema = parseJSON(join(contractDir, 'schema-hash-live-evidence.schema.json'));
const adminApiCommonSchema = parseJSON(join(contractDir, 'admin-api-common.schema.json'));
const adminOperationPolicySchema = parseJSON(join(contractDir, 'admin-operation-policy.schema.json'));
const adminOperationPolicy = parseJSON(join(contractDir, 'admin-operation-policy.json'));
const adminMutationRequestsSchema = parseJSON(join(contractDir, 'admin-mutation-requests.schema.json'));
const adminOperationErrorsSchema = parseJSON(join(contractDir, 'admin-operation-errors.schema.json'));
const adminOperationErrors = parseJSON(join(contractDir, 'admin-operation-errors.json'));
const adminControlResourcesSchema = parseJSON(join(contractDir, 'admin-control-resources.schema.json'));
const adminControlExamples = parseJSON(join(contractDir, 'admin-control-redacted-examples.json'));
const adminActivityResourcesSchema = parseJSON(join(contractDir, 'admin-activity-resources.schema.json'));
const adminActivityExamples = parseJSON(join(contractDir, 'admin-activity-redacted-examples.json'));
const adminTaskDetailResourcesSchema = parseJSON(join(contractDir, 'admin-task-detail-resources.schema.json'));
const adminTaskDetailExamples = parseJSON(join(contractDir, 'admin-task-detail-redacted-examples.json'));
const dependencyProviderCapabilitySchema = parseJSON(join(contractDir, 'dependency-provider-capability.schema.json'));
const dependencyProviderCapabilityExamples = parseJSON(join(contractDir, 'dependency-provider-capability-redacted-examples.json'));
const controlEvidenceSidecarSchema = parseJSON(join(contractDir, 'control-evidence-sidecar.schema.json'));
const controlEvidenceSidecarExample = parseJSON(join(contractDir, 'control-evidence-sidecar-redacted-example.json'));
const evidenceChunkLogSchema = parseJSON(join(contractDir, 'evidence-chunk-log.schema.json'));
const evidenceChunkLogExamples = parseJSON(join(contractDir, 'evidence-chunk-log-redacted-examples.json'));

function canonicalJSON(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    assert.ok(Number.isFinite(value), 'canonical JSON rejects non-finite numbers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`;
  const entries = Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`);
  return `{${entries.join(',')}}`;
}

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const expectedOperations = [
  'GET /admin/system-backup-overview',
  'GET /admin/system-backup-evidence/{id}',
  'POST /admin/system-backup-provider-proofs',
  'GET /admin/system-backup-operations/{id}',
  'GET /admin/system-backup-config',
  'GET /admin/system-backup-config/versions',
  'GET /admin/system-backup-config/versions/{version}',
  'PUT /admin/system-backup-config',
  'POST /admin/system-backup-config/rollback',
  'POST /admin/system-backup-catalog-scans',
  'GET /admin/system-backup-catalog-scans',
  'GET /admin/system-backup-catalog-scans/{id}',
  'GET /admin/system-backup-catalog-records',
  'GET /admin/system-backup-catalog-records/{id}',
  'POST /admin/system-backup-catalog-imports',
  'GET /admin/system-backup-catalog-imports',
  'GET /admin/system-backup-catalog-imports/{id}',
  'POST /admin/system-backup-catalog-imports/{id}/verify-artifact',
  'POST /admin/system-backup-catalog-imports/{id}/restore-drills',
  'GET /admin/system-backups',
  'POST /admin/system-backups',
  'GET /admin/system-backups/{id}',
  'GET /admin/system-backups/{id}/events',
  'GET /admin/system-backups/{id}/logs',
  'GET /admin/system-backups/{id}/manifest',
  'POST /admin/system-backups/{id}/cancel',
  'POST /admin/system-backups/{id}/resolve-finalization',
  'GET /admin/system-backups/{id}/staging-resources',
  'POST /admin/system-backups/{id}/staging-resources/{resource_id}/resolve-ownership',
  'POST /admin/system-backups/{id}/cleanup-staging',
  'PUT /admin/system-backups/{id}/manual-hold',
  'POST /admin/system-backups/{id}/verify-artifact',
  'GET /admin/system-backup-artifact-verifications',
  'GET /admin/system-backup-artifact-verifications/{id}',
  'GET /admin/system-backup-artifact-verifications/{id}/events',
  'GET /admin/system-backup-artifact-verifications/{id}/logs',
  'POST /admin/system-backup-artifact-verifications/{id}/cancel',
  'POST /admin/system-backups/{id}/restore-drills',
  'GET /admin/system-restore-drills',
  'GET /admin/system-restore-drills/{id}',
  'GET /admin/system-restore-drills/{id}/events',
  'GET /admin/system-restore-drills/{id}/logs',
  'POST /admin/system-restore-drills/{id}/cancel',
  'POST /admin/system-restore-drills/{id}/cleanup',
  'GET /admin/system-restore-drills/{id}/resources',
  'POST /admin/system-restore-drills/{id}/resources/{resource_id}/resolve-ownership',
  'POST /admin/system-backup-preflights',
  'GET /admin/system-backup-preflights',
  'GET /admin/system-backup-preflights/{id}',
  'GET /admin/system-backup-preflights/{id}/events',
  'GET /admin/system-backup-preflights/{id}/logs',
  'GET /admin/system-backup-preflights/{id}/restore-diff',
  'POST /admin/system-backup-preflights/{id}/cancel',
  'POST /admin/system-backup-prune/dry-run',
  'GET /admin/system-backup-prune-runs',
  'POST /admin/system-backup-prune-runs/{id}/confirmation',
  'POST /admin/system-backup-prune/execute',
  'POST /admin/system-backup-prune-runs/{id}/retry',
  'GET /admin/system-backup-prune-runs/{id}',
  'GET /admin/system-backup-prune-runs/{id}/items',
  'GET /admin/system-backup-prune-runs/{id}/events',
  'GET /admin/system-backup-operations',
  'GET /admin/system-backup-promotions',
  'POST /admin/system-backup-promotions',
  'POST /admin/system-backup-promotions/{matrix_key}/revoke',
].sort();

function parseGoArray(source, name) {
  const match = source.match(new RegExp(`var ${name} = \\[\\]string\\{([^}]*)\\}`));
  assert.ok(match, `missing Go enum array ${name}`);
  return JSON.parse(`[${match[1]}]`);
}

function parseTypeScriptArray(source, name) {
  const match = source.match(new RegExp(`export const ${name} = (\\[[^;]+\\]) as const;`));
  assert.ok(match, `missing TypeScript enum array ${name}`);
  return JSON.parse(match[1]);
}

function goJSONFields(source, typeName) {
  const match = source.match(new RegExp(`type ${typeName} struct \\{([\\s\\S]*?)\\n\\}`));
  assert.ok(match, `missing Go DTO ${typeName}`);
  return [...match[1].matchAll(/`json:"([a-z0-9_]+)"`/g)].map((item) => item[1]).sort();
}

function typeScriptFields(source, interfaceName) {
  const match = source.match(new RegExp(`export interface ${interfaceName} \\{([\\s\\S]*?)\\n\\}`));
  assert.ok(match, `missing TypeScript DTO ${interfaceName}`);
  return [...match[1].matchAll(/^\s+([a-z0-9_]+):/gm)].map((item) => item[1]).sort();
}

test('draft machine artifacts use one contract version and local references resolve', () => {
  const machineSchemas = [enums, taskSchema, interfaces, sourceWriter, schemaRegistrySchema, artifactCommonSchema, manifestSchema, artifactIndexSchema, committedSchema, acceptanceSchema, finalizerSchema, externalActionSchema, installationStateSchema, compactTombstoneSchema, verifierSchema, metricsAlertSchema, schemaHashObservationSchema, schemaHashResultSchema, schemaHashLiveEvidenceSchema, adminApiCommonSchema, adminOperationPolicySchema, adminMutationRequestsSchema, adminOperationErrorsSchema, adminControlResourcesSchema, adminActivityResourcesSchema, adminTaskDetailResourcesSchema, dependencyProviderCapabilitySchema, controlEvidenceSidecarSchema, evidenceChunkLogSchema];
  for (const artifact of machineSchemas) {
    assert.equal(artifact['x-contract-version'], contractVersion);
    assert.equal(artifact['x-contract-status'], 'draft');
  }
  assert.equal(openapi.info.version, contractVersion);
  assert.equal(openapi['x-contract-status'], 'draft');
  assert.equal(hashAlgorithms.contract_version, contractVersion);
  assert.equal(hashAlgorithms.status, 'draft');
  assert.equal(examples.contract_version, contractVersion);
  assert.equal(publicationExamples.contract_version, contractVersion);
  assert.equal(parity.contract_version, contractVersion);
  assert.equal(adminOperationPolicy.contract_version, contractVersion);
  assert.equal(adminOperationPolicy.status, 'draft');
  assert.equal(adminOperationErrors.contract_version, contractVersion);
  assert.equal(adminOperationErrors.status, 'draft');
  assert.equal(adminControlExamples.contract_version, contractVersion);
  assert.equal(adminControlExamples.status, 'draft');
  assert.equal(adminActivityExamples.contract_version, contractVersion);
  assert.equal(adminActivityExamples.status, 'draft');
  assert.equal(adminTaskDetailExamples.contract_version, contractVersion);
  assert.equal(adminTaskDetailExamples.status, 'draft');
  assert.equal(evidenceChunkLogExamples.contract_version, contractVersion);
  assert.equal(evidenceChunkLogExamples.status, 'draft');
  assert.equal(metricsAlertRegistry.contract_version, contractVersion);
  assert.equal(metricsAlertRegistry.status, 'draft');
  assert.equal(dependencyProviderCapabilityExamples.contract_version, contractVersion);
  assert.equal(dependencyProviderCapabilityExamples.status, 'draft');
  assert.equal(controlEvidenceSidecarExample.contract_version, contractVersion);
  assert.equal(controlEvidenceSidecarExample.status, 'draft');

  const refs = JSON.stringify([...machineSchemas, openapi]).match(/[a-z0-9-]+\.schema\.json/g) ?? [];
  for (const ref of refs) assert.ok(existsSync(join(contractDir, ref)), `missing local schema reference ${ref}`);
});

test('Admin OpenAPI route inventory exactly matches plan v12 and has unique operation IDs', () => {
  const actual = [];
  const operationIDs = [];
  for (const [path, item] of Object.entries(openapi.paths)) {
    for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
      if (!item[method]) continue;
      actual.push(`${method.toUpperCase()} ${path}`);
      operationIDs.push(item[method].operationId);
      assert.ok(Object.keys(item[method].responses ?? {}).length > 0, `${method.toUpperCase()} ${path} has no response`);
    }
  }
  assert.deepEqual(actual.sort(), expectedOperations);
  assert.equal(new Set(operationIDs).size, operationIDs.length);
  assert.ok(actual.every((item) => !/agent|schedule|restore-runs/.test(item)));
});

test('Admin mutations require bounded idempotency keys and common envelopes are closed', () => {
  const idempotencyRef = '#/components/parameters/IdempotencyKey';
  const mutationOperations = [];
  for (const item of Object.values(openapi.paths)) {
    for (const method of ['get', 'post', 'put']) {
      const operation = item[method];
      if (!operation) continue;
      const refs = (operation.parameters ?? []).map((parameter) => parameter.$ref);
      if (method === 'get') {
        assert.ok(!refs.includes(idempotencyRef), `${operation.operationId} must not require an idempotency key`);
      } else {
        mutationOperations.push(operation.operationId);
        assert.equal(refs.filter((ref) => ref === idempotencyRef).length, 1, `${operation.operationId} must require exactly one idempotency key`);
      }
    }
  }
  assert.equal(mutationOperations.length, 27);
  assert.deepEqual(openapi.components.parameters.IdempotencyKey.schema, { $ref: 'admin-api-common.schema.json#/$defs/IdempotencyKey' });
  assert.deepEqual(adminApiCommonSchema.$defs.IdempotencyKey, { type: 'string', minLength: 16, maxLength: 128, pattern: '^[A-Za-z0-9._:-]+$' });

  const error = adminApiCommonSchema.$defs.Error;
  assert.equal(error.additionalProperties, false);
  assert.deepEqual(error.required, ['code', 'message', 'details', 'request_id']);
  assert.equal(error.properties.retryable, undefined);
  assert.equal(error.properties.message.maxLength, 2048);
  assert.equal(new Set(adminApiCommonSchema.$defs.ApiErrorCode.enum).size, adminApiCommonSchema.$defs.ApiErrorCode.enum.length);

  const list = openapi.components.schemas.List;
  assert.equal(list.additionalProperties, false);
  assert.deepEqual(list.required, ['items', 'next_cursor', 'consistency']);
  assert.deepEqual(list.properties.consistency, { $ref: 'admin-api-common.schema.json#/$defs/ListConsistency' });
});

test('Admin path IDs are resource-prefixed instead of generic database IDs', () => {
  const expectedPathRefs = new Map([
    ['/admin/system-backup-evidence/', 'EvidenceId'],
    ['/admin/system-backup-operations/', 'OperationId'],
    ['/admin/system-backup-catalog-scans/', 'CatalogScanId'],
    ['/admin/system-backup-catalog-records/', 'CatalogRecordId'],
    ['/admin/system-backup-catalog-imports/', 'CatalogImportId'],
    ['/admin/system-backup-artifact-verifications/', 'ArtifactVerificationId'],
    ['/admin/system-backups/', 'BackupId'],
    ['/admin/system-restore-drills/', 'DrillId'],
    ['/admin/system-backup-preflights/', 'PreflightId'],
    ['/admin/system-backup-prune-runs/', 'PruneRunId'],
  ]);
  for (const [path, item] of Object.entries(openapi.paths)) {
    if (!path.includes('{id}')) continue;
    const expected = [...expectedPathRefs].find(([prefix]) => path.startsWith(prefix));
    assert.ok(expected, `missing typed ID expectation for ${path}`);
    for (const operation of Object.values(item)) {
      const refs = (operation.parameters ?? []).map((parameter) => parameter.$ref);
      assert.ok(refs.includes(`#/components/parameters/${expected[1]}`), `${operation.operationId} must use ${expected[1]}`);
      assert.ok(!refs.includes('#/components/parameters/Id'), `${operation.operationId} must not use a generic ID`);
      if (path.includes('{resource_id}')) {
        const resourceParameter = path.startsWith('/admin/system-backups/') ? 'BackupStagingResourceId' : 'RestoreResourceId';
        assert.ok(refs.includes(`#/components/parameters/${resourceParameter}`), `${operation.operationId} must use ${resourceParameter}`);
      }
    }
  }
  assert.equal(openapi.components.parameters.Id, undefined);
  assert.equal(openapi.components.parameters.ResourceId, undefined);
  for (const name of ['BackupPublicId', 'CatalogImportPublicId', 'CatalogScanPublicId', 'CatalogRecordPublicId', 'DrillPublicId', 'PreflightPublicId', 'ArtifactVerificationPublicId', 'PruneRunPublicId', 'OperationPublicId', 'BackupStagingPublicId', 'RestoreResourcePublicId', 'EvidencePublicId']) {
    assert.match(adminApiCommonSchema.$defs[name].pattern, /^\^s[a-z]{2}_/);
  }
});

test('Admin list, event and log routes use bounded opaque cursor pagination', () => {
  let listCount = 0;
  for (const item of Object.values(openapi.paths)) {
    const operation = item.get;
    if (!operation) continue;
    const refs = (operation.parameters ?? []).map((parameter) => parameter.$ref);
    if (!refs.includes('#/components/parameters/Cursor')) continue;
    listCount += 1;
    assert.equal(refs.filter((ref) => ref === '#/components/parameters/Cursor').length, 1, `${operation.operationId} must use one cursor`);
    const expectedLimit = operation.operationId.endsWith('Logs') ? 'LogLimit' : 'Limit';
    assert.equal(refs.filter((ref) => ref === `#/components/parameters/${expectedLimit}`).length, 1, `${operation.operationId} must use ${expectedLimit}`);
    assert.equal(refs.filter((ref) => ref === '#/components/parameters/Limit' || ref === '#/components/parameters/LogLimit').length, 1, `${operation.operationId} must use one limit`);
  }
  assert.equal(listCount, 23);
  assert.equal(adminApiCommonSchema.$defs.PageLimit.default, 50);
  assert.equal(adminApiCommonSchema.$defs.PageLimit.maximum, 500);
  assert.equal(adminApiCommonSchema.$defs.LogPageLimit.maximum, 1000);
  assert.equal(adminApiCommonSchema.$defs.Cursor['x-max-utf8-bytes'], 4096);
});

test('Admin synchronous and asynchronous mutation status codes match the plan', () => {
  const synchronous = new Map([
    ['registerSystemBackupProviderProof', '201'],
    ['updateSystemBackupConfig', '200'],
    ['rollbackSystemBackupConfig', '200'],
    ['updateSystemBackupManualHold', '200'],
    ['issueSystemBackupPruneConfirmation', '200'],
    ['createSystemBackupPromotion', '201'],
    ['revokeSystemBackupPromotion', '200'],
  ]);
  for (const item of Object.values(openapi.paths)) {
    for (const method of ['post', 'put']) {
      const operation = item[method];
      if (!operation) continue;
      const expected = synchronous.get(operation.operationId) ?? '202';
      assert.deepEqual(Object.keys(operation.responses).filter((status) => /^\d+$/.test(status)), [expected], `${operation.operationId} must return HTTP ${expected}`);
      assert.deepEqual(operation.responses.default, { $ref: '#/components/responses/Error' });
    }
  }
});

test('Admin 201 and 202 responses publish Location and task-producing routes return tasks', () => {
  const expectedTaskOperations = new Set([
    'verifyImportedSystemBackupArtifact',
    'createImportedSystemRestoreDrill',
    'createSystemBackup',
    'verifySystemBackupArtifact',
    'createSystemRestoreDrill',
    'createSystemBackupPreflight',
  ]);
  const actualTaskOperations = new Set();
  for (const item of Object.values(openapi.paths)) {
    for (const method of ['post', 'put']) {
      const operation = item[method];
      if (!operation) continue;
      const [status, response] = Object.entries(operation.responses).find(([key]) => /^\d+$/.test(key));
      if (status === '201' || status === '202') {
        const responseName = response.$ref.split('/').at(-1);
        const responseComponent = openapi.components.responses[responseName];
        assert.deepEqual(responseComponent.headers.Location, { $ref: '#/components/headers/Location' }, `${operation.operationId} must publish Location`);
        if (status === '202') assert.deepEqual(responseComponent.headers['Retry-After'], { $ref: '#/components/headers/RetryAfter' });
        if (responseName === 'TaskAccepted') actualTaskOperations.add(operation.operationId);
      }
    }
  }
  assert.deepEqual(actualTaskOperations, expectedTaskOperations);
  assert.equal(openapi.components.headers.Location.required, true);
  assert.deepEqual(openapi.components.headers.Location.schema, { $ref: 'admin-api-common.schema.json#/$defs/Location' });
});

test('Admin operation policy covers OpenAPI exactly and preserves D orchestration boundaries', () => {
  const openApiOperations = [];
  for (const [path, item] of Object.entries(openapi.paths)) {
    for (const method of ['get', 'post', 'put']) {
      const operation = item[method];
      if (!operation) continue;
      openApiOperations.push({
        operation_id: operation.operationId,
        method: method.toUpperCase(),
        path,
        success_http_status: Number(Object.keys(operation.responses)[0]),
      });
    }
  }
  const policies = new Map(adminOperationPolicy.operations.map((policy) => [policy.operation_id, policy]));
  assert.equal(policies.size, adminOperationPolicy.operations.length);
  assert.equal(policies.size, openApiOperations.length);
  for (const operation of openApiOperations) {
    const policy = policies.get(operation.operation_id);
    assert.ok(policy, `missing operation policy for ${operation.operation_id}`);
    assert.equal(policy.method, operation.method);
    assert.equal(policy.path, operation.path);
    assert.equal(policy.success_http_status, operation.success_http_status);
    assert.equal(policy.idempotency_required, operation.method !== 'GET');
    assert.equal(policy.completion_mode, operation.success_http_status === 202 ? 'asynchronous' : 'synchronous');
    if (operation.method === 'GET') {
      assert.deepEqual(policy.required_permissions, ['system_backup.read']);
      assert.equal(policy.kill_switch, 'allowed_when_disabled');
    }
  }
  assert.equal(openapi['x-operation-policy-registry'], 'contracts/system-backup/v12/admin-operation-policy.json');
  assert.deepEqual(adminOperationPolicy.middleware, ['Auth', 'SetUserInfo', 'NewAdminAuth']);
  assert.deepEqual(adminOperationPolicy.built_in_roles, {
    viewer: ['system_backup.read'],
    operator: ['system_backup.read', 'system_backup.operate'],
    config_admin: ['system_backup.read', 'system_backup.configure'],
    security_admin: ['system_backup.read', 'system_backup.operate', 'system_backup.configure', 'system_backup.security_configure', 'system_backup.destructive'],
  });

  const strongRequired = adminOperationPolicy.operations.filter((policy) => policy.recent_strong_auth === 'required').map((policy) => policy.operation_id).sort();
  assert.deepEqual(strongRequired, [
    'executeSystemBackupPrune',
    'issueSystemBackupPruneConfirmation',
    'registerSystemBackupProviderProof',
    'resolveSystemBackupFinalization',
    'resolveSystemBackupStagingOwnership',
    'resolveSystemRestoreDrillResourceOwnership',
    'retrySystemBackupPrune',
  ]);
  const strongConditional = adminOperationPolicy.operations.filter((policy) => policy.recent_strong_auth === 'conditional').map((policy) => policy.operation_id).sort();
  assert.deepEqual(strongConditional, ['rollbackSystemBackupConfig', 'updateSystemBackupConfig', 'updateSystemBackupManualHold']);

  const blockedByKillSwitch = adminOperationPolicy.operations.filter((policy) => policy.kill_switch === 'requires_effective_enabled').map((policy) => policy.operation_id).sort();
  assert.deepEqual(blockedByKillSwitch, [
    'createImportedSystemRestoreDrill',
    'createSystemBackup',
    'createSystemBackupPreflight',
    'createSystemBackupPromotion',
    'createSystemBackupPruneDryRun',
    'createSystemRestoreDrill',
    'executeSystemBackupPrune',
    'retrySystemBackupPrune',
    'verifyImportedSystemBackupArtifact',
    'verifySystemBackupArtifact',
  ]);
});

test('Admin API error codes have one frozen HTTP status mapping', () => {
  const errorCodes = adminApiCommonSchema.$defs.ApiErrorCode.enum;
  const mappings = new Map(adminOperationPolicy.error_status_map.map((entry) => [entry.code, entry.http_status]));
  assert.equal(mappings.size, adminOperationPolicy.error_status_map.length);
  assert.deepEqual([...mappings.keys()].sort(), [...errorCodes].sort());
  for (const code of ['authentication_required', 'strong_auth_required', 'strong_auth_expired', 'strong_auth_invalid_issuer', 'strong_auth_invalid', 'strong_auth_replayed']) assert.equal(mappings.get(code), 401);
  for (const code of ['idempotency_conflict', 'state_conflict', 'version_conflict', 'commit_started']) assert.equal(mappings.get(code), 409);
  assert.equal(mappings.get('logs_expired'), 410);
  assert.equal(mappings.get('idempotency_expired'), 410);
  assert.equal(mappings.get('payload_too_large'), 413);
  assert.equal(mappings.get('range_not_satisfiable'), 416);
  assert.equal(mappings.get('rate_limited'), 429);
  assert.equal(mappings.get('internal_error'), 500);
  let operationCount = 0;
  for (const item of Object.values(openapi.paths)) {
    for (const method of ['get', 'post', 'put']) {
      if (!item[method]) continue;
      operationCount += 1;
      assert.deepEqual(item[method].responses.default, { $ref: '#/components/responses/Error' });
    }
  }
  assert.equal(operationCount, 65);
});

test('Admin operation error profiles cover every route once and keep exceptional codes scoped', () => {
  const allowedCodes = new Set(adminApiCommonSchema.$defs.ApiErrorCode.enum);
  const expectedProfileIDs = adminOperationErrorsSchema.$defs.ProfileId.enum;
  const profiles = new Map(adminOperationErrors.profiles.map((profile) => [profile.profile_id, profile.codes]));
  assert.equal(profiles.size, adminOperationErrors.profiles.length);
  assert.deepEqual([...profiles.keys()].sort(), [...expectedProfileIDs].sort());
  for (const [profileID, codes] of profiles) {
    assert.equal(new Set(codes).size, codes.length, `${profileID} repeats an error code`);
    for (const code of codes) assert.ok(allowedCodes.has(code), `${profileID} uses unknown error code ${code}`);
  }

  const assignmentProfiles = adminOperationErrors.assignments.map((assignment) => assignment.profile_id);
  assert.equal(new Set(assignmentProfiles).size, assignmentProfiles.length);
  assert.deepEqual([...assignmentProfiles].sort(), [...expectedProfileIDs].sort());

  const assignedOperationIDs = adminOperationErrors.assignments.flatMap((assignment) => assignment.operation_ids);
  assert.equal(new Set(assignedOperationIDs).size, assignedOperationIDs.length);
  const openApiOperationIDs = [];
  for (const item of Object.values(openapi.paths)) {
    for (const method of ['get', 'post', 'put']) {
      if (item[method]) openApiOperationIDs.push(item[method].operationId);
    }
  }
  assert.deepEqual([...assignedOperationIDs].sort(), openApiOperationIDs.sort());

  const operationPolicies = new Map(adminOperationPolicy.operations.map((policy) => [policy.operation_id, policy]));
  const strongAuthCodes = new Set(['strong_auth_required', 'strong_auth_expired', 'strong_auth_invalid_issuer', 'strong_auth_invalid', 'strong_auth_replayed']);
  for (const assignment of adminOperationErrors.assignments) {
    if (!profiles.get(assignment.profile_id).some((code) => strongAuthCodes.has(code))) continue;
    for (const operationID of assignment.operation_ids) {
      assert.notEqual(operationPolicies.get(operationID).recent_strong_auth, 'none', `${operationID} must not expose strong-auth errors`);
    }
  }

  const operationsForCode = (code) => adminOperationErrors.assignments
    .filter((assignment) => profiles.get(assignment.profile_id).includes(code))
    .flatMap((assignment) => assignment.operation_ids)
    .sort();
  assert.deepEqual(operationsForCode('commit_started'), ['cancelSystemBackup']);
  assert.deepEqual(operationsForCode('logs_expired'), [
    'listSystemBackupArtifactVerificationLogs',
    'listSystemBackupLogs',
    'listSystemBackupPreflightLogs',
    'listSystemRestoreDrillLogs',
  ]);
  assert.deepEqual(operationsForCode('range_not_satisfiable'), ['getSystemBackupEvidence']);
  assert.equal(openapi['x-operation-error-policy'], 'contracts/system-backup/v12/admin-operation-errors.json');
});

test('D-owned Admin mutation bodies are closed and owner authentication fields stay external', () => {
  const expectedBodies = new Map([
    ['updateSystemBackupConfig', 'ConfigUpdate'],
    ['rollbackSystemBackupConfig', 'ConfigRollback'],
    ['cancelSystemBackup', 'Cancel'],
    ['resolveSystemBackupFinalization', 'FinalizationResolution'],
    ['resolveSystemBackupStagingOwnership', 'OwnershipResolution'],
    ['cleanupSystemBackupStaging', 'Cleanup'],
    ['updateSystemBackupManualHold', 'ManualHoldUpdate'],
    ['cancelSystemBackupArtifactVerification', 'Cancel'],
    ['cancelSystemRestoreDrill', 'Cancel'],
    ['cleanupSystemRestoreDrill', 'Cleanup'],
    ['resolveSystemRestoreDrillResourceOwnership', 'OwnershipResolution'],
    ['cancelSystemBackupPreflight', 'Cancel'],
    ['issueSystemBackupPruneConfirmation', 'PruneConfirmation'],
    ['executeSystemBackupPrune', 'PruneExecute'],
    ['retrySystemBackupPrune', 'PruneRetry'],
    ['createSystemBackupPromotion', 'PromotionCreate'],
    ['revokeSystemBackupPromotion', 'PromotionRevoke'],
  ]);
  let attached = 0;
  for (const item of Object.values(openapi.paths)) {
    for (const method of ['post', 'put']) {
      const operation = item[method];
      if (!operation?.requestBody) continue;
      attached += 1;
      const expected = expectedBodies.get(operation.operationId);
      assert.ok(expected, `unexpected D-owned request body on ${operation.operationId}`);
      assert.deepEqual(operation.requestBody, { $ref: `#/components/requestBodies/${expected}` });
    }
  }
  assert.equal(attached, expectedBodies.size);
  for (const [componentName, component] of Object.entries(openapi.components.requestBodies)) {
    assert.equal(component.required, true);
    const ref = component.content['application/json'].schema.$ref;
    const defName = ref.split('/').at(-1);
    const source = ref.startsWith('admin-control-resources.schema.json') ? adminControlResourcesSchema : adminMutationRequestsSchema;
    assert.ok(source.$defs[defName], `${componentName} references missing ${defName}`);
    assert.equal(source.$defs[defName].additionalProperties, false);
  }
  assert.deepEqual(adminMutationRequestsSchema['x-request-hash-excluded-transport'], ['request_id', 'idempotency_key', 'strong_auth_proof']);
  assert.match(adminMutationRequestsSchema['x-owner-boundaries'].A, /pending_owner_submission/);
  for (const name of ['FinalizationResolutionRequest', 'OwnershipResolutionRequest']) {
    const schema = adminMutationRequestsSchema.$defs[name];
    for (const field of schema['x-forbidden-fields']) assert.equal(schema.properties[field], undefined);
    assert.equal(schema.properties.provider_proof_evidence_public_id.$ref, 'admin-api-common.schema.json#/$defs/EvidencePublicId');
  }
});

test('Go and TypeScript DTO snapshots match enum and field schemas', () => {
  const goSource = readFileSync(join(root, parity.go_snapshot), 'utf8');
  const tsSource = readFileSync(join(root, parity.typescript_snapshot), 'utf8');
  const mappings = [
    ['TaskTypes', 'taskTypes', 'TaskType'],
    ['BackupStatuses', 'backupStatuses', 'BackupStatus'],
    ['DrillStatuses', 'drillStatuses', 'DrillStatus'],
    ['SimpleTaskStatuses', 'simpleTaskStatuses', 'SimpleTaskStatus'],
    ['OperationStatuses', 'operationStatuses', 'OperationStatus'],
    ['OperationTypes', 'operationTypes', 'OperationType'],
    ['FailureCategories', 'failureCategories', 'FailureCategory'],
  ];
  for (const [goName, tsName, schemaName] of mappings) {
    const expected = enums.$defs[schemaName].enum;
    assert.deepEqual(parseGoArray(goSource, goName), expected);
    assert.deepEqual(parseTypeScriptArray(tsSource, tsName), expected);
  }

  const taskFields = Object.keys(taskSchema.$defs.Task.properties).sort();
  const operationFields = Object.keys(taskSchema.$defs.Operation.properties).sort();
  assert.deepEqual(goJSONFields(goSource, 'Task'), taskFields);
  assert.deepEqual(goJSONFields(goSource, 'Operation'), operationFields);
  assert.deepEqual(typeScriptFields(tsSource, 'SystemBackupTask'), taskFields);
  assert.deepEqual(typeScriptFields(tsSource, 'SystemBackupOperation'), operationFields);
  for (const typeName of ['TaskList', 'OperationList']) {
    const fields = Object.keys(taskSchema.$defs[typeName].properties).sort();
    assert.deepEqual(goJSONFields(goSource, typeName), fields, `${typeName} Go fields drifted`);
    assert.deepEqual(typeScriptFields(tsSource, typeName), fields, `${typeName} TypeScript fields drifted`);
  }

  const requestTypes = [
    'CancelRequest',
    'CleanupRequest',
    'ConfigRollbackRequest',
    'FinalizationResolutionRequest',
    'OwnershipResolutionRequest',
    'ManualHoldUpdateRequest',
    'PromotionCreateRequest',
    'PromotionRevokeRequest',
    'PruneConfirmationRequest',
    'PruneExecuteRequest',
    'PruneRetryRequest',
  ];
  for (const typeName of requestTypes) {
    const fields = Object.keys(adminMutationRequestsSchema.$defs[typeName].properties).sort();
    assert.deepEqual(goJSONFields(goSource, typeName), fields, `${typeName} Go fields drifted`);
    assert.deepEqual(typeScriptFields(tsSource, typeName), fields, `${typeName} TypeScript fields drifted`);
  }
  const controlTypes = [
    'ConfigReference',
    'RegistryReference',
    'DurationConfig',
    'CapacityConfig',
    'ConcurrencyConfig',
    'PreflightLimits',
    'ConfigValues',
    'ConfigUpdateRequest',
    'ConfigResource',
    'FailureDomainShortage',
    'OverviewResource',
    'PruneRunResource',
    'PruneConfirmationResource',
  ];
  for (const typeName of controlTypes) {
    const fields = Object.keys(adminControlResourcesSchema.$defs[typeName].properties).sort();
    assert.deepEqual(goJSONFields(goSource, typeName), fields, `${typeName} Go fields drifted`);
    assert.deepEqual(typeScriptFields(tsSource, typeName), fields, `${typeName} TypeScript fields drifted`);
  }
  const activityTypes = [
    'EventDetails',
    'EventResource',
    'EventResourceList',
    'LogEntryResource',
    'LogEntryResourceList',
    'PruneItemResource',
    'PruneItemResourceList',
    'PromotionHealth',
    'PromotionResource',
    'PromotionResourceList',
  ];
  for (const typeName of activityTypes) {
    const fields = Object.keys(adminActivityResourcesSchema.$defs[typeName].properties).sort();
    assert.deepEqual(goJSONFields(goSource, typeName), fields, `${typeName} Go fields drifted`);
    assert.deepEqual(typeScriptFields(tsSource, typeName), fields, `${typeName} TypeScript fields drifted`);
  }
  const taskDetailTypes = [
    'EvidenceReference',
    'SourceArtifactReference',
    'ExecutionProjection',
    'VerifierSummary',
    'NullableArtifactChecksumSet',
    'BackupDetailResource',
    'DrillDetailResource',
    'PreflightDetailResource',
    'ArtifactVerificationDetailResource',
  ];
  for (const typeName of taskDetailTypes) {
    const fields = Object.keys(adminTaskDetailResourcesSchema.$defs[typeName].properties).sort();
    assert.deepEqual(goJSONFields(goSource, typeName), fields, `${typeName} Go fields drifted`);
    assert.deepEqual(typeScriptFields(tsSource, typeName), fields, `${typeName} TypeScript fields drifted`);
  }
  assert.deepEqual(parity.schema_sources, [
    'contracts/system-backup/v12/task-operation.schema.json',
    'contracts/system-backup/v12/admin-mutation-requests.schema.json',
    'contracts/system-backup/v12/admin-control-resources.schema.json',
    'contracts/system-backup/v12/admin-activity-resources.schema.json',
    'contracts/system-backup/v12/admin-task-detail-resources.schema.json',
  ]);
});

test('D-owned Admin resources replace only D placeholders and bind the existing manifest contract', () => {
  const expectedResponses = new Map([
    ['getSystemBackupOverview', 'Overview'],
    ['getSystemBackupConfig', 'Config'],
    ['listSystemBackupConfigVersions', 'ConfigList'],
    ['getSystemBackupConfigVersion', 'Config'],
    ['getSystemBackupManifest', 'Manifest'],
    ['createSystemBackupPruneDryRun', 'PruneRunAccepted'],
    ['listSystemBackupPruneRuns', 'PruneRunList'],
    ['issueSystemBackupPruneConfirmation', 'PruneConfirmation'],
    ['getSystemBackupPruneRun', 'PruneRun'],
  ]);
  const remainingDirectPlaceholders = [];
  for (const item of Object.values(openapi.paths)) {
    for (const method of ['get', 'post', 'put']) {
      const operation = item[method];
      if (!operation) continue;
      const success = Object.entries(operation.responses).find(([status]) => /^\d+$/.test(status))[1];
      if (expectedResponses.has(operation.operationId)) {
        assert.deepEqual(success, { $ref: `#/components/responses/${expectedResponses.get(operation.operationId)}` });
      } else if (success.$ref === '#/components/responses/Resource') {
        remainingDirectPlaceholders.push(operation.operationId);
      }
    }
  }
  assert.deepEqual(remainingDirectPlaceholders.sort(), [
    'getSystemBackupCatalogImport',
    'getSystemBackupCatalogRecord',
    'getSystemBackupCatalogScan',
    'getSystemBackupEvidence',
    'getSystemBackupPreflightRestoreDiff',
  ]);
  assert.deepEqual(openapi.components.responses.Manifest.content['application/json'].schema, { $ref: 'manifest-system-backup-v1.schema.json' });
  assert.deepEqual(openapi.components.requestBodies.ConfigUpdate.content['application/json'].schema, { $ref: 'admin-control-resources.schema.json#/$defs/ConfigUpdateRequest' });
});

test('D-owned task detail routes use typed closed projections without claiming owner payloads', () => {
  const expected = new Map([
    ['getSystemBackup', 'BackupDetail'],
    ['getSystemBackupArtifactVerification', 'ArtifactVerificationDetail'],
    ['getSystemRestoreDrill', 'DrillDetail'],
    ['getSystemBackupPreflight', 'PreflightDetail'],
  ]);
  for (const item of Object.values(openapi.paths)) {
    const operation = item.get;
    if (!operation || !expected.has(operation.operationId)) continue;
    assert.deepEqual(operation.responses['200'], { $ref: `#/components/responses/${expected.get(operation.operationId)}` });
  }
  assert.equal(expected.size, 4);
  const responseRefs = {
    BackupDetail: 'admin-task-detail-resources.schema.json#/$defs/BackupDetailResource',
    ArtifactVerificationDetail: 'admin-task-detail-resources.schema.json#/$defs/ArtifactVerificationDetailResource',
    DrillDetail: 'admin-task-detail-resources.schema.json#/$defs/DrillDetailResource',
    PreflightDetail: 'admin-task-detail-resources.schema.json#/$defs/PreflightDetailResource',
  };
  for (const [name, ref] of Object.entries(responseRefs)) {
    assert.deepEqual(openapi.components.responses[name].content['application/json'].schema, { $ref: ref });
  }

  const defs = adminTaskDetailResourcesSchema.$defs;
  for (const name of ['EvidenceReference', 'SourceArtifactReference', 'ExecutionProjection', 'VerifierSummary', 'NullableArtifactChecksumSet', 'BackupDetailResource', 'DrillDetailResource', 'PreflightDetailResource', 'ArtifactVerificationDetailResource']) {
    assert.equal(defs[name].additionalProperties, false, `${name} must be closed`);
    assert.deepEqual([...defs[name].required].sort(), Object.keys(defs[name].properties).sort(), `${name} must require every property`);
  }
  assert.equal(defs.BackupDetailResource.properties.task.allOf[1].properties.task_type.const, 'backup');
  assert.equal(defs.DrillDetailResource.properties.task.allOf[1].properties.task_type.const, 'drill');
  assert.equal(defs.PreflightDetailResource.properties.task.allOf[1].properties.task_type.const, 'preflight');
  assert.equal(defs.ArtifactVerificationDetailResource.properties.task.allOf[1].properties.task_type.const, 'artifact_verify');
  assert.equal(defs.SourceArtifactReference.allOf.length, 2);
  assert.match(adminTaskDetailResourcesSchema['x-owner-boundaries'].A, /aggregate counts/);
  assert.match(adminTaskDetailResourcesSchema['x-owner-boundaries'].B, /immutable hash/);
  assert.match(adminTaskDetailResourcesSchema['x-owner-boundaries'].C, /not embedded/);
  const serializedSchema = JSON.stringify(adminTaskDetailResourcesSchema);
  assert.doesNotMatch(serializedSchema, /"(?:uri|location|credential|secret|expected|actual)"\s*:/i);
});

test('D-owned task detail conditions preserve eligibility, cleanup and artifact-state authority', () => {
  const defs = adminTaskDetailResourcesSchema.$defs;
  const backupRules = defs.BackupDetailResource.allOf;
  assert.equal(backupRules.length, 5);
  assert.equal(backupRules[0].then.properties.artifact_unusable_reason.const, 'none');
  assert.deepEqual(backupRules[1].then.properties.eligibility_reason_codes.const, ['eligible']);
  assert.equal(backupRules[1].then.properties.eligibility_decision_hash.$ref, '#/$defs/Sha256');
  assert.equal(backupRules[2].then.properties.acceptance_eligible.const, true);
  assert.equal(backupRules[3].then.properties.artifact_registration_hash.type, 'null');
  assert.equal(backupRules[3].else.properties.artifact_registration_hash.$ref, '#/$defs/Sha256');
  assert.equal(backupRules[4].then.properties.manual_hold_reason.type, 'null');
  assert.equal(backupRules[4].else.properties.manual_hold_reason.minLength, 1);
  assert.equal(backupRules[4].else.properties.manual_hold_actor.minLength, 1);
  assert.equal(backupRules[4].else.properties.manual_hold_at.format, 'date-time');

  const drillRules = defs.DrillDetailResource.allOf;
  assert.equal(drillRules.length, 2);
  assert.equal(drillRules[0].else.properties.cleanup_failure_code.const, 'none');
  assert.equal(drillRules[1].then.properties.task_purpose.const, 'acceptance');
  assert.equal(drillRules[1].then.properties.cleanup_policy.const, 'delete-on-success');
  assert.equal(drillRules[1].then.properties.cleanup_status.const, 'succeeded');
  assert.deepEqual(drillRules[1].then.properties.eligibility_reason_codes.const, ['eligible']);
  assert.equal(drillRules[1].then.properties.eligibility_decision_hash.$ref, '#/$defs/Sha256');

  const verificationRules = defs.ArtifactVerificationDetailResource.allOf;
  assert.equal(verificationRules.length, 2);
  assert.equal(verificationRules[0].else.properties.artifact_state_before.type, 'null');
  assert.equal(verificationRules[0].else.properties.artifact_state_after.type, 'null');
  assert.equal(verificationRules[1].then.properties.unusable_reason_after.const, 'none');
  assert.match(defs.ArtifactVerificationDetailResource['x-invariant'], /historical eligibility is never rewritten/);
});

test('D-owned task detail examples assemble into exact redacted response shapes', () => {
  const defs = adminTaskDetailResourcesSchema.$defs;
  const shared = adminTaskDetailExamples.shared;
  const templates = adminTaskDetailExamples.task_templates;
  const fields = adminTaskDetailExamples.resource_fields;
  const assembled = {
    BackupDetailResource: { ...fields.BackupDetailResource, task: templates.backup, execution: shared.execution, checksums: shared.checksums, verifier_summary: shared.verifier_summary },
    DrillDetailResource: { ...fields.DrillDetailResource, task: templates.drill, execution: shared.execution, source_checksums: shared.checksums, verifier_summary: shared.verifier_summary },
    PreflightDetailResource: { ...fields.PreflightDetailResource, task: templates.preflight, execution: shared.execution, source_checksums: shared.checksums, verifier_summary: shared.verifier_summary },
    ArtifactVerificationDetailResource: { ...fields.ArtifactVerificationDetailResource, task: templates.artifact_verification, execution: shared.execution, observed_checksums: shared.checksums, verifier_summary: shared.verifier_summary },
  };
  for (const [name, example] of Object.entries(assembled)) {
    assert.deepEqual(Object.keys(example).sort(), Object.keys(defs[name].properties).sort(), `${name} fixture is not closed`);
    assert.deepEqual(Object.keys(example.task).sort(), Object.keys(taskSchema.$defs.Task.properties).sort(), `${name} task fixture drifted`);
    assert.equal(example.task.task_type, defs[name].properties.task.allOf[1].properties.task_type.const);
  }
  assert.deepEqual(Object.keys(shared.execution).sort(), Object.keys(defs.ExecutionProjection.properties).sort());
  assert.deepEqual(Object.keys(shared.checksums).sort(), Object.keys(defs.NullableArtifactChecksumSet.properties).sort());
  assert.deepEqual(Object.keys(shared.verifier_summary).sort(), Object.keys(defs.VerifierSummary.properties).sort());
  assert.deepEqual(Object.keys(shared.verifier_summary.report_evidence).sort(), Object.keys(defs.EvidenceReference.properties).sort());
  const serialized = JSON.stringify(adminTaskDetailExamples);
  assert.doesNotMatch(serialized, /:\/\//);
  assert.doesNotMatch(serialized, /"(?:password|secret|token|credential|private_key|authorization|uri|location|expected|actual)"\s*:/i);
});

test('D-owned config wire records all defaults, redacted references and cross-field safety rules', () => {
  const defs = adminControlResourcesSchema.$defs;
  for (const name of ['ConfigReference', 'RegistryReference', 'DurationConfig', 'CapacityConfig', 'ConcurrencyConfig', 'PreflightLimits', 'ConfigValues', 'ConfigUpdateRequest', 'ConfigResource', 'FailureDomainShortage', 'OverviewResource', 'PruneRunResource', 'PruneConfirmationResource', 'ConfigResourceList', 'PruneRunResourceList']) {
    assert.equal(defs[name].additionalProperties, false, `${name} must be closed`);
    assert.deepEqual([...defs[name].required].sort(), Object.keys(defs[name].properties).sort(), `${name} must require every property`);
  }
  const values = adminControlExamples.config_update_request.config;
  for (const section of ['durations', 'capacity', 'concurrency', 'preflight_limits']) {
    assert.deepEqual(Object.keys(values[section]).sort(), Object.keys(defs[section === 'durations' ? 'DurationConfig' : section === 'capacity' ? 'CapacityConfig' : section === 'concurrency' ? 'ConcurrencyConfig' : 'PreflightLimits'].properties).sort());
    for (const [key, value] of Object.entries(values[section])) assert.equal(defs[section === 'durations' ? 'DurationConfig' : section === 'capacity' ? 'CapacityConfig' : section === 'concurrency' ? 'ConcurrencyConfig' : 'PreflightLimits'].properties[key].default, value, `${key} default drifted`);
  }
  assert.equal(defs.ConfigValues.properties.enabled.default, false);
  assert.equal(defs.ConfigValues.properties.alert_profile.default, 'production');
  assert.equal(defs.ConfigValues.properties.minimum_recovery_points.default, 1);
  assert.equal(defs.ConfigValues['x-max-jcs-utf8-bytes'], 262144);
  assert.equal(defs.ConfigUpdateRequest['x-max-jcs-utf8-bytes'], 262144);
  assert.equal(defs.ConfigValues.properties.registries.uniqueItems, true);
  assert.equal(defs.ConfigValues.properties.references.uniqueItems, true);

  const registryKinds = defs.RegistryReference.properties.registry_kind.enum;
  assert.deepEqual(values.registries.map((entry) => entry.registry_kind).sort(), [...registryKinds].sort());
  assert.equal(new Set(values.registries.map((entry) => entry.registry_kind)).size, registryKinds.length);
  const referencePurposes = defs.ConfigReference.properties.purpose.enum;
  assert.deepEqual(values.references.map((entry) => entry.purpose).sort(), [...referencePurposes].sort());
  assert.equal(new Set(values.references.map((entry) => entry.purpose)).size, referencePurposes.length);

  const d = values.durations;
  assert.ok(d.controller_claim_heartbeat_seconds <= d.controller_claim_ttl_seconds / 3);
  assert.ok(d.mutation_lease_heartbeat_seconds <= d.mutation_lease_ttl_seconds / 3);
  assert.ok(d.artifact_lease_heartbeat_seconds <= d.artifact_lease_ttl_seconds / 3);
  assert.ok(d.maintenance_lock_ttl_seconds >= d.quiesce_max_hold_seconds + d.watchdog_safety_margin_seconds + 2 * d.controller_claim_ttl_seconds);
  assert.ok(d.evidence_retention_seconds >= d.retention_seconds);
  assert.ok(d.control_metadata_retention_seconds >= Math.max(d.retention_seconds, d.evidence_retention_seconds, d.logs_retention_seconds, d.strong_auth_max_age_seconds));
  assert.ok(values.capacity.staging_capacity_bytes >= Math.ceil(values.capacity.max_artifact_bytes * 1.10) + values.capacity.max_index_bytes);
  assert.ok(values.capacity.log_chunk_bytes <= values.capacity.max_log_bytes);
  assert.ok(values.capacity.log_chunk_lines <= values.capacity.max_log_lines);
  assert.ok(values.concurrency.max_auto_attempts >= 1 && values.concurrency.max_auto_attempts <= 10);
  assert.ok(d.capture_certificate_ttl_seconds > d.backup_task_deadline_seconds);

  const serialized = JSON.stringify(adminControlExamples);
  assert.doesNotMatch(serialized, /:\/\//);
  assert.doesNotMatch(serialized, /"(?:password|secret|token|credential|private_key|strong_auth_proof|uri)"\s*:/i);
});

test('D-owned control examples are closed snapshots of their response schemas', () => {
  const defs = adminControlResourcesSchema.$defs;
  assert.deepEqual(Object.keys(adminControlExamples.overview_resource).sort(), Object.keys(defs.OverviewResource.properties).sort());
  assert.deepEqual(Object.keys(adminControlExamples.config_update_request).sort(), Object.keys(defs.ConfigUpdateRequest.properties).sort());
  assert.deepEqual(Object.keys(adminControlExamples.prune_run_resource).sort(), Object.keys(defs.PruneRunResource.properties).sort());
  assert.deepEqual(Object.keys(adminControlExamples.prune_confirmation_resource).sort(), Object.keys(defs.PruneConfirmationResource.properties).sort());
  const configResource = { ...adminControlExamples.config_resource_metadata, config: adminControlExamples.config_update_request.config };
  assert.deepEqual(Object.keys(configResource).sort(), Object.keys(defs.ConfigResource.properties).sort());
  assert.deepEqual(defs.PruneRunResource.properties.status.enum, ['planning', 'dry_run_created', 'executing', 'partial_failed', 'succeeded', 'failed', 'expired']);
  const candidateFields = ['candidate_hash', 'candidate_count', 'candidate_bytes', 'candidate_expires_at'];
  const planningRule = defs.PruneRunResource.allOf[0];
  assert.equal(planningRule.if.properties.status.const, 'planning');
  for (const field of candidateFields) {
    assert.equal(planningRule.then.properties[field].type, 'null', `${field} must be unavailable while planning`);
    assert.notEqual(planningRule.else.properties[field].type, 'null', `${field} must be present after planning`);
  }
});

test('D-owned activity routes use typed task, operation, event, log, prune and promotion lists', () => {
  const expected = new Map([
    ['listSystemBackups', 'TaskList'],
    ['listSystemBackupArtifactVerifications', 'TaskList'],
    ['listSystemRestoreDrills', 'TaskList'],
    ['listSystemBackupPreflights', 'TaskList'],
    ['listSystemBackupEvents', 'EventList'],
    ['listSystemBackupArtifactVerificationEvents', 'EventList'],
    ['listSystemRestoreDrillEvents', 'EventList'],
    ['listSystemBackupPreflightEvents', 'EventList'],
    ['listSystemBackupPruneEvents', 'EventList'],
    ['listSystemBackupLogs', 'LogList'],
    ['listSystemBackupArtifactVerificationLogs', 'LogList'],
    ['listSystemRestoreDrillLogs', 'LogList'],
    ['listSystemBackupPreflightLogs', 'LogList'],
    ['listSystemBackupPruneItems', 'PruneItemList'],
    ['listSystemBackupOperations', 'OperationList'],
    ['listSystemBackupPromotions', 'PromotionList'],
  ]);
  const remainingGenericLists = [];
  for (const item of Object.values(openapi.paths)) {
    const operation = item.get;
    if (!operation) continue;
    const success = operation.responses['200'];
    if (expected.has(operation.operationId)) {
      assert.deepEqual(success, { $ref: `#/components/responses/${expected.get(operation.operationId)}` });
    } else if (success.$ref === '#/components/responses/List') {
      remainingGenericLists.push(operation.operationId);
    }
  }
  assert.deepEqual(remainingGenericLists.sort(), [
    'listSystemBackupCatalogImports',
    'listSystemBackupCatalogRecords',
    'listSystemBackupCatalogScans',
    'listSystemBackupStagingResources',
    'listSystemRestoreDrillResources',
  ]);
  const responseRefs = {
    TaskList: 'task-operation.schema.json#/$defs/TaskList',
    OperationList: 'task-operation.schema.json#/$defs/OperationList',
    EventList: 'admin-activity-resources.schema.json#/$defs/EventResourceList',
    LogList: 'admin-activity-resources.schema.json#/$defs/LogEntryResourceList',
    PruneItemList: 'admin-activity-resources.schema.json#/$defs/PruneItemResourceList',
    PromotionList: 'admin-activity-resources.schema.json#/$defs/PromotionResourceList',
  };
  for (const [name, ref] of Object.entries(responseRefs)) assert.deepEqual(openapi.components.responses[name].content['application/json'].schema, { $ref: ref });
});

test('D-owned event and log envelopes are bounded, redacted and non-authoritative', () => {
  const defs = adminActivityResourcesSchema.$defs;
  assert.deepEqual(defs.CoreEventType.enum, [
    'task_status_changed', 'attempt_started', 'attempt_finished', 'gate_changed', 'participant_changed',
    'artifact_committed', 'artifact_health_changed', 'external_action_changed', 'evidence_changed',
    'log_persistence_changed', 'provider_capability_changed', 'dependency_health_changed', 'catalog_scan_changed',
    'catalog_record_changed', 'cleanup_changed', 'ownership_resolved', 'prune_changed', 'promotion_changed',
    'operation_finished',
  ]);
  assert.equal(defs.EventDetails.additionalProperties, false);
  assert.equal(defs.EventDetails['x-max-jcs-utf8-bytes'], 65536);
  assert.equal(defs.EventResource.properties.message.maxLength, 2048);
  assert.equal(defs.LogEntryResource.properties.message.maxLength, 8192);
  assert.equal(defs.LogEntryResourceList.properties.items.maxItems, 1000);
  assert.equal(defs.EventResource.allOf.length, 11);
  assert.equal(defs.LogEntryResource.allOf.length, 4);
  assert.match(defs.EventResource['x-invariant'], /never become a second authority/);
  assert.match(defs.LogEntryResource['x-invariant'], /already-redacted persisted log lines/);
  assert.deepEqual(Object.keys(adminActivityExamples.event_resource).sort(), Object.keys(defs.EventResource.properties).sort());
  assert.deepEqual(Object.keys(adminActivityExamples.event_resource.details).sort(), Object.keys(defs.EventDetails.properties).sort());
  assert.deepEqual(Object.keys(adminActivityExamples.log_entry_resource).sort(), Object.keys(defs.LogEntryResource.properties).sort());
  const serialized = JSON.stringify(adminActivityExamples);
  assert.doesNotMatch(serialized, /:\/\//);
  assert.doesNotMatch(serialized, /"(?:password|secret|token|credential|private_key|authorization|uri|location)"\s*:/i);
});

test('D-owned prune item and promotion views preserve lifecycle and derived-health boundaries', () => {
  const defs = adminActivityResourcesSchema.$defs;
  assert.deepEqual(defs.PruneItemResource.properties.status.enum, ['planned', 'blocked_by_delete', 'deleting', 'deleted', 'delete_failed']);
  assert.deepEqual(defs.PruneItemResource['x-state-transitions'], ['planned->deleting', 'blocked_by_delete->planned', 'deleting->deleted|delete_failed', 'delete_failed->deleting']);
  assert.deepEqual(defs.PruneItemResource.properties.item_failure_code.enum, ['none', 'deadline_exceeded', 'provider_unavailable', 'permission_denied', 'identity_mismatch', 'checksum_mismatch', 'catalog_conflict', 'internal']);
  assert.equal(defs.PruneItemResource.allOf.length, 4);
  assert.deepEqual(adminApiCommonSchema.$defs.PruneItemPublicId, { type: 'string', pattern: '^spi_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' });
  for (const item of adminActivityExamples.prune_item_resources) assert.deepEqual(Object.keys(item).sort(), Object.keys(defs.PruneItemResource.properties).sort());
  const [objectItem, catalogItem] = adminActivityExamples.prune_item_resources;
  assert.notEqual(objectItem.locator_hash, null);
  assert.notEqual(objectItem.immutable_version, null);
  assert.equal(objectItem.catalog_record_hash, null);
  assert.equal(catalogItem.locator_hash, null);
  assert.equal(catalogItem.immutable_version, null);
  assert.notEqual(catalogItem.catalog_record_hash, null);

  const promotion = adminActivityExamples.promotion_resource;
  assert.deepEqual(Object.keys(promotion).sort(), Object.keys(defs.PromotionResource.properties).sort());
  assert.deepEqual(Object.keys(promotion.health).sort(), Object.keys(defs.PromotionHealth.properties).sort());
  const dependencyStates = ['artifact', 'artifact_access', 'kek', 'signature', 'catalog', 'evidence', 'attestation'].map((key) => promotion.health[key]);
  const derived = dependencyStates.every((state) => state === 'healthy') ? 'healthy' : dependencyStates.some((state) => state === 'degraded' || state === 'stale') ? 'degraded' : 'unknown';
  assert.equal(promotion.health.current_health, derived);
  assert.equal(defs.PromotionHealth.allOf.length, 3);
  assert.equal(defs.PromotionResource.allOf.length, 3);
  assert.match(defs.PromotionResource['x-invariant'], /derived at read time/);
});

test('redacted examples are closed against DTO fields and contain no credential material', () => {
  assert.deepEqual(Object.keys(examples.examples.task).sort(), Object.keys(taskSchema.$defs.Task.properties).sort());
  assert.deepEqual(Object.keys(examples.examples.operation).sort(), Object.keys(taskSchema.$defs.Operation.properties).sort());
  const serialized = JSON.stringify(examples);
  assert.doesNotMatch(serialized, /:\/\/[^/"\\s]+@/);
  assert.doesNotMatch(serialized, /"(?:password|secret|access_token|refresh_token|authorization)"\s*:/i);
  const requestExamples = examples.examples.mutation_requests;
  assert.deepEqual(Object.keys(requestExamples).sort(), Object.keys(adminMutationRequestsSchema.$defs).sort());
  for (const [typeName, example] of Object.entries(requestExamples)) {
    assert.deepEqual(Object.keys(example).sort(), Object.keys(adminMutationRequestsSchema.$defs[typeName].properties).sort(), `${typeName} fixture is not closed`);
  }
  assert.doesNotMatch(JSON.stringify(requestExamples), /"(?:strong_auth_proof|uri|location|credential|force|observed_state|free_text_result)"\s*:/i);
});

test('module interfaces keep ownership boundaries and source-writer state is closed', () => {
  assert.deepEqual(interfaces['x-interfaces'].map((item) => item.name).sort(), ['BackupArtifactStore', 'Collector', 'Normalizer', 'Runner', 'Verifier']);
  assert.ok(interfaces['x-interfaces'].every((item) => item.authority.length > 20));
  assert.equal(sourceWriter.additionalProperties, false);
  assert.deepEqual(sourceWriter.properties.check_state.enum, ['clean', 'drift', 'unknown']);
  assert.equal(sourceWriter.allOf.length, 3);
});

test('D-owned controller claim primitive is DB-time CAS only and has no owner execution dependency', () => {
  const source = readFileSync(join(root, 'backend/internal/systembackupcontroller/claim.go'), 'utf8');
  const coordinator = readFileSync(join(root, 'backend/internal/systembackupcontroller/claim_coordinator.go'), 'utf8');
  const importBlock = source.match(/import \(([\s\S]*?)\n\)/);
  assert.ok(importBlock, 'claim primitive import block must be present');
  const imports = [...importBlock[1].matchAll(/"([^"]+)"/g)].map((item) => item[1]).sort();
  assert.deepEqual(imports, ['context', 'database/sql', 'errors', 'fmt', 'regexp', 'strings', 'time']);

  for (const required of [
    'func AcquireClaimInInstallation(',
    'func RenewClaimInInstallation(',
    'func ReleaseClaimInInstallation(',
    'UTC_TIMESTAMP(6)',
    'row_version = row_version + 1',
    'public_id = ? AND row_version = ?',
    'next_reconcile_at IS NULL OR next_reconcile_at <= UTC_TIMESTAMP(6)',
    'ErrClaimNotAcquired',
    'ErrClaimLost',
    'if err := ctx.Err(); err != nil',
  ]) assert.match(source, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  assert.doesNotMatch(source, /"(?:net\/http|k8s\.io\/|github\.com\/minio|github\.com\/go-sql-driver|github\.com\/upper)\b/);
  assert.doesNotMatch(source, /\b(?:INSERT INTO|DELETE FROM|CREATE JOB|provider_payload|credential_value|check_registry_json)\b/i);
  for (const required of [
    'type ClaimCoordinator struct',
    'func (c ClaimCoordinator) Acquire(',
    'func (c ClaimCoordinator) Renew(',
    'func (c ClaimCoordinator) Release(',
    'installationIDPattern.MatchString(c.InstallationID)',
    'AcquireClaimInInstallation(ctx, c.Executor, c.InstallationID, target, owner, expectedRowVersion, policy)',
    'RenewClaimInInstallation(ctx, c.Executor, c.InstallationID, token, policy)',
    'ReleaseClaimInInstallation(ctx, c.Executor, c.InstallationID, token, retryAfter)',
  ]) assert.match(coordinator, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.doesNotMatch(coordinator, /\b(?:Runner|JobObserver|provider|catalog|status\s*=|INSERT INTO|DELETE FROM)\b/i);
});

test('D-owned pending deadline transition is transactional, evidence-guarded and task-only', () => {
  const source = readFileSync(join(root, 'backend/internal/systembackupcontroller/deadline.go'), 'utf8');
  for (const required of [
    'type Transaction interface',
    'Commit() error',
    'Rollback() error',
    'func ExpirePendingClaim(',
    "status = 'failed'",
    "failure_category = 'deadline_exceeded'",
    'deadline_at <= UTC_TIMESTAMP(6)',
    'NOT EXISTS (SELECT 1 FROM system_backup_attempts',
    'NOT EXISTS (SELECT 1 FROM system_backup_external_actions',
    'NOT EXISTS (SELECT 1 FROM system_artifact_leases',
    'INSERT INTO system_backup_events',
    'INSERT INTO system_backup_alert_states',
    'origin_installation_id = ? AND public_id = ?',
    "task_purpose = 'acceptance'",
    'ON DUPLICATE KEY UPDATE',
    'consecutive_anomaly_count = LEAST(consecutive_anomaly_count + 1, 4294967295)',
    "'pending', 'failed', 'deadline_exceeded'",
    'if err := tx.Commit(); err != nil',
  ]) assert.match(source, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  assert.doesNotMatch(source, /case TargetOperation:/);
  assert.doesNotMatch(source, /\b(?:provider_payload|credential_value|check_registry_json|CREATE JOB|DELETE FROM)\b/i);
  const grants = readFileSync(join(root, 'backend/internal/systembackupcontroller/database_grants.go'), 'utf8');
  assert.match(grants, /"system_backup_alert_states":\s*\{"SELECT", "INSERT", "UPDATE"\}/);
});

test('D-owned pending deadline sweep is bounded, fair and has no runner surface', () => {
  const sweeper = readFileSync(join(root, 'backend/internal/systembackupcontroller/deadline_sweeper.go'), 'utf8');
  const sqlStore = readFileSync(join(root, 'backend/internal/systembackupcontroller/sql_deadline_store.go'), 'utf8');

  for (const required of [
    'const MaxDeadlineSweepBatch = 100',
    'TargetBackup,',
    'TargetDrill,',
    'TargetPreflight,',
    'TargetArtifactVerify,',
    'roundRobinDeadlineCandidates(queues, s.Limit)',
    'errors.Is(err, ErrClaimNotAcquired)',
    'errors.Is(err, ErrDeadlineTransitionRejected)',
    's.Store.Release(ctx, s.InstallationID, token, s.Policy)',
    'installationIDPattern.MatchString(s.InstallationID)',
    'Leave an errored claim in place',
    'if err := ctx.Err(); err != nil',
  ]) assert.match(sweeper, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  for (const required of [
    'ClaimCoordinator{Executor: s.DB, InstallationID: installationID}).Acquire(',
    'ClaimCoordinator{Executor: s.DB, InstallationID: installationID}).Release(',
    'ExpirePendingClaim(ctx, tx, installationID, token)',
    'func expiredPendingCandidateSQL(kind TargetKind)',
    'WHERE origin_installation_id = ? AND status = \'pending\'',
    "status = 'pending'",
    'deadline_at <= UTC_TIMESTAMP(6)',
    'next_reconcile_at IS NULL OR next_reconcile_at <= UTC_TIMESTAMP(6)',
    'NOT EXISTS (SELECT 1 FROM system_backup_attempts',
    'NOT EXISTS (SELECT 1 FROM system_backup_external_actions',
    'NOT EXISTS (SELECT 1 FROM system_artifact_leases',
    'ORDER BY deadline_at, id LIMIT ?',
    'kind == TargetOperation',
  ]) assert.match(sqlStore, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  assert.doesNotMatch(`${sweeper}\n${sqlStore}`, /"(?:net\/http|k8s\.io\/|github\.com\/minio|github\.com\/go-sql-driver|github\.com\/upper)\b/);
  assert.doesNotMatch(`${sweeper}\n${sqlStore}`, /\b(?:CREATE JOB|provider_payload|credential_value|check_registry_json|Runner|JobObserver)\b/);
  assert.doesNotMatch(sqlStore, /\b(?:UPDATE|INSERT|DELETE)\s+/i);
});

test('D-owned gate and mutation lease core preserves row-lock order and explicit participant proof', () => {
  const gate = readFileSync(join(root, 'backend/internal/systembackupcontroller/gate.go'), 'utf8');
  const mutation = readFileSync(join(root, 'backend/internal/systembackupcontroller/mutation_lease.go'), 'utf8');
  const protectedMutation = readFileSync(join(root, 'backend/internal/systembackupcontroller/protected_mutation.go'), 'utf8');
  const mutationCoordinator = readFileSync(join(root, 'backend/internal/systembackupcontroller/mutation_lease_coordinator.go'), 'utf8');
  const gateCoordinator = readFileSync(join(root, 'backend/internal/systembackupcontroller/gate_coordinator.go'), 'utf8');
  const gateEvent = readFileSync(join(root, 'backend/internal/systembackupcontroller/gate_event.go'), 'utf8');
  const migrationCoord = readFileSync(join(root, 'backend/internal/migrationcoord/lock.go'), 'utf8');
  const migrationRunner = readFileSync(join(root, 'backend/internal/db/migrations.go'), 'utf8');
  const migration = readFileSync(join(root, 'backend/internal/db/migrations/068_add_system_backup_coordination_observability.sql'), 'utf8');

  for (const required of [
    'type CoordinationTransaction interface',
    'LockGate(context.Context, GateKey)',
    'LockMutationLease(context.Context, string)',
    'CountOutstandingMutationLeases(context.Context, GateKey, uint64)',
    'FOR UPDATE',
    'gate_state = \'acquiring\'',
    'generation = generation + 1',
    'GateHoldReadinessVerifier',
    'VerifyParticipantsPaused(context.Context, CoordinationTransaction, GateKey, uint64)',
    'GateRecoveryReadinessVerifier',
    'VerifyParticipantsRunning(context.Context, CoordinationTransaction, GateKey, uint64)',
    'ErrGateHoldNotReady',
    'ErrGateRecoveryNotReady',
    'fencing_token = fencing_token + 1',
    'absolute_hold_deadline_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND)',
    'fencing_token = ?',
    'func RecoverGateRelease(',
    'func RecoverGateIdle(',
    "gate_state = 'releasing'",
    'release_started_at = COALESCE(release_started_at, UTC_TIMESTAMP(6))',
    'lease_expires_at <= UTC_TIMESTAMP(6) OR absolute_hold_deadline_at <= UTC_TIMESTAMP(6)',
    'lease_expires_at <= UTC_TIMESTAMP(6) OR acquisition_deadline_at <= UTC_TIMESTAMP(6)',
  ]) assert.match(gate, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  for (const required of [
    'func AcquireMutationLease(',
    'tx.LockGate(ctx, request.Key)',
    'gate.State != GateIdle',
    'INSERT INTO system_maintenance_mutation_leases',
    'func ValidateMutationLeaseForCommit(',
    'tx.LockGate(ctx, token.Key)',
    'tx.LockMutationLease(ctx, token.LeaseID)',
    'expires_at > UTC_TIMESTAMP(6)',
    'DELETE FROM system_maintenance_mutation_leases',
    'expiry alone never deletes the blocker row',
  ]) assert.match(mutation, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  for (const required of [
    'type CoordinationTransactionFactory interface',
    'type SQLCoordinationTransactionFactory struct',
    'BeginCoordination(context.Context)',
    'func ExecuteProtectedMutation(',
    'ValidateMutationLeaseForCommit(ctx, tx, token)',
    'mutate(ctx, tx)',
    'tx.Commit()',
    'withCoordinationRollback(tx, &committed)',
  ]) assert.match(protectedMutation, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  for (const required of [
    'type MutationLeaseCoordinator struct',
    'Factory CoordinationTransactionFactory',
    'func (c MutationLeaseCoordinator) Acquire(',
    'func (c MutationLeaseCoordinator) Renew(',
    'func (c MutationLeaseCoordinator) Release(',
    'AcquireMutationLease(ctx, tx, request, policy)',
    'RenewMutationLease(ctx, tx, token, policy)',
    'ReleaseMutationLease(ctx, tx, token)',
  ]) assert.match(mutationCoordinator, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  for (const required of [
    'type GateCoordinator struct',
    'Factory            CoordinationTransactionFactory',
    'MigrationExclusion migrationcoord.Locker',
    'HoldReadiness      GateHoldReadinessVerifier',
    'RecoveryReadiness  GateRecoveryReadinessVerifier',
    'func NewSQLGateCoordinator(',
    'func (c GateCoordinator) BeginAcquisition(',
    'c.MigrationExclusion.Acquire(ctx)',
    'guard.Release(releaseCtx)',
    'func (c GateCoordinator) AdvanceHeld(',
    'func (c GateCoordinator) Renew(',
    'func (c GateCoordinator) AbortAcquisition(',
    'func (c GateCoordinator) BeginRelease(',
    'func (c GateCoordinator) FinishRelease(',
    'func (c GateCoordinator) RecoverAcquiring(',
    'func (c GateCoordinator) RecoverRelease(',
    'AdvanceGateHeld(ctx, tx, token, policy, c.HoldReadiness)',
    'RecoverGateIdle(ctx, tx, key, expectedRowVersion, c.RecoveryReadiness)',
  ]) assert.match(gateCoordinator, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  for (const required of [
    'const LockName = "clawmanager:system-backup:migration-capture:v1"',
    'SELECT GET_LOCK(?, ?)',
    'SELECT RELEASE_LOCK(?)',
    'type SQLLock struct',
    'conn     *sql.Conn',
  ]) assert.match(migrationCoord, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  for (const required of [
    'AcquireSQL(ctx)',
    'assertCaptureGateIdle(ctx, guard)',
    "gate_state <> 'idle'",
    'guard.ExecContext(ctx, statement)',
    'guard.Release(releaseCtx)',
  ]) assert.match(migrationRunner, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  for (const required of [
    'func insertGateTransitionEvent(',
    'INSERT INTO system_backup_events',
    "'system'",
    "'gate_changed'",
    'detail_previous_status',
    'detail_current_status',
    'detail_reason',
    'maintenance gate transition did not produce exactly one event',
  ]) assert.match(gateEvent, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  for (const required of [
    'insertGateTransitionEvent(ctx, tx, key, GateIdle, GateAcquiring',
    'insertGateTransitionEvent(ctx, tx, token.Key, GateAcquiring, GateHeld',
    'insertGateTransitionEvent(ctx, tx, key, GateAcquiring, GateIdle',
    'insertGateTransitionEvent(ctx, tx, key, snapshot.State, GateReleasing',
  ]) assert.match(gate, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  for (const required of [
    'insertGateTransitionEvent(ctx, tx, token.Key, GateAcquiring, GateIdle',
    'insertGateTransitionEvent(ctx, tx, token.Key, GateHeld, GateReleasing',
    'insertGateTransitionEvent(ctx, tx, token.Key, GateReleasing, GateIdle',
  ]) assert.match(gateCoordinator, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  assert.doesNotMatch(`${gate}\n${mutation}\n${protectedMutation}\n${mutationCoordinator}\n${gateCoordinator}\n${gateEvent}`, /"(?:net\/http|k8s\.io\/|github\.com\/minio|github\.com\/go-sql-driver|github\.com\/upper)\b/);
  assert.doesNotMatch(`${gate}\n${mutation}\n${protectedMutation}\n${mutationCoordinator}\n${gateCoordinator}\n${gateEvent}`, /\b(?:CREATE JOB|provider_payload|credential_value|check_registry_json|JobObserver)\b/);
  assert.doesNotMatch(protectedMutation, /\b(?:VerifyParticipantsPaused|VerifyParticipantsRunning|Runner|provider|catalog)\b/i);
  assert.doesNotMatch(mutationCoordinator, /\b(?:GateHoldReadinessVerifier|GateRecoveryReadinessVerifier|Runner|provider|catalog)\b/i);
  assert.doesNotMatch(gateCoordinator, /\b(?:Runner|JobObserver|provider|catalog|PauseParticipants|ResumeParticipants)\b/i);
  assert.match(migration, /gate_state = 'releasing'[\s\S]*absolute_hold_deadline_at > held_at/);
  assert.doesNotMatch(migration, /gate_state = 'releasing'[\s\S]{0,1000}absolute_hold_deadline_at > heartbeat_at/);
});

test('D-owned controller skeleton is feature-gated and uses a lease-only ServiceAccount', () => {
  const command = readFileSync(join(root, 'backend/cmd/system-backup-controller/main.go'), 'utf8');
  const loop = readFileSync(join(root, 'backend/internal/systembackupcontroller/deadline_loop.go'), 'utf8');
  const controlLoop = readFileSync(join(root, 'backend/internal/systembackupcontroller/control_loop.go'), 'utf8');
  const gateRecovery = readFileSync(join(root, 'backend/internal/systembackupcontroller/gate_recovery.go'), 'utf8');
  const sqlGateRecovery = readFileSync(join(root, 'backend/internal/systembackupcontroller/sql_gate_recovery_store.go'), 'utf8');
  const gateInitializer = readFileSync(join(root, 'backend/internal/systembackupcontroller/gate_initializer.go'), 'utf8');
  const readiness = readFileSync(join(root, 'backend/internal/systembackupcontroller/readiness.go'), 'utf8');
  const killSwitch = readFileSync(join(root, 'backend/internal/systembackupcontroller/kill_switch.go'), 'utf8');
  const sqlKillSwitch = readFileSync(join(root, 'backend/internal/systembackupcontroller/sql_kill_switch_store.go'), 'utf8');
  const bootstrap = readFileSync(join(root, 'backend/internal/systembackupcontroller/bootstrap.go'), 'utf8');
  const supervisor = readFileSync(join(root, 'backend/internal/systembackupcontroller/bootstrap_supervisor.go'), 'utf8');
  const migrationCatalog = readFileSync(join(root, 'backend/internal/migrationcatalog/catalog.go'), 'utf8');
  const database = readFileSync(join(root, 'backend/internal/db/db.go'), 'utf8');
  const deployment = readFileSync(join(root, 'deployments/k8s/system-backup-controller.yaml'), 'utf8');
  const dockerfile = readFileSync(join(root, 'Dockerfile'), 'utf8');
  const registry = parseJSON(join(root, 'contracts/system-backup/v12/schema-registry.json'));

  for (const required of [
    'envBool("SYSTEM_BACKUP_CONTROLLER_ENABLED", false)',
    'disabled by feature gate',
    'systembackupcontroller.ValidateControllerDatabaseCredentials(os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), cfg.Database.User)',
    'db.ConnectSystemBackupController(cfg.Database)',
    'session.Driver().(*stdsql.DB)',
    'db.EmbeddedMigrationCatalog()',
    'SYSTEM_BACKUP_ORIGIN_INSTALLATION_ID',
    'envBool("SYSTEM_BACKUP_ENABLED", false)',
    'envBool("SYSTEM_BACKUP_REQUIRED", false)',
    'systembackupcontroller.BootstrapSupervisor{',
    'systembackupcontroller.SQLBootstrapChecker{DB: sqlDB}',
    'systembackupcontroller.SQLInstallationStateReconciler{DB: sqlDB}',
    'systembackupcontroller.SQLGateInitializer{DB: sqlDB}',
    'policy := snapshot.Policy',
    'Policy:           snapshot.GatePolicy',
    'supervisor.Run(rootCtx)',
    'systembackupcontroller.SQLGateRecoveryStore{DB: sqlDB}',
    'systembackupcontroller.GateRecoveryReconciler{',
    'systembackupcontroller.SQLKillSwitchStore{DB: sqlDB}',
    'systembackupcontroller.KillSwitchReconciler{',
    'systembackupcontroller.SQLDeadlineStore',
    'InstallationID: snapshot.InstallationID',
    'systembackupcontroller.SQLUTCReadinessProbe{DB: sqlDB}',
    'systembackupcontroller.SQLControllerGrantProbe{DB: sqlDB, Schema: cfg.Database.Database, User: cfg.Database.User}',
    'grantErr := grantProbe.Check(grantCtx)',
    'Guard: systembackupcontroller.ReadinessProbeSet{',
    'systembackupcontroller.SQLClaimReadinessProbe{DB: sqlDB}',
    'systembackupcontroller.SQLDeadlineAlertReadinessProbe{DB: sqlDB}',
    'kubernetesControllerReadinessProbe{',
    'ServerResourcesForGroupVersion("coordination.k8s.io/v1")',
    'SelfSubjectAccessReviews().Create(',
    'go runDependencyProbe(rootCtx, status, dependencyProbe)',
    'admissionErr := dependencyProbe.Check(admissionCtx)',
    'systembackupcontroller.ControlLoop',
    'leader.Run(',
    'defaultLeaderLease        = "clawmanager-system-backup-controller"',
    'OnStartedLeading:',
    'OnStoppedLeading:',
    'PingContext',
    '"/healthz"',
    '"/readyz"',
  ]) assert.match(command, new RegExp(required.replace(/[.*+?^{}()|[\]\\$]/g, '\\$&')));
  assert.doesNotMatch(command, /db\.Initialize\(|\b(?:Runner|JobObserver|provider_payload|credential_value|catalog append)\b/);
  assert.doesNotMatch(command, /envDuration\("SYSTEM_BACKUP_CONTROLLER_(?:CLAIM_TTL|CLAIM_HEARTBEAT|RECONCILE_INTERVAL)"/);
  assert.ok(command.indexOf('ValidateControllerDatabaseCredentials(') < command.indexOf('db.ConnectSystemBackupController(cfg.Database)'), 'explicit dedicated credentials must be checked before connecting');
  assert.match(database, /func ConnectSystemBackupController\(cfg config\.DatabaseConfig\)/);
  assert.match(database, /"time_zone": "'\+00:00'"/);
  assert.match(database, /"loc":\s+"UTC"/);
  assert.match(deployment, /name: DB_USER\s+value: "sbk_controller"/);
  assert.match(deployment, /name: DB_PASSWORD\s+valueFrom:\s+secretKeyRef:\s+name: clawmanager-system-backup-controller-db\s+key: password\s+optional: true/);
  assert.ok(command.indexOf('grantErr := grantProbe.Check(grantCtx)') < command.indexOf('leader.Run('), 'grant admission must precede leader mutations');
  assert.ok(command.indexOf('admissionErr := dependencyProbe.Check(admissionCtx)') < command.indexOf('leader.Run('), 'all dependency admission must precede leader mutations');
  const controlLoopGuard = command.slice(command.indexOf('Guard: systembackupcontroller.ReadinessProbeSet{'), command.indexOf('GateRecovery: gateRecovery,'));
  assert.match(controlLoopGuard, /grantProbe/);
  assert.match(controlLoopGuard, /SQLUTCReadinessProbe\{DB: sqlDB\}/);

  for (const required of [
    'type SQLUTCReadinessProbe struct',
    'TIMESTAMPDIFF(MICROSECOND, UTC_TIMESTAMP(6), CURRENT_TIMESTAMP(6))',
    'type SQLClaimReadinessProbe struct',
    'func (p SQLClaimReadinessProbe) Check(',
    'TargetBackup, TargetDrill, TargetPreflight, TargetArtifactVerify, TargetOperation',
    'row_version = row_version WHERE 1 = 0',
    'type SQLDeadlineAlertReadinessProbe struct',
    'func (p SQLDeadlineAlertReadinessProbe) Check(',
    'acceptanceAnomalyStateKey, "installation_readiness_probe", "__readiness_probe__", uint64(0), false',
    'type ReadinessProbeSet []ReadinessProbe',
  ]) assert.match(readiness, new RegExp(required.replace(/[.*+?^{}()|[\]\\$]/g, '\\$&')));
  const claimReadinessSource = readiness.slice(readiness.indexOf('type SQLClaimReadinessProbe struct'), readiness.indexOf('// SQLDeadlineAlertReadinessProbe'));
  assert.doesNotMatch(claimReadinessSource, /UTC_TIMESTAMP|row_version \+|\b(?:INSERT|DELETE)\b/);
  assert.ok(command.indexOf('OnStartedLeading:') < command.indexOf('stateReconciler.Reconcile('), 'installation state mutation must run only after leadership starts');
  assert.ok(command.indexOf('stateReconciler.Reconcile(') < command.indexOf('gateInitializer.Ensure('), 'capture gate initialization must follow leader-owned installation-state reconciliation');
  assert.ok(command.indexOf('gateInitializer.Ensure(') < command.indexOf('status.leading.Store(true)'), 'controller must not report leading before its capture gate exists');

  for (const required of [
    'const CaptureGateScope = "system-backup:capture"',
    'type SQLGateInitializer struct',
    'func (i SQLGateInitializer) Ensure(',
    'INSERT INTO system_maintenance_locks',
    'ON DUPLICATE KEY UPDATE id = id',
    'gateSeconds(policy.LockTTL)',
  ]) assert.match(gateInitializer, new RegExp(required.replace(/[.*+?^{}()|[\]\\$]/g, '\\$&')));
  assert.doesNotMatch(gateInitializer, /gate_state\s*=|generation\s*=|fencing_token\s*=|lock_owner\s*=|heartbeat_at\s*=|lease_expires_at\s*=|row_version\s*=/);

  for (const required of [
    'type DeadlineLoop struct',
    'func (l DeadlineLoop) Run(ctx context.Context) error',
    'if err := ctx.Err(); err != nil',
    'time.NewTicker(l.Interval)',
    'l.Sweeper.RunOnce(ctx)',
  ]) assert.match(loop, new RegExp(required.replace(/[.*+?^{}()|[\]\\$]/g, '\\$&')));
  for (const required of [
    'type ControlLoop struct',
    'func (l ControlLoop) Run(ctx context.Context) error',
    'l.GateRecovery.RunOnce(ctx)',
    'l.KillSwitch.RunOnce(ctx)',
    'l.Deadline.RunOnce(ctx)',
    'type KillSwitchReconciler struct',
    'func (r KillSwitchReconciler) RunOnce(ctx context.Context)',
    'PendingGlobalCaptureQueue',
    'PendingKillSwitch',
    'roundRobinKillSwitchCandidates',
  ]) assert.match(`${controlLoop}\n${killSwitch}`, new RegExp(required.replace(/[.*+?^{}()|[\]\\$]/g, '\\$&')));
  assert.ok(controlLoop.indexOf('l.GateRecovery.RunOnce(ctx)') < controlLoop.indexOf('l.KillSwitch.RunOnce(ctx)'), 'expired gate fencing must run before task reconciliation');
  assert.ok(controlLoop.indexOf('l.KillSwitch.RunOnce(ctx)') < controlLoop.indexOf('l.Deadline.RunOnce(ctx)'), 'kill-switch projection must run before deadline reconciliation');
  for (const required of [
    'type GateRecoveryReconciler struct',
    'RunningReadiness GateRecoveryReadinessVerifier',
    'ParticipantProofBlock',
    'if r.RunningReadiness == nil',
    'r.Store.FenceForRelease(',
    'token.State != GateReleasing',
    'type SQLGateRecoveryStore struct',
    "gate_state = 'acquiring' AND (lease_expires_at <= UTC_TIMESTAMP(6) OR acquisition_deadline_at <= UTC_TIMESTAMP(6))",
    "gate_state = 'held' AND (lease_expires_at <= UTC_TIMESTAMP(6) OR absolute_hold_deadline_at <= UTC_TIMESTAMP(6))",
    "gate_state = 'releasing' AND lease_expires_at <= UTC_TIMESTAMP(6)",
    'return coordinator.RecoverAcquiring(',
    'return coordinator.RecoverRelease(',
  ]) assert.match(`${gateRecovery}\n${sqlGateRecovery}`, new RegExp(required.replace(/[.*+?^{}()|[\]\\$]/g, '\\$&')));
  assert.doesNotMatch(`${gateRecovery}\n${sqlGateRecovery}`, /FinishGateRelease|VerifyParticipantsPaused|CREATE JOB|provider_payload|credential_value|catalog append/);
  for (const required of [
    "status = 'pending'",
    "pending_reason <> 'kill_switch'",
    "pending_reason = 'kill_switch'",
    'SET pending_reason = ?, row_version = row_version + 1',
    'origin_installation_id = ?',
    'public_id = ?',
    'row_version = ?',
    'ORDER BY id LIMIT ?',
  ]) assert.match(sqlKillSwitch, new RegExp(required.replace(/[.*+?^{}()|[\]\\$]/g, '\\$&')));
  const transitionUpdate = sqlKillSwitch.match(/"UPDATE %s SET pending_reason[^\n]+/);
  assert.ok(transitionUpdate, 'kill-switch store must use one row-version CAS update');
  assert.doesNotMatch(transitionUpdate[0], /deadline_at|created_at|idempotency_key|request_hash|next_reconcile_at|started_at|finished_at/);
  assert.doesNotMatch(`${killSwitch}\n${sqlKillSwitch}\n${controlLoop}`, /\b(?:JobObserver|provider_payload|credential_value|catalog append)\b/);

  for (const required of [
    'ContractMigrationCatalogHash',
    'ContractMigrationCatalogFileCount',
    'SELECT filename FROM schema_migrations ORDER BY filename',
    'FROM system_backup_installation_state AS installation',
    'LEFT JOIN system_backup_configs AS active_config',
    'active_config.controller_claim_ttl_seconds',
    'active_config.controller_claim_heartbeat_seconds',
    'active_config.controller_reconcile_interval_seconds',
    'active_config.mutation_lease_ttl_seconds',
    'active_config.mutation_lease_heartbeat_seconds',
    'active_config.gate_acquisition_timeout_seconds',
    'active_config.quiesce_max_hold_seconds',
    'active_config.maintenance_lock_ttl_seconds',
    'installation.first_enabled_at IS NOT NULL',
    'first_enabled_at = CASE WHEN ? THEN COALESCE(first_enabled_at, UTC_TIMESTAMP(6)) ELSE first_enabled_at END',
    'last_effective_enabled_transition_at = CASE WHEN last_effective_enabled <> ? THEN UTC_TIMESTAMP(6) ELSE last_effective_enabled_transition_at END',
    'AND row_version = ?',
    'func WaitForBootstrap(',
  ]) assert.match(bootstrap, new RegExp(required.replace(/[.*+?^{}()|[\]\\$]/g, '\\$&')));
  const checkerSource = bootstrap.slice(bootstrap.indexOf('func (c SQLBootstrapChecker) Check('), bootstrap.indexOf('type SQLInstallationStateReconciler struct'));
  assert.doesNotMatch(checkerSource, /UPDATE system_backup_installation_state/);
  const catalogHash = bootstrap.match(/ContractMigrationCatalogHash\s+=\s+"([0-9a-f]{64})"/);
  assert.ok(catalogHash, 'controller bootstrap must freeze one migration catalog hash');
  assert.equal(catalogHash[1], registry.migration_catalog.hash);
  const catalogFileCount = bootstrap.match(/ContractMigrationCatalogFileCount\s+=\s+(\d+)/);
  assert.ok(catalogFileCount, 'controller bootstrap must freeze one migration catalog file count');
  assert.equal(Number(catalogFileCount[1]), registry.migration_catalog.file_count);
  assert.match(migrationCatalog, /system-backup-migration-catalog\.v1\\x00/);
  assert.match(migrationCatalog, /binary\.BigEndian\.PutUint64/);
  assert.match(migrationCatalog, /strings\.ReplaceAll\(strings\.ReplaceAll/);
  for (const required of [
    'type BootstrapSupervisor struct',
    'func (s BootstrapSupervisor) Run(ctx context.Context) error',
    'BootstrapRuntimeRestarting',
    's.stop(ctx, active)',
    'sameBootstrapRuntime(active.snapshot, snapshot)',
  ]) assert.match(`${bootstrap}\n${supervisor}`, new RegExp(required.replace(/[.*+?^{}()|[\]\\$]/g, '\\$&')));

  for (const required of [
    'kind: ServiceAccount',
    'name: clawmanager-system-backup-controller',
    'kind: Role',
    'resources: ["leases"]',
    'resourceNames: ["clawmanager-system-backup-controller"]',
    'kind: Deployment',
    'replicas: 2',
    'command: ["/usr/local/bin/clawreef-system-backup-controller"]',
    'name: SYSTEM_BACKUP_CONTROLLER_ENABLED',
    'value: "false"',
    'name: SYSTEM_BACKUP_ENABLED',
    'name: SYSTEM_BACKUP_REQUIRED',
    'name: SYSTEM_BACKUP_ORIGIN_INSTALLATION_ID',
    'name: SYSTEM_BACKUP_CONTROLLER_BOOTSTRAP_INTERVAL',
    'path: /readyz',
    'path: /healthz',
    'readOnlyRootFilesystem: true',
    'seccompProfile:',
    'type: RuntimeDefault',
    'drop: ["ALL"]',
  ]) assert.match(deployment, new RegExp(required.replace(/[.*+?^{}()|[\]\\$]/g, '\\$&')));
  const terminationGrace = deployment.match(/terminationGracePeriodSeconds:\s*(\d+)/);
  assert.ok(terminationGrace, 'controller must declare a Pod termination grace period');
  assert.ok(Number(terminationGrace[1]) >= 40, 'termination grace must cover the 30s worker stop, 5s health shutdown, and a margin');
  const roleDocument = deployment.split('\n---\n').find((document) => /^kind: Role$/m.test(document));
  assert.ok(roleDocument, 'controller manifest must contain one namespaced Role');
  assert.doesNotMatch(deployment, /\b(?:ClusterRole|ClusterRoleBinding|cluster-admin)\b/);
  assert.doesNotMatch(roleDocument, /\b(?:secrets|pods|jobs|deployments)\b/);
  assert.doesNotMatch(deployment, /SYSTEM_BACKUP_CONTROLLER_(?:CLAIM_TTL|CLAIM_HEARTBEAT|RECONCILE_INTERVAL)/);

  assert.match(dockerfile, /-o \/out\/clawreef-system-backup-controller \.\/cmd\/system-backup-controller/);
  assert.match(dockerfile, /COPY --from=backend-builder \/out\/clawreef-system-backup-controller \/usr\/local\/bin\/clawreef-system-backup-controller/);
});

test('D-owned system image schema is migration-owned instead of repository runtime DDL', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const systemImage = inventory.objects.find((item) => item.object_type === 'table' && item.name === 'system_image_settings');
  assert.ok(systemImage);
  assert.equal(systemImage.owner, 'D');
  assert.equal(systemImage.category, 'resources');
  assert.deepEqual(systemImage.repository_create_sources, []);
  assert.deepEqual(systemImage.repository_alter_sources, []);
  assert.deepEqual(systemImage.deployment_bootstrap_create_sources, []);
  assert.ok(systemImage.migration_sources.includes('backend/internal/db/migrations/003_add_system_image_settings.sql'));
  assert.ok(systemImage.migration_sources.includes('backend/internal/db/migrations/064_reconcile_system_image_settings_schema.sql'));
  assert.equal(inventory.summary.repository_runtime_create, 9);
  assert.equal(inventory.summary.repository_runtime_alter, 3);

  const repositorySource = readFileSync(join(root, 'backend/internal/repository/system_image_setting_repository.go'), 'utf8');
  assert.doesNotMatch(repositorySource, /\b(?:CREATE|ALTER)\s+(?:TABLE|INDEX)\b|information_schema/i);
  assert.doesNotMatch(repositorySource, /ensure(?:Table|Runtime|IsEnabled|InstanceType)/);

  const migration = readFileSync(join(root, 'backend/internal/db/migrations/064_reconcile_system_image_settings_schema.sql'), 'utf8');
  for (const required of [
    'CREATE TABLE IF NOT EXISTS system_image_settings',
    "runtime_type ENUM('desktop', 'shell', 'gateway') NOT NULL DEFAULT 'desktop'",
    "runtime_variant VARCHAR(32) NOT NULL DEFAULT ''",
    'is_enabled BOOLEAN NOT NULL DEFAULT TRUE',
    'SUM(COLUMN_NAME = \'instance_type\') = 1',
    'CREATE INDEX idx_instance_type ON system_image_settings (instance_type)',
  ]) assert.match(migration, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.doesNotMatch(migration, /\b(?:DROP TABLE|TRUNCATE|DELETE FROM)\b/i);

  const systemImageInitKeys = [
    '003_add_system_image_settings.sql',
    '005_update_openclaw_default_image.sql',
    '012_update_agents_runtime_default_images.sql',
    '013_normalize_agents_runtime_image_names.sql',
    '020_add_system_image_runtime_type.sql',
    '021_add_openclaw_shell_runtime_image.sql',
    '031_add_hermes_lite_runtime_image.sql',
  ];
  for (const key of systemImageInitKeys) {
    const embedded = readFileSync(join(root, 'backend/internal/db/migrations', key), 'utf8');
    assert.match(embedded, /system_image_settings/, `${key} must remain an embedded migration`);
  }

  for (const manifest of [
    'deployments/k8s/cluster/clawmanager.yaml',
    'deployments/k8s/single-node/clawmanager.yaml',
    'deployments/k3s/cluster/clawmanager.yaml',
    'deployments/k3s/single-node/clawmanager.yaml',
  ]) {
    const source = readFileSync(join(root, manifest), 'utf8');
    assert.doesNotMatch(source, /system_image_settings/);
    for (const key of systemImageInitKeys) {
      assert.doesNotMatch(source, new RegExp(`^  ${key.replaceAll('.', '\\.')}: \\|`, 'm'));
    }
  }
});

test('D-owned audit log table is created by embedded migration, not four deployment init scripts', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const auditLog = inventory.objects.find((item) => item.object_type === 'table' && item.name === 'audit_logs');
  assert.ok(auditLog);
  assert.equal(auditLog.owner, 'D');
  assert.ok(auditLog.migration_sources.includes('backend/internal/db/migrations/001_init_schema.sql'));
  assert.deepEqual(auditLog.deployment_bootstrap_create_sources, []);
  assert.equal(inventory.summary.deployment_bootstrap_create, 22);
  const migration = readFileSync(join(root, 'backend/internal/db/migrations/001_init_schema.sql'), 'utf8');
  assert.match(migration, /CREATE TABLE IF NOT EXISTS audit_logs\s*\(/);
  for (const manifest of [
    'deployments/k8s/cluster/clawmanager.yaml',
    'deployments/k8s/single-node/clawmanager.yaml',
    'deployments/k3s/cluster/clawmanager.yaml',
    'deployments/k3s/single-node/clawmanager.yaml',
  ]) {
    const source = readFileSync(join(root, manifest), 'utf8');
    assert.doesNotMatch(source, /CREATE TABLE IF NOT EXISTS audit_logs\s*\(/);
  }
});

test('core applies embedded migrations before constructing D repositories', () => {
  const entry = readFileSync(join(root, 'backend/cmd/server/main.go'), 'utf8');
  const database = readFileSync(join(root, 'backend/internal/db/db.go'), 'utf8');
  const initialize = entry.indexOf('database, err := db.Initialize(cfg.Database)');
  const imageRepository = entry.indexOf('repository.NewSystemImageSettingRepository(database)');
  const serverStart = entry.indexOf('router.Run(');
  assert.ok(initialize >= 0 && imageRepository > initialize, 'core must initialize its database before using system_image_settings');
  assert.ok(serverStart < 0 || serverStart > imageRepository, 'core must not serve requests before D repositories exist');

  const connect = database.indexOf('session, err := connect(cfg)', database.indexOf('func Initialize('));
  const migrate = database.indexOf('applyEmbeddedMigrations(session)', connect);
  const publish = database.indexOf('Session = session', migrate);
  const returnSession = database.indexOf('return session, nil', publish);
  assert.ok(connect >= 0 && migrate > connect && publish > migrate && returnSession > publish,
    'db.Initialize must apply embedded migrations before publishing the connection');
});

test('D-owned control metadata core is migration-owned and remains metadata-only', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const decisions = parseJSON(join(contractDir, 'schema-registry-decisions.json'));
  const migrationPath = 'backend/internal/db/migrations/065_add_system_backup_control_metadata_core.sql';
  const tables = [
    'system_backup_installation_state',
    'system_backup_evidence',
    'system_backup_evidence_chunks',
    'system_backup_log_chunks',
    'system_backup_dependency_health',
    'system_backup_provider_capabilities',
    'system_backup_compact_tombstones',
  ];

  for (const table of tables) {
    const object = inventory.objects.find((item) => item.object_type === 'table' && item.name === table);
    assert.ok(object, `${table} must be inventoried`);
    assert.equal(object.owner, 'D');
    assert.equal(object.category, 'system_backup');
    assert.deepEqual(object.migration_sources, [migrationPath]);
    assert.deepEqual(object.repository_create_sources, []);
    assert.deepEqual(object.repository_alter_sources, []);

    const decision = decisions.decisions.find((item) => item.object_type === 'table' && item.name === table);
    assert.ok(decision, `${table} must have a D owner decision`);
    assert.equal(decision.backup_strategy, 'metadata_only');
    assert.equal(decision.restore_strategy, 'reference_only');
    assert.equal(decision.normalizer_id, null);
    assert.equal(decision.decision_status, 'owner_recorded');
    assert.deepEqual(decision.approved_cross_reviewers, []);
  }

  const migration = readFileSync(join(root, migrationPath), 'utf8');
  assert.deepEqual(
    [...migration.matchAll(/^CREATE TABLE IF NOT EXISTS ([a-z][a-z0-9_]*)/gm)].map((match) => match[1]),
    tables,
  );
  for (const required of [
    'CONSTRAINT chk_sb_installation_monitoring CHECK',
    'CONSTRAINT chk_sb_evidence_owner_id CHECK',
    'UNIQUE KEY uk_sb_evidence_public_owner_type (public_id, owner_target_public_id, evidence_type)',
    'CONSTRAINT chk_sb_evidence_failure CHECK',
    'CONSTRAINT chk_sb_evidence_storage CHECK',
    'CONSTRAINT chk_sb_evidence_encryption CHECK',
    'UNIQUE KEY uk_sb_evidence_chunk (evidence_id, chunk_index)',
    'FOREIGN KEY (evidence_id) REFERENCES system_backup_evidence(id) ON DELETE CASCADE',
    'UNIQUE KEY uk_sb_log_chunk (task_type, task_public_id, job_uid, job_generation, chunk_sequence)',
    'FOREIGN KEY (redacted_evidence_id) REFERENCES system_backup_evidence(id) ON DELETE RESTRICT',
    'UNIQUE KEY uk_sb_dependency_identity (dependency_kind, identity_hash, identity_version, owner_target_type, owner_target_public_id)',
    'UNIQUE KEY uk_sb_provider_capability (provider_role, provider_identity_hash, provider_ref_version, capability_code)',
    'CONSTRAINT chk_sb_provider_role_code CHECK',
    'UNIQUE KEY uk_sb_tombstone_source (origin_installation_id, source_type, source_public_id)',
    'UNIQUE KEY uk_sb_tombstone_idempotency (origin_installation_id, actor_type, actor_id, endpoint, idempotency_key)',
    'CONSTRAINT chk_sb_tombstone_retention CHECK',
  ]) assert.match(migration, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.doesNotMatch(migration, /\b(?:DROP TABLE|TRUNCATE|DELETE FROM)\b/i);
});

test('D-owned config and operation authorities materialize the closed machine contracts', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const decisions = parseJSON(join(contractDir, 'schema-registry-decisions.json'));
  const migrationPath = 'backend/internal/db/migrations/066_add_system_backup_config_and_operations.sql';
  const migration = readFileSync(join(root, migrationPath), 'utf8');
  const tables = ['system_backup_configs', 'system_backup_operations'];

  for (const table of tables) {
    const object = inventory.objects.find((item) => item.object_type === 'table' && item.name === table);
    assert.ok(object, `${table} must be inventoried`);
    assert.equal(object.owner, 'D');
    assert.equal(object.category, 'system_backup');
    assert.deepEqual(object.migration_sources, [migrationPath]);
    assert.deepEqual(object.repository_create_sources, []);
    assert.deepEqual(object.repository_alter_sources, []);

    const decision = decisions.decisions.find((item) => item.object_type === 'table' && item.name === table);
    assert.ok(decision, `${table} must have a D owner decision`);
    assert.equal(decision.backup_strategy, 'metadata_only');
    assert.equal(decision.restore_strategy, 'reference_only');
    assert.equal(decision.normalizer_id, null);
    assert.equal(decision.decision_status, 'owner_recorded');
    assert.deepEqual(decision.required_cross_reviewers, ['A', 'B', 'C']);
    assert.deepEqual(decision.approved_cross_reviewers, []);
  }

  const configDefs = adminControlResourcesSchema.$defs;
  const scalarColumns = [
    ...configDefs.DurationConfig.required,
    ...configDefs.CapacityConfig.required,
    ...configDefs.ConcurrencyConfig.required,
    ...configDefs.PreflightLimits.required.map((name) => `preflight_${name}`),
  ];
  for (const column of scalarColumns) {
    assert.match(migration, new RegExp(`^\\s+${column}\\s+[^\\r\\n]+\\bNOT NULL`, 'm'), `missing closed config column ${column}`);
  }

  const registryKinds = configDefs.RegistryReference.properties.registry_kind.enum;
  assert.equal(registryKinds.length, 9);
  for (const kind of registryKinds) {
    assert.match(migration, new RegExp(`^\\s+${kind}_registry_version\\s+VARCHAR\\(128\\).+NOT NULL`, 'm'));
    assert.match(migration, new RegExp(`^\\s+${kind}_registry_sha256\\s+CHAR\\(64\\).+NOT NULL`, 'm'));
  }

  const referencePurposes = configDefs.ConfigReference.properties.purpose.enum;
  assert.equal(referencePurposes.length, 20);
  for (const purpose of referencePurposes) {
    assert.match(migration, new RegExp(`^\\s+${purpose}_identity_hash\\s+CHAR\\(64\\).+NOT NULL`, 'm'));
    assert.match(migration, new RegExp(`^\\s+${purpose}_ref_version\\s+VARCHAR\\(128\\).+NOT NULL`, 'm'));
  }

  const statusDefs = enums.$defs;
  const enumValues = (column) => {
    const match = migration.match(new RegExp(`^\\s+${column}\\s+ENUM\\(([^)]*)\\)`, 'm'));
    assert.ok(match, `${column} enum must be present`);
    return [...match[1].matchAll(/'([^']+)'/g)].map((item) => item[1]);
  };
  assert.deepEqual(enumValues('operation_type'), statusDefs.OperationType.enum);
  assert.deepEqual(enumValues('target_type'), statusDefs.OperationTargetType.enum);
  assert.deepEqual(enumValues('status'), statusDefs.OperationStatus.enum);
  assert.deepEqual(enumValues('failure_category'), statusDefs.FailureCategory.enum);
  assert.equal(taskSchema.$defs.Operation.properties.public_id.$ref, 'admin-api-common.schema.json#/$defs/OperationPublicId');
  assert.equal(taskSchema.$defs.Operation.properties.origin_installation_id.$ref, 'admin-api-common.schema.json#/$defs/InstallationId');
  assert.equal(taskSchema.$defs.Operation.properties.idempotency_key.$ref, 'admin-api-common.schema.json#/$defs/IdempotencyKey');
  assert.equal(taskSchema.$defs.Operation.properties.failure_message.maxLength, 2048);
  assert.equal(taskSchema.$defs.Operation.allOf.length, statusDefs.OperationTargetType.enum.length);
  assert.match(examples.examples.operation.public_id, /^sop_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
  assert.match(examples.examples.operation.target_public_id, /^sbk_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);

  for (const required of [
    'UNIQUE KEY uk_sb_config_version (origin_installation_id, version)',
    'UNIQUE KEY uk_sb_config_snapshot (origin_installation_id, version, config_sha256, config_size_bytes)',
    'CONSTRAINT chk_sb_config_relationships CHECK',
    'controller_claim_heartbeat_seconds * 3 <= controller_claim_ttl_seconds',
    'staging_capacity_bytes * 10 >= max_artifact_bytes * 11 + max_index_bytes * 10',
    'capture_certificate_ttl_seconds > backup_task_deadline_seconds',
    'UNIQUE KEY uk_sb_operation_idempotency (origin_installation_id, actor_type, actor_id, endpoint, idempotency_key)',
    'UNIQUE KEY uk_sb_operation_origin_public (origin_installation_id, public_id)',
    'retry_of_operation_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL',
    'KEY idx_sb_operation_retry (origin_installation_id, retry_of_operation_public_id)',
    'FOREIGN KEY (origin_installation_id, retry_of_operation_public_id) REFERENCES system_backup_operations(origin_installation_id, public_id) ON DELETE RESTRICT',
    'retry_of_operation_public_id <> public_id',
    'CONSTRAINT chk_sb_operation_target_id CHECK',
    'external_action_public_ids_canonical_json BLOB NOT NULL',
    'external_action_public_ids_size_bytes = OCTET_LENGTH(external_action_public_ids_canonical_json)',
    'CONSTRAINT chk_sb_operation_result CHECK',
    'CONSTRAINT chk_sb_operation_sync_terminal CHECK',
    'CONSTRAINT chk_sb_operation_failure CHECK',
    'CONSTRAINT chk_sb_operation_reconcile CHECK',
    'ALTER TABLE system_backup_installation_state ADD CONSTRAINT fk_sb_installation_active_config',
  ]) assert.match(migration, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.doesNotMatch(migration, /retry_of_operation_id/);
  assert.doesNotMatch(migration, /\b(?:password|access_token|refresh_token|private_key|credential_value|provider_uri)\b/i);
  assert.doesNotMatch(migration, /\b(?:DROP TABLE|TRUNCATE|DELETE FROM)\b/i);
});

test('D-owned task and attempt authorities preserve typed cross-owner boundaries', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const decisions = parseJSON(join(contractDir, 'schema-registry-decisions.json'));
  const migrationPath = 'backend/internal/db/migrations/067_add_system_backup_task_execution_core.sql';
  const migration = readFileSync(join(root, migrationPath), 'utf8');
  const tables = [
    'system_backups',
    'system_restore_drills',
    'system_backup_preflights',
    'system_backup_artifact_verifications',
    'system_backup_attempts',
  ];

  for (const table of tables) {
    const object = inventory.objects.find((item) => item.object_type === 'table' && item.name === table);
    assert.ok(object, `${table} must be inventoried`);
    assert.equal(object.owner, 'D');
    assert.equal(object.category, 'system_backup');
    assert.deepEqual(object.migration_sources, [migrationPath]);
    assert.deepEqual(object.repository_create_sources, []);
    assert.deepEqual(object.repository_alter_sources, []);

    const decision = decisions.decisions.find((item) => item.object_type === 'table' && item.name === table);
    assert.ok(decision, `${table} must have a D owner decision`);
    assert.equal(decision.backup_strategy, 'metadata_only');
    assert.equal(decision.restore_strategy, 'reference_only');
    assert.equal(decision.normalizer_id, null);
    assert.deepEqual(decision.required_cross_reviewers, ['A', 'B', 'C']);
    assert.deepEqual(decision.approved_cross_reviewers, []);
  }

  const tableSQL = (table) => {
    const match = migration.match(new RegExp(`CREATE TABLE IF NOT EXISTS ${table} \\(([\\s\\S]*?)\\n\\) ENGINE=InnoDB`));
    assert.ok(match, `${table} DDL must be present`);
    return match[1];
  };
  const enumValues = (sql, column) => {
    const match = sql.match(new RegExp(`^\\s+${column}\\s+ENUM\\(([^)]*)\\)`, 'm'));
    assert.ok(match, `${column} enum must be present`);
    return [...match[1].matchAll(/'([^']+)'/g)].map((item) => item[1]);
  };

  const backupSQL = tableSQL('system_backups');
  const drillSQL = tableSQL('system_restore_drills');
  const preflightSQL = tableSQL('system_backup_preflights');
  const verificationSQL = tableSQL('system_backup_artifact_verifications');
  const attemptSQL = tableSQL('system_backup_attempts');
  assert.deepEqual(enumValues(backupSQL, 'status'), enums.$defs.BackupStatus.enum);
  assert.deepEqual(enumValues(drillSQL, 'status'), enums.$defs.DrillStatus.enum);
  assert.deepEqual(enumValues(preflightSQL, 'status'), enums.$defs.SimpleTaskStatus.enum);
  assert.deepEqual(enumValues(verificationSQL, 'status'), enums.$defs.SimpleTaskStatus.enum);
  assert.deepEqual(enumValues(attemptSQL, 'phase'), enums.$defs.AttemptPhase.enum);
  assert.deepEqual(enumValues(attemptSQL, 'status'), enums.$defs.AttemptStatus.enum);

  for (const sql of [backupSQL, drillSQL, preflightSQL, verificationSQL]) {
    assert.deepEqual(enumValues(sql, 'failure_category'), enums.$defs.FailureCategory.enum);
    for (const field of ['config_snapshot_json', 'config_snapshot_size_bytes', 'config_snapshot_sha256', 'row_version', 'controller_owner', 'controller_lease_expires_at', 'next_reconcile_at', 'deadline_at']) {
      assert.match(sql, new RegExp(`^\\s+${field}\\s+`, 'm'), `task table missing ${field}`);
    }
    assert.match(sql, /UNIQUE KEY .+ \(origin_installation_id, actor_type, actor_id, endpoint, idempotency_key\)/);
    assert.match(sql, /FOREIGN KEY \(origin_installation_id, config_version, config_snapshot_sha256, config_snapshot_size_bytes\) REFERENCES system_backup_configs\(origin_installation_id, version, config_sha256, config_size_bytes\) ON DELETE RESTRICT/);
  }

  for (const required of [
    'CONSTRAINT chk_sb_backup_cancel CHECK',
    'CONSTRAINT chk_sb_backup_commit CHECK',
    "status = 'finalization_unknown' AND failure_category = 'none' AND finished_at IS NULL AND retryable = FALSE",
    'CONSTRAINT chk_sb_backup_artifact CHECK',
    'CONSTRAINT chk_sb_backup_eligibility CHECK',
    'restore_target_config_ref',
    'restore_target_config_hash',
    'CONSTRAINT chk_sb_drill_cleanup CHECK',
    'CONSTRAINT chk_sb_preflight_mode CHECK',
    'CONSTRAINT chk_sb_verify_usable CHECK',
    'CONSTRAINT chk_sb_attempt_phase CHECK',
    'CONSTRAINT chk_sb_attempt_sealed CHECK',
    "status <> 'sealed' AND NOT (status = 'succeeded' AND target_type = 'backup' AND phase IN ('capture', 'secret_capture'))",
    'UNIQUE KEY uk_sb_attempt_unit (target_type, target_public_id, attempt_no, phase)',
  ]) assert.match(migration, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  assert.doesNotMatch(migration, /\b(?:password|access_token|refresh_token|private_key|credential_value)\b/i);
  assert.doesNotMatch(migration, /\b(?:check_expected|check_actual|restore_resource_inventory|provider_payload)\b/i);
  assert.doesNotMatch(migration, /\b(?:DROP TABLE|TRUNCATE|DELETE FROM)\b/i);
});

test('D-owned staging resource intent is migration-owned and follows the plan lifecycle', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const decisions = parseJSON(join(contractDir, 'schema-registry-decisions.json'));
  const schema = parseJSON(join(contractDir, 'staging-resource-lifecycle.schema.json'));
  const migrationPath = 'backend/internal/db/migrations/073_add_system_backup_staging_resources.sql';
  const migration = readFileSync(join(root, migrationPath), 'utf8');
  const object = inventory.objects.find((item) => item.name === 'system_backup_staging_resources');
  const decision = decisions.decisions.find((item) => item.name === 'system_backup_staging_resources');
  assert.equal(object.owner, 'D');
  assert.equal(object.category, 'system_backup');
  assert.deepEqual(object.migration_sources, [migrationPath]);
  assert.deepEqual(object.repository_create_sources, []);
  assert.ok(decision);
  assert.equal(decision.backup_strategy, 'metadata_only');
  assert.equal(decision.restore_strategy, 'reference_only');
  assert.deepEqual(decision.required_cross_reviewers, ['A', 'B', 'C']);
  assert.deepEqual(decision.approved_cross_reviewers, []);
  assert.equal(schema.properties.schema_version.const, 'system-backup-staging-resource.v1');
  assert.deepEqual(schema.properties.lifecycle.enum, ['creating', 'absent', 'ready', 'sealed', 'deleting', 'deleted', 'delete_failed', 'ownership_unknown']);
  assert.deepEqual(schema.properties.cleanup_result.enum, ['not_started', 'running', 'succeeded', 'failed']);
  for (const field of ['phase', 'resource_type', 'lifecycle', 'cleanup_result', 'last_failure_code']) {
    const sqlEnum = migration.match(new RegExp(`^\\s+${field}\\s+ENUM\\(([^)]*)\\)`, 'm'));
    assert.ok(sqlEnum, `staging DDL missing ${field} enum`);
    assert.deepEqual([...sqlEnum[1].matchAll(/'([^']+)'/g)].map((match) => match[1]), schema.properties[field].enum,
      `${field} diverges between DDL and machine schema`);
  }
  for (const [state, destinations] of Object.entries({
    creating: ['absent', 'ready', 'sealed', 'ownership_unknown'],
    ready: ['sealed', 'deleting', 'ownership_unknown'],
    sealed: ['deleting', 'ownership_unknown'],
    deleting: ['deleted', 'delete_failed', 'ownership_unknown'],
    delete_failed: ['deleting', 'ownership_unknown'],
    ownership_unknown: ['absent', 'ready', 'sealed'],
    absent: [], deleted: [],
  })) assert.deepEqual(schema['x-lifecycle-transitions'][state], destinations);
  for (const required of [
    'CREATE TABLE IF NOT EXISTS system_backup_staging_resources',
    'UNIQUE KEY uk_sb_staging_public (public_id)',
    'UNIQUE KEY uk_sb_staging_locator (origin_installation_id, location_sha256)',
    'FOREIGN KEY (origin_installation_id, backup_public_id) REFERENCES system_backups(origin_installation_id, public_id) ON DELETE RESTRICT',
    'FOREIGN KEY (ownership_resolution_evidence_id) REFERENCES system_backup_evidence(id) ON DELETE RESTRICT',
    'CONSTRAINT chk_sb_staging_phase CHECK',
    'CONSTRAINT chk_sb_staging_candidate CHECK',
    'CONSTRAINT chk_sb_staging_lifecycle CHECK',
    'CONSTRAINT chk_sb_staging_observed CHECK',
    'CONSTRAINT chk_sb_staging_claim CHECK',
  ]) assert.ok(migration.includes(required), `staging DDL missing ${required}`);
  assert.doesNotMatch(migration, /\b(?:DROP TABLE|TRUNCATE|DELETE FROM|credential_value|presigned_url|plaintext_key)\b/i);
  assert.equal(schema['x-forbidden-fields'].includes('credential'), true);
  assert.equal(schema['x-forbidden-fields'].includes('presigned_url'), true);
});

test('D-owned maintenance participant ACK is migration-owned and generation-scoped', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const decisions = parseJSON(join(contractDir, 'schema-registry-decisions.json'));
  const schema = parseJSON(join(contractDir, 'maintenance-participant-state.schema.json'));
  const migrationPath = 'backend/internal/db/migrations/074_add_system_maintenance_participants.sql';
  const migration = readFileSync(join(root, migrationPath), 'utf8');
  const object = inventory.objects.find((item) => item.name === 'system_maintenance_participants');
  const decision = decisions.decisions.find((item) => item.name === 'system_maintenance_participants');
  assert.equal(object.owner, 'D');
  assert.equal(object.category, 'system_backup');
  assert.deepEqual(object.migration_sources, [migrationPath]);
  assert.deepEqual(object.repository_create_sources, []);
  assert.equal(decision.backup_strategy, 'metadata_only');
  assert.equal(decision.restore_strategy, 'reference_only');
  assert.deepEqual(decision.required_cross_reviewers, ['A', 'B', 'C']);
  assert.deepEqual(decision.approved_cross_reviewers, []);
  assert.equal(schema.properties.schema_version.const, 'system-maintenance-participant.v1');
  for (const field of ['desired_state', 'observed_state', 'resume_result', 'participant_failure_code']) {
    const sqlEnum = migration.match(new RegExp(`^\\s+${field}\\s+ENUM\\(([^)]*)\\)`, 'm'));
    assert.ok(sqlEnum, `participant DDL missing ${field} enum`);
    assert.deepEqual([...sqlEnum[1].matchAll(/'([^']+)'/g)].map((match) => match[1]), schema.properties[field].enum,
      `${field} diverges between DDL and machine schema`);
  }
  assert.deepEqual(schema['x-state-transitions'], {
    running: ['pausing'],
    pausing: ['paused', 'error'],
    paused: ['resuming'],
    resuming: ['running', 'error'],
    error: ['resuming'],
  });
  for (const required of [
    'CREATE TABLE IF NOT EXISTS system_maintenance_participants',
    'UNIQUE KEY uk_sb_participant_scope (origin_installation_id, scope, participant_id)',
    'FOREIGN KEY (origin_installation_id, scope) REFERENCES system_maintenance_locks(origin_installation_id, scope) ON DELETE RESTRICT',
    'CONSTRAINT chk_sb_participant_identity CHECK',
    'CONSTRAINT chk_sb_participant_checkpoint CHECK',
    'CONSTRAINT chk_sb_participant_state CHECK',
    'CONSTRAINT chk_sb_participant_ack CHECK',
    'CONSTRAINT chk_sb_participant_failure CHECK',
    'CONSTRAINT chk_sb_participant_time CHECK',
  ]) assert.ok(migration.includes(required), `participant DDL missing ${required}`);
  assert.doesNotMatch(migration, /\b(?:DROP TABLE|TRUNCATE|DELETE FROM|credential_value|plaintext_secret)\b/i);
  assert.equal(schema['x-forbidden-fields'].includes('credential'), true);
});

test('D-owned strong-auth nonce ledger stores consumed HMACs without defining A proof verification', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const decisions = parseJSON(join(contractDir, 'schema-registry-decisions.json'));
  const schema = parseJSON(join(contractDir, 'strong-auth-nonce-ledger.schema.json'));
  const manifest = parseJSON(join(contractDir, 'contract-manifest.json'));
  const migrationPath = 'backend/internal/db/migrations/075_add_system_backup_strong_auth_nonces.sql';
  const migration = readFileSync(join(root, migrationPath), 'utf8');
  const object = inventory.objects.find((item) => item.name === 'system_backup_strong_auth_nonces');
  const decision = decisions.decisions.find((item) => item.name === 'system_backup_strong_auth_nonces');
  assert.equal(object.owner, 'D');
  assert.deepEqual(object.migration_sources, [migrationPath]);
  assert.deepEqual(object.repository_create_sources, []);
  assert.equal(decision.backup_strategy, 'metadata_only');
  assert.equal(decision.restore_strategy, 'reference_only');
  assert.deepEqual(decision.required_cross_reviewers, ['A']);
  assert.deepEqual(decision.approved_cross_reviewers, []);
  assert.equal(schema.properties.schema_version.const, 'system-backup-strong-auth-nonce.v1');
  assert.equal(manifest.artifacts.find((artifact) => artifact.id === 'strong_auth_proof_nonce').status, 'missing');
  for (const required of [
    'CREATE TABLE IF NOT EXISTS system_backup_strong_auth_nonces',
    'UNIQUE KEY uk_sb_auth_nonce (nonce_hmac, nonce_hmac_key_version)',
    'KEY idx_sb_auth_nonce_key_retention (nonce_hmac_key_version, retain_until, id)',
    'FOREIGN KEY (operation_id) REFERENCES system_backup_operations(id) ON DELETE RESTRICT',
    'FOREIGN KEY (audit_log_id) REFERENCES audit_logs(id) ON DELETE RESTRICT',
    'CONSTRAINT chk_sb_auth_nonce_identity CHECK',
    'CONSTRAINT chk_sb_auth_nonce_request CHECK',
    'CONSTRAINT chk_sb_auth_nonce_result CHECK',
    'response_sha256 IS NOT NULL AND response_sha256 REGEXP',
    'CONSTRAINT chk_sb_auth_nonce_times CHECK',
  ]) assert.ok(migration.includes(required), `nonce DDL missing ${required}`);
  assert.doesNotMatch(migration, /\b(?:DROP TABLE|TRUNCATE|DELETE FROM|raw_nonce|nonce_key_material|session_token|raw_subject)\b/i);
  assert.equal(schema['x-forbidden-fields'].includes('raw_nonce'), true);
  assert.equal(schema['x-forbidden-fields'].includes('proof'), true);
});

test('D-owned Job observation cursor is migration-owned while B status relay stays missing', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const decisions = parseJSON(join(contractDir, 'schema-registry-decisions.json'));
  const schema = parseJSON(join(contractDir, 'job-observation-cursor.schema.json'));
  const manifest = parseJSON(join(contractDir, 'contract-manifest.json'));
  const migrationPath = 'backend/internal/db/migrations/076_add_system_backup_job_observations.sql';
  const migration = readFileSync(join(root, migrationPath), 'utf8');
  const object = inventory.objects.find((item) => item.name === 'system_backup_job_observations');
  const decision = decisions.decisions.find((item) => item.name === 'system_backup_job_observations');
  assert.equal(object.owner, 'D');
  assert.deepEqual(object.migration_sources, [migrationPath]);
  assert.deepEqual(object.repository_create_sources, []);
  assert.equal(decision.backup_strategy, 'metadata_only');
  assert.equal(decision.restore_strategy, 'reference_only');
  assert.deepEqual(decision.required_cross_reviewers, ['A', 'B', 'C']);
  assert.deepEqual(decision.approved_cross_reviewers, []);
  assert.equal(manifest.artifacts.find((artifact) => artifact.id === 'status_relay').status, 'missing');
  assert.equal(schema.properties.schema_version.const, 'system-backup-job-observation.v1');
  for (const field of ['target_type', 'phase']) {
    const sqlEnum = migration.match(new RegExp(`^\\s+${field}\\s+ENUM\\(([^)]*)\\)`, 'm'));
    assert.ok(sqlEnum, `Job DDL missing ${field} enum`);
    assert.deepEqual([...sqlEnum[1].matchAll(/'([^']+)'/g)].map((match) => match[1]), schema.properties[field].enum);
  }
  for (const required of [
    'CREATE TABLE IF NOT EXISTS system_backup_job_observations',
    'UNIQUE KEY uk_sb_job_unit (origin_installation_id, target_type, target_public_id, attempt_no, phase, job_unit_key)',
    'UNIQUE KEY uk_sb_job_uid (job_uid)',
    'FOREIGN KEY (target_type, target_public_id, attempt_no, phase) REFERENCES system_backup_attempts(target_type, target_public_id, attempt_no, phase) ON DELETE RESTRICT',
    'CONSTRAINT chk_sb_job_relay CHECK',
    'CONSTRAINT chk_sb_job_cursor CHECK',
    'CONSTRAINT chk_sb_job_progress CHECK',
    'CONSTRAINT chk_sb_job_command CHECK',
    'last_accepted_body_sha256 IS NOT NULL',
    'progress_digest_sha256 IS NOT NULL',
    'command_job_generation = job_generation',
  ]) assert.ok(migration.includes(required), `Job DDL missing ${required}`);
  assert.doesNotMatch(migration, /\b(?:DROP TABLE|TRUNCATE|DELETE FROM|credential_value|relay_private_key|raw_result|index_payload)\b/i);
  assert.equal(schema['x-forbidden-fields'].includes('credential'), true);
});

test('D-owned restore drill resource intent records cleanup without B target behavior', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const decisions = parseJSON(join(contractDir, 'schema-registry-decisions.json'));
  const schema = parseJSON(join(contractDir, 'restore-drill-resource-lifecycle.schema.json'));
  const manifest = parseJSON(join(contractDir, 'contract-manifest.json'));
  const migrationPath = 'backend/internal/db/migrations/077_add_system_restore_drill_resources.sql';
  const migration = readFileSync(join(root, migrationPath), 'utf8');
  const object = inventory.objects.find((item) => item.name === 'system_restore_drill_resources');
  const decision = decisions.decisions.find((item) => item.name === 'system_restore_drill_resources');
  assert.equal(object.owner, 'D');
  assert.deepEqual(object.migration_sources, [migrationPath]);
  assert.deepEqual(object.repository_create_sources, []);
  assert.equal(decision.backup_strategy, 'metadata_only');
  assert.equal(decision.restore_strategy, 'reference_only');
  assert.deepEqual(decision.required_cross_reviewers, ['A', 'B', 'C']);
  assert.deepEqual(decision.approved_cross_reviewers, []);
  assert.equal(manifest.artifacts.find((artifact) => artifact.id === 'restore_target').status, 'missing');
  assert.equal(schema.properties.schema_version.const, 'system-restore-drill-resource.v1');
  for (const field of ['lifecycle', 'last_failure_code']) {
    const sqlEnum = migration.match(new RegExp(`^\\s+${field}\\s+ENUM\\(([^)]*)\\)`, 'm'));
    assert.ok(sqlEnum, `restore resource DDL missing ${field} enum`);
    assert.deepEqual([...sqlEnum[1].matchAll(/'([^']+)'/g)].map((match) => match[1]), schema.properties[field].enum);
  }
  assert.deepEqual(schema['x-lifecycle-transitions'], {
    creating: ['absent', 'created', 'ownership_unknown'],
    created: ['deleting', 'ownership_unknown'],
    deleting: ['deleted', 'delete_failed', 'ownership_unknown'],
    delete_failed: ['deleting', 'ownership_unknown'],
    ownership_unknown: ['absent', 'created'],
    absent: [], deleted: [],
  });
  for (const required of [
    'CREATE TABLE IF NOT EXISTS system_restore_drill_resources',
    'UNIQUE KEY uk_sb_restore_resource_public (public_id)',
    'UNIQUE KEY uk_sb_restore_resource_location (origin_installation_id, drill_public_id, resource_type, location_sha256)',
    'FOREIGN KEY (origin_installation_id, drill_public_id) REFERENCES system_restore_drills(origin_installation_id, public_id) ON DELETE RESTRICT',
    'FOREIGN KEY (ownership_resolution_evidence_id) REFERENCES system_backup_evidence(id) ON DELETE RESTRICT',
    'CONSTRAINT chk_sb_restore_resource_lifecycle CHECK',
    'CONSTRAINT chk_sb_restore_resource_observed CHECK',
    'CONSTRAINT chk_sb_restore_resource_evidence CHECK',
    'ownership_resolution_evidence_sha256 IS NOT NULL',
  ]) assert.ok(migration.includes(required), `restore resource DDL missing ${required}`);
  assert.doesNotMatch(migration, /\b(?:DROP TABLE|TRUNCATE|DELETE FROM|credential_value|presigned_url|raw_owner_token|created_boolean)\b/i);
  assert.equal(schema['x-forbidden-fields'].includes('credential'), true);
});

test('D-owned coordination and observability tables stay closed and owner-neutral', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const decisions = parseJSON(join(contractDir, 'schema-registry-decisions.json'));
  const migrationPath = 'backend/internal/db/migrations/068_add_system_backup_coordination_observability.sql';
  const migration = readFileSync(join(root, migrationPath), 'utf8');
  const reviewMap = new Map([
    ['system_backup_events', ['A', 'B', 'C']],
    ['system_backup_alert_states', ['A', 'B', 'C']],
    ['system_artifact_lease_states', ['B', 'C']],
    ['system_artifact_leases', ['B', 'C']],
    ['system_maintenance_locks', ['A', 'B', 'C']],
    ['system_maintenance_mutation_leases', ['A', 'B', 'C']],
  ]);

  for (const [table, reviewers] of reviewMap) {
    const object = inventory.objects.find((item) => item.object_type === 'table' && item.name === table);
    assert.ok(object, `${table} must be inventoried`);
    assert.equal(object.owner, 'D');
    assert.equal(object.category, 'system_backup');
    assert.deepEqual(object.migration_sources, [migrationPath]);
    assert.deepEqual(object.repository_create_sources, []);
    assert.deepEqual(object.repository_alter_sources, []);

    const decision = decisions.decisions.find((item) => item.object_type === 'table' && item.name === table);
    assert.ok(decision, `${table} must have a D owner decision`);
    assert.equal(decision.backup_strategy, 'metadata_only');
    assert.equal(decision.restore_strategy, 'reference_only');
    assert.equal(decision.normalizer_id, null);
    assert.deepEqual(decision.required_cross_reviewers, reviewers);
    assert.deepEqual(decision.approved_cross_reviewers, []);
  }

  const eventTypes = adminActivityResourcesSchema.$defs.CoreEventType.enum;
  for (const eventType of eventTypes) {
    assert.match(migration, new RegExp(`'${eventType}'`), `missing core event type ${eventType}`);
  }
  for (const detailName of Object.keys(adminActivityResourcesSchema.$defs.EventDetails.properties)) {
    assert.match(migration, new RegExp(`^\\s+detail_${detailName}\\s+`, 'm'), `missing closed event detail ${detailName}`);
  }

  for (const required of [
    'KEY idx_sb_event_cursor (target_type, target_public_id, created_at, id)',
    'CONSTRAINT chk_sb_event_target CHECK',
    'CONSTRAINT chk_sb_event_task_status CHECK',
    'CONSTRAINT chk_sb_event_details CHECK',
    'UNIQUE KEY uk_sb_alert_scope (origin_installation_id, rule_key, matrix_key, task_type, task_purpose)',
    'CONSTRAINT chk_sb_alert_sequence CHECK',
    'CONSTRAINT chk_sb_alert_lifecycle CHECK',
    'UNIQUE KEY uk_sb_artifact_lease_mode (origin_installation_id, source_artifact_type, source_public_id, generation, lease_mode)',
    'UNIQUE KEY uk_sb_artifact_delete_guard (origin_installation_id, delete_source_guard)',
    'CONSTRAINT chk_sb_artifact_lease_holder CHECK',
    'FOREIGN KEY (origin_installation_id, source_artifact_type, source_public_id, lease_generation, lease_mode) REFERENCES system_artifact_lease_states(origin_installation_id, source_artifact_type, source_public_id, generation, lease_mode) ON DELETE RESTRICT ON UPDATE RESTRICT',
    'UNIQUE KEY uk_sb_maintenance_gate (origin_installation_id, scope)',
    'CONSTRAINT chk_sb_maintenance_idle CHECK',
    'CONSTRAINT chk_sb_maintenance_fence CHECK',
    'FOREIGN KEY (origin_installation_id, scope) REFERENCES system_maintenance_locks(origin_installation_id, scope) ON DELETE RESTRICT',
  ]) assert.match(migration, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  assert.doesNotMatch(migration, /\b(?:participant_id|job_uid|provider_payload|credential_value|check_expected|check_actual)\b/i);
  assert.doesNotMatch(migration, /\b(?:DROP TABLE|TRUNCATE|DELETE FROM)\b/i);
});

test('D-owned promotion authority binds one active baseline without caching current health', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const decisions = parseJSON(join(contractDir, 'schema-registry-decisions.json'));
  const migrationPath = 'backend/internal/db/migrations/069_add_system_backup_promotion_authority.sql';
  const migration = readFileSync(join(root, migrationPath), 'utf8');
  const table = 'system_backup_promotions';
  const object = inventory.objects.find((item) => item.object_type === 'table' && item.name === table);
  assert.ok(object, `${table} must be inventoried`);
  assert.equal(object.owner, 'D');
  assert.equal(object.category, 'system_backup');
  assert.deepEqual(object.migration_sources, [migrationPath]);
  assert.deepEqual(object.repository_create_sources, []);
  assert.deepEqual(object.repository_alter_sources, []);

  const decision = decisions.decisions.find((item) => item.object_type === 'table' && item.name === table);
  assert.ok(decision, `${table} must have a D owner decision`);
  assert.equal(decision.backup_strategy, 'metadata_only');
  assert.equal(decision.restore_strategy, 'reference_only');
  assert.equal(decision.normalizer_id, null);
  assert.deepEqual(decision.required_cross_reviewers, ['A', 'B', 'C']);
  assert.deepEqual(decision.approved_cross_reviewers, []);

  const promotion = adminActivityResourcesSchema.$defs.PromotionResource;
  const scalarColumns = {
    schema_version: 'schema_version',
    public_id: 'public_id',
    origin_installation_id: 'origin_installation_id',
    matrix: 'matrix_key',
    record_status: 'record_status',
    backup_public_id: 'backup_public_id',
    drill_public_id: 'drill_public_id',
    manifest_checksum: 'manifest_checksum',
    acceptance_checksum: 'acceptance_checksum',
    artifact_registration_id: 'artifact_registration_id',
    artifact_registration_hash: 'artifact_registration_hash',
    eligibility_decision_hash: 'eligibility_decision_hash',
    drill_evidence_public_id: 'drill_evidence_public_id',
    drill_evidence_hash: 'drill_evidence_hash',
    created_by: 'created_by',
    created_at: 'created_at',
    superseded_by_public_id: 'superseded_by_public_id',
    superseded_at: 'superseded_at',
    revoked_by: 'revoked_by',
    revoked_reason: 'revoked_reason',
    revoked_at: 'revoked_at',
    row_version: 'row_version',
  };
  for (const field of promotion.required.filter((name) => name !== 'health')) {
    assert.match(migration, new RegExp(`^\\s+${scalarColumns[field]}\\s+`, 'm'), `missing promotion authority field ${field}`);
  }

  for (const group of ['artifact', 'artifact_access', 'kek', 'signature', 'catalog', 'evidence', 'attestation']) {
    assert.match(migration, new RegExp(`^\\s+creation_${group}_health\\s+ENUM\\('healthy', 'degraded', 'unknown', 'stale'\\)`, 'm'));
  }
  for (const required of [
    'UNIQUE KEY uk_sb_promotion_active (origin_installation_id, matrix_key, active_guard)',
    'FOREIGN KEY (origin_installation_id, backup_public_id, matrix_key) REFERENCES system_backups(origin_installation_id, public_id, matrix_key) ON DELETE RESTRICT',
    'FOREIGN KEY (origin_installation_id, drill_public_id, backup_public_id) REFERENCES system_restore_drills(origin_installation_id, public_id, local_source_backup_public_id) ON DELETE RESTRICT',
    'CONSTRAINT chk_sb_promotion_creation_health CHECK',
    'CONSTRAINT chk_sb_promotion_registration CHECK',
    'CONSTRAINT chk_sb_promotion_lifecycle CHECK',
    'OCTET_LENGTH(revoked_reason) BETWEEN 1 AND 512',
  ]) assert.match(migration, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.doesNotMatch(migration, /^\s+current_health\s+/m);
  assert.doesNotMatch(migration, /\b(?:provider_payload|credential_value|restore_resource_inventory|signature_payload)\b/i);
  assert.doesNotMatch(migration, /\b(?:DROP TABLE|TRUNCATE|DELETE FROM)\b/i);
});

test('D-owned prune authority freezes candidates and owner-neutral item retries', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const decisions = parseJSON(join(contractDir, 'schema-registry-decisions.json'));
  const migrationPath = 'backend/internal/db/migrations/070_add_system_backup_prune_authority.sql';
  const migration = readFileSync(join(root, migrationPath), 'utf8');
  const reviewMap = new Map([
    ['system_backup_prune_runs', ['A', 'C']],
    ['system_backup_prune_items', ['C']],
  ]);

  for (const [table, reviewers] of reviewMap) {
    const object = inventory.objects.find((item) => item.object_type === 'table' && item.name === table);
    assert.ok(object, `${table} must be inventoried`);
    assert.equal(object.owner, 'D');
    assert.equal(object.category, 'system_backup');
    assert.deepEqual(object.migration_sources, [migrationPath]);
    assert.deepEqual(object.repository_create_sources, []);
    assert.deepEqual(object.repository_alter_sources, []);

    const decision = decisions.decisions.find((item) => item.object_type === 'table' && item.name === table);
    assert.ok(decision, `${table} must have a D owner decision`);
    assert.equal(decision.backup_strategy, 'metadata_only');
    assert.equal(decision.restore_strategy, 'reference_only');
    assert.equal(decision.normalizer_id, null);
    assert.deepEqual(decision.required_cross_reviewers, reviewers);
    assert.deepEqual(decision.approved_cross_reviewers, []);
  }

  const tableSQL = (table) => {
    const match = migration.match(new RegExp(`CREATE TABLE IF NOT EXISTS ${table} \\(([\\s\\S]*?)\\n\\) ENGINE=InnoDB`));
    assert.ok(match, `${table} DDL must be present`);
    return match[1];
  };
  const enumValues = (sql, column) => {
    const match = sql.match(new RegExp(`^\\s+${column}\\s+ENUM\\(([^)]*)\\)`, 'm'));
    assert.ok(match, `${column} enum must be present`);
    return [...match[1].matchAll(/'([^']+)'/g)].map((item) => item[1]);
  };

  const runSQL = tableSQL('system_backup_prune_runs');
  const itemSQL = tableSQL('system_backup_prune_items');
  assert.deepEqual(enumValues(runSQL, 'status'), adminControlResourcesSchema.$defs.PruneRunResource.properties.status.enum);
  assert.deepEqual(enumValues(runSQL, 'confirmation_status'), ['none', ...adminControlResourcesSchema.$defs.PruneConfirmationResource.properties.status.enum]);
  assert.deepEqual(enumValues(runSQL, 'failure_category'), enums.$defs.FailureCategory.enum);
  assert.deepEqual(enumValues(itemSQL, 'item_type'), adminActivityResourcesSchema.$defs.PruneItemResource.properties.item_type.enum);
  assert.deepEqual(enumValues(itemSQL, 'status'), adminActivityResourcesSchema.$defs.PruneItemResource.properties.status.enum);
  assert.deepEqual(enumValues(itemSQL, 'item_failure_code'), adminActivityResourcesSchema.$defs.PruneItemResource.properties.item_failure_code.enum);

  for (const required of [
    'UNIQUE KEY uk_sb_prune_run_create (origin_installation_id, create_actor_type, create_actor_id, create_endpoint, create_idempotency_key)',
    'UNIQUE KEY uk_sb_prune_run_confirmation_id (origin_installation_id, confirmation_id)',
    'UNIQUE KEY uk_sb_prune_run_confirmation (origin_installation_id, confirmation_actor_id, confirmation_endpoint, confirmation_idempotency_key)',
    'CONSTRAINT chk_sb_prune_run_candidate CHECK',
    'CONSTRAINT chk_sb_prune_run_confirmation CHECK',
    'confirmation_candidate_hash = candidate_hash',
    'confirmation_cutoff_at = older_than',
    'confirmation_config_version = config_version',
    'CONSTRAINT chk_sb_prune_run_retry CHECK',
    'CONSTRAINT chk_sb_prune_run_status CHECK',
    'UNIQUE KEY uk_sb_prune_item_origin_public (origin_installation_id, public_id)',
    'UNIQUE KEY uk_sb_prune_item_plan (prune_run_id, artifact_public_id, item_type, canonical_location_hash, immutable_version_sentinel)',
    'FOREIGN KEY (origin_installation_id, artifact_public_id, artifact_registration_id, artifact_registration_hash) REFERENCES system_backups(origin_installation_id, public_id, artifact_registration_id, artifact_registration_hash) ON DELETE RESTRICT',
    'CONSTRAINT chk_sb_prune_item_kind CHECK',
    'CONSTRAINT chk_sb_prune_item_location CHECK',
    'canonical_location_size_bytes = OCTET_LENGTH(canonical_location_key)',
    'canonical_location_hash = SHA2(canonical_location_key, 256)',
    'CONSTRAINT chk_sb_prune_item_blocked CHECK',
    'CONSTRAINT chk_sb_prune_item_status CHECK',
    "status = 'blocked_by_delete' AND external_action_public_id IS NULL",
    "status <> 'blocked_by_delete' AND external_action_public_id IS NOT NULL",
  ]) assert.match(migration, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  assert.doesNotMatch(migration, /\b(?:strong_auth_proof|provider_payload|provider_locator|catalog_payload|credential_value)\b/i);
  assert.doesNotMatch(migration, /\b(?:DROP TABLE|TRUNCATE|DELETE FROM)\b/i);
});

test('D-owned external action authority persists exact bytes without provider execution', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const decisions = parseJSON(join(contractDir, 'schema-registry-decisions.json'));
  const migrationPath = 'backend/internal/db/migrations/071_add_system_backup_external_action_authority.sql';
  const migration = readFileSync(join(root, migrationPath), 'utf8');
  const table = 'system_backup_external_actions';
  const object = inventory.objects.find((item) => item.object_type === 'table' && item.name === table);
  assert.ok(object, `${table} must be inventoried`);
  assert.equal(object.owner, 'D');
  assert.equal(object.category, 'system_backup');
  assert.deepEqual(object.migration_sources, [migrationPath]);
  assert.deepEqual(object.repository_create_sources, []);
  assert.deepEqual(object.repository_alter_sources, []);

  const decision = decisions.decisions.find((item) => item.object_type === 'table' && item.name === table);
  assert.ok(decision, `${table} must have a D owner decision`);
  assert.equal(decision.backup_strategy, 'metadata_only');
  assert.equal(decision.restore_strategy, 'reference_only');
  assert.equal(decision.normalizer_id, null);
  assert.deepEqual(decision.required_cross_reviewers, ['A', 'C']);
  assert.deepEqual(decision.approved_cross_reviewers, []);

  const tableMatch = migration.match(/CREATE TABLE IF NOT EXISTS system_backup_external_actions \(([\s\S]*?)\n\) ENGINE=InnoDB/);
  assert.ok(tableMatch, `${table} DDL must be present`);
  const sql = tableMatch[1];
  const enumValues = (column) => {
    const match = sql.match(new RegExp(`^\\s+${column}\\s+ENUM\\(([^)]*)\\)`, 'm'));
    assert.ok(match, `${column} enum must be present`);
    return [...match[1].matchAll(/'([^']+)'/g)].map((item) => item[1]);
  };
  assert.deepEqual(enumValues('target_type'), externalActionSchema.properties.target_type.enum);
  assert.deepEqual(enumValues('action_type'), externalActionSchema.properties.action_type.enum);
  assert.deepEqual(enumValues('state'), externalActionSchema.properties.state.enum);

  const fieldMap = {
    schema_version: 'schema_version', public_id: 'public_id', target_type: 'target_type', target_public_id: 'target_public_id',
    operation_public_id: 'operation_public_id', action_type: 'action_type', logical_action_hash: 'logical_action_hash', action_key: 'action_key',
    canonical_payload_base64: 'canonical_payload_bytes', payload_sha256: 'payload_sha256', content_length: 'content_length', final_key: 'final_key',
    dispatch_generation: 'dispatch_generation', dispatch_deadline: 'dispatch_deadline', state: 'state', send_attempt_count: 'send_attempt_count',
    observe_attempt_count: 'observe_attempt_count', last_checked_at: 'last_checked_at', observed_version: 'observed_version',
    observed_checksum: 'observed_checksum', provider_proof_evidence_id: 'provider_proof_evidence_public_id', row_version: 'row_version',
    created_at: 'created_at', updated_at: 'updated_at',
  };
  for (const field of Object.keys(externalActionSchema.properties).filter((name) => name !== 'conditional_create')) {
    assert.match(sql, new RegExp(`^\\s+${fieldMap[field]}\\s+`, 'm'), `missing external-action authority field ${field}`);
  }

  for (const required of [
    'UNIQUE KEY uk_sb_external_action_identity (target_type, target_public_id, action_type, action_key)',
    'UNIQUE KEY uk_sb_external_action_unresolved_backup (origin_installation_id, unresolved_backup_guard)',
    "GENERATED ALWAYS AS (CASE WHEN target_type = 'backup' AND state IN ('request_sent', 'provider_unreachable') THEN target_public_id ELSE NULL END) STORED",
    'FOREIGN KEY (origin_installation_id, backup_target_public_id) REFERENCES system_backups(origin_installation_id, public_id) ON DELETE RESTRICT',
    'FOREIGN KEY (origin_installation_id, prune_item_target_public_id) REFERENCES system_backup_prune_items(origin_installation_id, public_id) ON DELETE RESTRICT',
    'CONSTRAINT chk_sb_external_action_type CHECK',
    'CONSTRAINT chk_sb_external_action_payload CHECK',
    'payload_sha256 = SHA2(canonical_payload_bytes, 256)',
    'content_length = OCTET_LENGTH(canonical_payload_bytes)',
    'CONSTRAINT chk_sb_external_action_keys CHECK',
    'FOREIGN KEY (provider_proof_evidence_public_id, provider_proof_target_public_id, provider_proof_evidence_type) REFERENCES system_backup_evidence(public_id, owner_target_public_id, evidence_type) ON DELETE RESTRICT',
    'CONSTRAINT chk_sb_external_action_state CHECK',
    'observed_checksum = payload_sha256',
    'observed_checksum <> payload_sha256',
    "state = 'confirmed_absent' AND last_checked_at IS NOT NULL AND last_checked_at >= dispatch_deadline",
    "CONSTRAINT_NAME = 'fk_sb_backup_finalization_action'",
    'ALTER TABLE system_backups ADD CONSTRAINT fk_sb_backup_finalization_action',
    "CONSTRAINT_NAME = 'fk_sb_prune_item_external_action'",
    'ALTER TABLE system_backup_prune_items ADD CONSTRAINT fk_sb_prune_item_external_action',
  ]) assert.match(migration, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  for (const forbidden of externalActionSchema['x-forbidden-fields']) assert.doesNotMatch(migration, new RegExp(`\\b${forbidden}\\b`, 'i'));
  assert.doesNotMatch(migration, /\b(?:opaque_credential|provider_request|provider_response|dispatch_result)\b/i);
  assert.doesNotMatch(migration, /\b(?:DROP TABLE|TRUNCATE|DELETE FROM)\b/i);
});

test('D-owned check authorities persist summaries without owner discovery or verifier registries', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const decisions = parseJSON(join(contractDir, 'schema-registry-decisions.json'));
  const migrationPath = 'backend/internal/db/migrations/072_add_system_backup_check_authority.sql';
  const migration = readFileSync(join(root, migrationPath), 'utf8');
  const tables = ['system_backup_source_writer_check_states', 'system_backup_check_results'];

  for (const table of tables) {
    const object = inventory.objects.find((item) => item.object_type === 'table' && item.name === table);
    assert.ok(object, `${table} must be inventoried`);
    assert.equal(object.owner, 'D');
    assert.equal(object.category, 'system_backup');
    assert.deepEqual(object.migration_sources, [migrationPath]);
    assert.deepEqual(object.repository_create_sources, []);
    assert.deepEqual(object.repository_alter_sources, []);

    const decision = decisions.decisions.find((item) => item.object_type === 'table' && item.name === table);
    assert.ok(decision, `${table} must have a D owner decision`);
    assert.equal(decision.backup_strategy, 'metadata_only');
    assert.equal(decision.restore_strategy, 'reference_only');
    assert.equal(decision.normalizer_id, null);
    assert.deepEqual(decision.required_cross_reviewers, ['A', 'B', 'C']);
    assert.deepEqual(decision.approved_cross_reviewers, []);
  }

  const tableSQL = (table) => {
    const match = migration.match(new RegExp(`CREATE TABLE IF NOT EXISTS ${table} \\(([\\s\\S]*?)\\n\\) ENGINE=InnoDB`));
    assert.ok(match, `${table} DDL must be present`);
    return match[1];
  };
  const enumValues = (sql, column) => {
    const match = sql.match(new RegExp(`^\\s+${column}\\s+ENUM\\(([^)]*)\\)`, 'm'));
    assert.ok(match, `${column} enum must be present`);
    return [...match[1].matchAll(/'([^']+)'/g)].map((item) => item[1]);
  };

  const writerSQL = tableSQL('system_backup_source_writer_check_states');
  assert.deepEqual(enumValues(writerSQL, 'check_state'), sourceWriter.properties.check_state.enum);
  assert.deepEqual(enumValues(writerSQL, 'reason_code'), sourceWriter.properties.reason_code.enum);
  for (const column of ['mysql_inventory_hash', 'redis_inventory_hash', 'object_inventory_hash', 'workspace_inventory_hash', 'runtime_inventory_hash']) {
    assert.match(writerSQL, new RegExp(`^\\s+${column}\\s+CHAR\\(64\\)`, 'm'));
  }
  for (const required of [
    'UNIQUE KEY uk_sb_writer_check_config (origin_installation_id, config_version)',
    'FOREIGN KEY (origin_installation_id, config_version) REFERENCES system_backup_configs(origin_installation_id, version) ON DELETE RESTRICT',
    'CONSTRAINT chk_sb_writer_check_hashes CHECK',
    'CONSTRAINT chk_sb_writer_check_result CHECK',
    "check_state = 'clean' AND reason_code = 'none' AND difference_count = 0 AND last_success_at IS NOT NULL AND last_success_at = checked_at",
    "check_state = 'drift' AND reason_code IN ('identity_mismatch', 'writer_missing', 'writer_unregistered', 'policy_mismatch') AND difference_count >= 1",
    'CONSTRAINT chk_sb_writer_check_claim CHECK',
  ]) assert.match(writerSQL, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  const checkSQL = tableSQL('system_backup_check_results');
  assert.deepEqual(enumValues(checkSQL, 'target_type'), verifierSchema.properties.target_type.enum);
  assert.deepEqual(enumValues(checkSQL, 'category'), verifierSchema.properties.category.enum);
  assert.deepEqual(enumValues(checkSQL, 'mode'), verifierSchema.properties.mode.enum);
  assert.deepEqual(enumValues(checkSQL, 'status'), verifierSchema.$defs.Check.properties.status.enum);
  assert.deepEqual(enumValues(checkSQL, 'check_classification'), enums.$defs.CheckClassification.enum);
  assert.deepEqual(enumValues(checkSQL, 'failure_category'), enums.$defs.FailureCategory.enum);
  for (const required of [
    'UNIQUE KEY uk_sb_check_result_identity (target_type, target_public_id, attempt_no_sentinel, mode, category, check_code)',
    'FOREIGN KEY (origin_installation_id, backup_target_public_id) REFERENCES system_backups(origin_installation_id, public_id) ON DELETE RESTRICT',
    'FOREIGN KEY (origin_installation_id, cleanup_target_public_id, cleanup_operation_type) REFERENCES system_backup_operations(origin_installation_id, public_id, operation_type) ON DELETE RESTRICT',
    'CONSTRAINT chk_sb_check_result_target CHECK',
    "mode = 'backup_validate' AND attempt_no IS NOT NULL AND attempt_no >= 1",
    'CONSTRAINT chk_sb_check_result_category CHECK',
    'CONSTRAINT chk_sb_check_result_payload CHECK',
    'expected_canonical_json BLOB NOT NULL',
    'actual_canonical_json BLOB NOT NULL',
    'expected_sha256 = SHA2(expected_canonical_json, 256)',
    'actual_sha256 = SHA2(actual_canonical_json, 256)',
    'JSON_LENGTH(CONVERT(expected_canonical_json USING utf8mb4)) <= 128',
    'CONSTRAINT chk_sb_check_result_status CHECK',
    "status = 'warning' AND skip_reason IS NULL AND warning_code IS NOT NULL",
    "status = 'failed' AND skip_reason IS NULL AND warning_code IS NULL AND check_classification IS NOT NULL AND failure_category <> 'none'",
    'evidence_public_id IS NOT NULL AND evidence_sha256 IS NOT NULL',
    'CONSTRAINT chk_sb_check_result_evidence CHECK',
  ]) assert.match(checkSQL, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  for (const [migrationFile, key] of [
    ['066_add_system_backup_config_and_operations.sql', 'UNIQUE KEY uk_sb_operation_origin_type (origin_installation_id, public_id, operation_type)'],
    ['067_add_system_backup_task_execution_core.sql', 'UNIQUE KEY uk_sb_preflight_origin_public (origin_installation_id, public_id)'],
    ['067_add_system_backup_task_execution_core.sql', 'UNIQUE KEY uk_sb_verify_origin_public (origin_installation_id, public_id)'],
    ['069_add_system_backup_promotion_authority.sql', 'UNIQUE KEY uk_sb_promotion_origin_public (origin_installation_id, public_id)'],
    ['070_add_system_backup_prune_authority.sql', 'UNIQUE KEY uk_sb_prune_run_origin_public (origin_installation_id, public_id)'],
  ]) assert.match(readFileSync(join(root, 'backend/internal/db/migrations', migrationFile), 'utf8'), new RegExp(key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  assert.doesNotMatch(migration, /\b(?:raw_writer_inventory|writer_inventory_json|check_registry_json|provider_payload|credential_value)\b/i);
  assert.doesNotMatch(migration, /\b(?:DROP TABLE|TRUNCATE|DELETE FROM)\b/i);
});

test('cross-owner request covers every pending owner decision and required D review without inventing approvals', () => {
  const inventory = parseJSON(join(root, 'docs/system-backup-restore-schema-inventory.json'));
  const decisions = parseJSON(join(contractDir, 'schema-registry-decisions.json'));
  for (const owner of ['A', 'B', 'C']) {
    const expected = inventory.objects
      .filter((item) => item.owner === owner)
      .map((item) => `${item.object_type}:${item.name}`)
      .sort();
    assert.deepEqual([...reviews.schema_policy_submissions[owner]].sort(), expected);

    const expectedDReviews = decisions.decisions
      .filter((item) => item.required_cross_reviewers.includes(owner))
      .map((item) => `${item.object_type}:${item.name}`)
      .sort();
    assert.deepEqual([...reviews.d_owned_object_reviews[owner]].sort(), expectedDReviews);
  }
  assert.deepEqual(reviews.approval_evidence, []);
  assert.ok(reviews.public_contract_reviews.every((item) => item.approved_reviewers.length === 0));
  assert.deepEqual(
    reviews.public_contract_reviews.find((item) => item.artifact_ids.includes('hash_algorithms')),
    { artifact_ids: ['hash_algorithms'], required_reviewers: ['A', 'B', 'C'], approved_reviewers: [] },
  );
  const artifactIDs = new Set(parseJSON(join(contractDir, 'contract-manifest.json')).artifacts.map((item) => item.id));
  const requestedArtifactIDs = reviews.public_contract_reviews.flatMap((item) => item.artifact_ids);
  assert.equal(new Set(requestedArtifactIDs).size, requestedArtifactIDs.length);
  assert.ok(requestedArtifactIDs.every((id) => artifactIDs.has(id)));
});

test('publication schemas exclude self-references and post-commit eligibility', () => {
  assert.equal(manifestSchema.additionalProperties, false);
  for (const forbidden of manifestSchema['x-forbidden-fields']) {
    assert.equal(manifestSchema.properties[forbidden], undefined);
  }
  assert.equal(manifestSchema.properties.parts.required, undefined);
  assert.deepEqual(
    manifestSchema.allOf[0].then.properties.parts.required,
    ['mysql', 'redis', 'object_storage', 'workspace', 'deployment_resources', 'secret_bundle'],
  );
  assert.equal(manifestSchema.properties.precommit_eligibility.properties.required_parts_complete.const, true);
  assert.equal(manifestSchema.properties.precommit_eligibility.properties.required_verifiers_complete.const, true);
  assert.deepEqual(
    artifactIndexSchema.properties.entries.items.properties.path.not.enum,
    ['artifact-index.json', 'manifest.json', '_COMMITTED', '_ACCEPTANCE'],
  );
  assert.equal(committedSchema.properties.marker_checksum, undefined);
  assert.equal(committedSchema.properties.object_checksum, undefined);
  assert.equal(acceptanceSchema.properties.payload.properties.acceptance_eligible, undefined);
  assert.equal(acceptanceSchema.properties.payload.properties.catalog_record, undefined);
  assert.ok(acceptanceSchema['x-forbidden-local-reasons'].includes('required_part_failed'));
});

test('external action persists exact immutable bytes without a replayable credential', () => {
  const action = publicationExamples.examples.external_action;
  const request = publicationExamples.examples.finalizer_request;
  const committed = publicationExamples.examples.committed;
  const canonicalBytes = Buffer.from(canonicalJSON(committed), 'utf8');
  const persistedBytes = Buffer.from(action.canonical_payload_base64, 'base64');

  assert.deepEqual(persistedBytes, canonicalBytes);
  assert.equal(action.content_length, canonicalBytes.length);
  assert.equal(action.payload_sha256, sha256(canonicalBytes));
  assert.equal(request.canonical_payload_base64, action.canonical_payload_base64);
  assert.equal(request.payload_sha256, action.payload_sha256);
  assert.equal(request.content_length, action.content_length);
  assert.equal(request.key, action.final_key);
  assert.equal(request.logical_action_hash, action.logical_action_hash);
  assert.equal(request.credential_envelope.allowed_key, action.final_key);
  assert.equal(request.credential_envelope.allowed_payload_sha256, action.payload_sha256);
  assert.equal(request.credential_envelope.allowed_content_length, action.content_length);
  assert.equal(request.credential_envelope.dispatch_generation, action.dispatch_generation);

  for (const forbidden of externalActionSchema['x-forbidden-fields']) {
    assert.equal(externalActionSchema.properties[forbidden], undefined);
    assert.equal(action[forbidden], undefined);
  }
  assert.equal(finalizerSchema.properties.credential_envelope.properties.opaque_credential.writeOnly, true);
  assert.match(request.credential_envelope.opaque_credential, /^synthetic-non-replayable-/);
});

test('acceptance signs payload only and keeps local reason codes canonical', () => {
  const acceptance = publicationExamples.examples.acceptance;
  const payloadBytes = Buffer.from(canonicalJSON(acceptance.payload), 'utf8');
  const changedSignature = { ...acceptance, signature: { ...acceptance.signature, value: 'different-synthetic-signature' } };

  assert.equal(acceptance.payload.local_reason_codes_hash, sha256(Buffer.from(canonicalJSON(acceptance.payload.local_reason_codes), 'utf8')));
  assert.equal(acceptance.payload.local_acceptance, true);
  assert.deepEqual(acceptance.payload.local_reason_codes, ['eligible']);
  assert.equal(acceptance.payload.signing_key.purpose, 'acceptance_record');
  assert.equal(acceptance.signature.key_purpose, 'acceptance_record');
  assert.equal(canonicalJSON(changedSignature.payload), payloadBytes.toString('utf8'));
  assert.notEqual(sha256(Buffer.from(canonicalJSON(changedSignature), 'utf8')), sha256(Buffer.from(canonicalJSON(acceptance), 'utf8')));
});

test('installation state preserves first-enable and matrix transition authority', () => {
  assert.equal(installationStateSchema.additionalProperties, false);
  assert.deepEqual(installationStateSchema.properties.monitoring_armed_reason.enum, ['none', 'deployment_required', 'previously_enabled']);
  assert.deepEqual(installationStateSchema.properties.matrix_key.enum, ['k8s-cluster', 'k3s-cluster', 'k8s-single-node', 'k3s-single-node']);
  assert.equal(installationStateSchema.allOf.length, 3);
  assert.ok(installationStateSchema['x-invariants'].some((item) => item.includes('first_enabled_at once')));
  assert.ok(installationStateSchema['x-invariants'].some((item) => item.includes('SYSTEM_BACKUP_ENABLED AND')));
  assert.ok(installationStateSchema['x-invariants'].some((item) => item.includes('SYSTEM_BACKUP_REQUIRED OR first_enabled_at IS NOT NULL')));
  assert.ok(installationStateSchema['x-invariants'].some((item) => item.includes('clients cannot supply')));
});

test('live schema-hash evidence cannot satisfy the gate before cleanup, registration and three-owner review', () => {
  const schema = schemaHashLiveEvidenceSchema;
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual([...schema.required].sort(), Object.keys(schema.properties).sort());
  for (const name of ['EvidenceReference', 'InventoryComparison', 'RecordsCleanup']) {
    assert.equal(schema.$defs[name].additionalProperties, false, `${name} must be closed`);
    assert.deepEqual([...schema.$defs[name].required].sort(), Object.keys(schema.$defs[name].properties).sort());
  }
  assert.deepEqual(schema.properties.status.enum, ['candidate', 'reviewed']);
  assert.equal(schema.allOf.length, 2);
  assert.equal(schema.allOf[0].then.properties.registered_evidence.type, 'null');
  assert.equal(schema.allOf[0].then.properties.approved_reviewers.maxItems, 0);
  assert.equal(schema.allOf[1].then.properties.inventory_comparison.allOf[1].properties.matched.const, true);
  assert.equal(schema.allOf[1].then.properties.records_cleanup.allOf[1].properties.status.const, 'verified');
  assert.equal(schema.allOf[1].then.properties.records_cleanup.allOf[1].properties.verified_absent.const, true);
  assert.equal(schema.allOf[1].then.properties.registered_evidence.$ref, '#/$defs/EvidenceReference');
  assert.equal(schema.allOf[1].then.properties.approved_reviewers.$ref, '#/$defs/AllOwners');
  assert.equal(schema['x-owner-boundaries'].D.includes('cleanup verification'), true);

  assert.equal(hashAlgorithms.schema_hash.live_evidence_schema, 'contracts/system-backup/v12/schema-hash-live-evidence.schema.json');
  assert.equal(hashAlgorithms.schema_hash.live_evidence_builder, 'scripts/system-backup-schema-hash-evidence.mjs');
  assert.deepEqual(schemaRegistrySchema.properties.schema_hash.required, ['algorithm', 'status', 'hash', 'evidence']);
  assert.equal(schemaRegistry.schema_hash.status, 'pending_live_evidence');
  assert.equal(schemaRegistry.schema_hash.hash, null);
  assert.equal(schemaRegistry.schema_hash.evidence, null);
  assert.equal(parseJSON(join(contractDir, 'contract-manifest.json')).freeze_gates.schema_hash_evidence_present, false);
});

test('compact tombstone separates permanent destructive keys from standard expiry', () => {
  assert.equal(compactTombstoneSchema.additionalProperties, false);
  assert.deepEqual(compactTombstoneSchema.properties.retention_class.enum, ['destructive_permanent', 'standard']);
  assert.equal(compactTombstoneSchema.allOf[0].then.properties.delete_after.type, 'null');
  assert.equal(compactTombstoneSchema.allOf[1].then.properties.delete_after.type, 'string');
  assert.ok(compactTombstoneSchema['x-invariants'].some((item) => item.includes('never deleted')));
  assert.ok(compactTombstoneSchema['x-unique-key'].includes('idempotency_key'));
});

test('verifier shell owns aggregation but leaves A/B/C check registries pending', () => {
  assert.equal(verifierSchema.additionalProperties, false);
  assert.equal(verifierSchema.properties.status, undefined);
  assert.equal(verifierSchema.properties.warnings, undefined);
  assert.deepEqual(verifierSchema['x-aggregate-order'], ['failed', 'warning', 'passed', 'skipped']);
  for (const owner of ['A', 'B', 'C']) {
    assert.equal(verifierSchema['x-owner-check-registries'][owner].status, 'pending_owner_submission');
  }
  assert.equal(verifierSchema['x-owner-check-registries'].D.status, 'draft');
  assert.equal(verifierSchema.$defs.Check.additionalProperties, false);
  assert.equal(verifierSchema.$defs.Check.properties.expected['x-owner-schema-required'], true);
});

test('metrics registry shape rejects high-cardinality labels and requires complete alert metadata', () => {
  const allowed = new Set(metricsAlertSchema.$defs.AllowedLabel.enum);
  const forbidden = metricsAlertSchema['x-forbidden-labels'];
  assert.ok(forbidden.every((label) => !allowed.has(label)));
  assert.equal(metricsAlertSchema.properties.metrics.items.$ref, '#/$defs/Metric');
  assert.equal(metricsAlertSchema.properties.alerts.items.$ref, '#/$defs/Alert');
  assert.deepEqual(metricsAlertSchema.$defs.Alert.required, ['id', 'expression_language', 'expression', 'severity', 'for_seconds', 'threshold_source', 'dedupe_key', 'recovery_condition', 'missing_series', 'counter_reset', 'runbook', 'profiles', 'fixed_clock_cases']);
  assert.equal(metricsAlertSchema['x-registry-instance'], 'metrics-alert-registry.json');
  assert.ok(metricsAlertSchema['x-freeze-blockers'].some((item) => item.includes('production-selected')));
  assert.ok(metricsAlertSchema['x-freeze-blockers'].some((item) => item.includes('A/B cross-review')));
});

test('D-owned metrics registry materializes every section-15 metric exactly once', () => {
  const plan = readFileSync(join(root, 'docs/system-backup-restore-division-plan.md'), 'utf8');
  const markers = [
    '任务/协调核心集为：',
    '数据/artifact 核心集为：',
    '运维/API 核心集为：',
    'v12补充且不得由通用request counter替代的安全/新鲜度指标为：',
    'Status-relay核心集为：',
    '依赖保护窗口另输出',
    '告警表达所需配置 gauge 固定为：',
    '队列不可变预算指标为：',
    '补充队列类别指标为：',
  ];
  const expected = [];
  for (const marker of markers) {
    const line = plan.split(/\r?\n/).find((candidate) => candidate.includes(marker));
    assert.ok(line, `missing metric paragraph ${marker}`);
    for (const match of line.matchAll(/`([^`]+)`/g)) {
      const parsed = match[1].match(/^([a-z][a-z0-9_]+)(?:\{[^}]+\})?(?:=[^`]*)?$/);
      if (parsed && parsed[1] !== 'clawmanager_system_backup_') expected.push(`clawmanager_system_backup_${parsed[1]}`);
    }
  }
  const expectedUnique = [...new Set(expected)];
  const actual = metricsAlertRegistry.metrics.map((metric) => metric.name);
  assert.equal(expectedUnique.length, 210);
  assert.equal(new Set(actual).size, actual.length);
  assert.deepEqual(actual, expectedUnique);
  assert.equal(metricsAlertRegistry.source.metric_count, actual.length);
  assert.equal(metricsAlertRegistry.source.alert_count, metricsAlertRegistry.alerts.length);

  const allowed = new Set(metricsAlertSchema.$defs.AllowedLabel.enum);
  const forbidden = new Set(metricsAlertSchema['x-forbidden-labels']);
  for (const metric of metricsAlertRegistry.metrics) {
    assert.deepEqual(Object.keys(metric).sort(), Object.keys(metricsAlertSchema.$defs.Metric.properties).sort(), `${metric.name} is not closed`);
    assert.match(metric.name, /^clawmanager_system_backup_[a-z0-9_]+$/);
    assert.ok(metric.help.length >= 16);
    assert.equal(new Set(metric.labels).size, metric.labels.length, `${metric.name} repeats a label`);
    assert.ok(metric.labels.every((label) => allowed.has(label) && !forbidden.has(label)), `${metric.name} uses a forbidden label`);
    if (metric.type === 'histogram') {
      assert.ok(metric.buckets.length > 0, `${metric.name} needs buckets`);
      assert.ok(metric.buckets.every((bucket, index) => bucket > 0 && (index === 0 || bucket > metric.buckets[index - 1])), `${metric.name} buckets must increase`);
      assert.equal(metric.aggregation, 'observe');
      assert.equal(metric.no_data, 'not_emitted');
    } else {
      assert.deepEqual(metric.buckets, []);
    }
  }

  const byName = new Map(metricsAlertRegistry.metrics.map((metric) => [metric.name, metric]));
  assert.equal(byName.get('clawmanager_system_backup_task_transitions_total').type, 'counter');
  assert.equal(byName.get('clawmanager_system_backup_task_status_duration_seconds').type, 'histogram');
  assert.equal(byName.get('clawmanager_system_backup_task_queue_age_seconds').type, 'gauge');
  assert.equal(byName.get('clawmanager_system_backup_controller_last_success_timestamp_seconds').no_data, 'timestamp_zero');
  assert.equal(byName.get('clawmanager_system_backup_dependency_health').aggregation, 'one_hot_worst_health');
  assert.equal(byName.get('clawmanager_system_backup_provider_capability_health').aggregation, 'one_hot_worst_capability');
  assert.deepEqual(byName.get('clawmanager_system_backup_dependency_health').labels, ['dependency_kind', 'health_state']);
  assert.deepEqual(byName.get('clawmanager_system_backup_configured_task_deadline_seconds').labels, ['task_type']);
  assert.deepEqual(byName.get('clawmanager_system_backup_configured_operation_deadline_seconds').labels, ['operation_type']);
  assert.deepEqual(byName.get('clawmanager_system_backup_control_database_available_bytes').labels, []);
  assert.deepEqual(byName.get('clawmanager_system_backup_control_metadata_size_estimated').labels, []);
});

test('D-owned alert registry closes section-15 defaults and profile behavior', () => {
  const alerts = metricsAlertRegistry.alerts;
  const byID = new Map(alerts.map((alert) => [alert.id, alert]));
  const metricNames = new Set(metricsAlertRegistry.metrics.map((metric) => metric.name));
  const allowedLabels = new Set(metricsAlertSchema.$defs.AllowedLabel.enum);
  assert.equal(alerts.length, 99);
  assert.equal(byID.size, alerts.length);
  assert.equal(metricsAlertRegistry.source.alert_count, alerts.length);

  for (const alert of alerts) {
    assert.deepEqual(Object.keys(alert).sort(), Object.keys(metricsAlertSchema.$defs.Alert.properties).sort(), `${alert.id} is not closed`);
    assert.ok(alert.profiles.length > 0);
    assert.equal(new Set(alert.profiles).size, alert.profiles.length, `${alert.id} repeats a profile`);
    assert.ok(alert.dedupe_key.every((label) => allowedLabels.has(label)), `${alert.id} uses an unknown dedupe label`);
    assert.match(alert.runbook, /^system-backup\/[a-z0-9][a-z0-9-]*$/);
    const expectedCaseNames = alert.for_seconds > 0 ? ['recovered', 'before_for', 'at_for'] : ['recovered', 'at_for'];
    assert.deepEqual(alert.fixed_clock_cases.map((item) => item.case), expectedCaseNames, `${alert.id} fixed-clock coverage drifted`);
    for (const item of alert.fixed_clock_cases) {
      assert.deepEqual(Object.keys(item).sort(), Object.keys(metricsAlertSchema.$defs.AlertFixedClockCase.properties).sort());
      const actualFiring = item.condition_result
        && item.condition_true_since_unix_seconds !== null
        && item.clock_unix_seconds - item.condition_true_since_unix_seconds >= alert.for_seconds;
      assert.equal(actualFiring, item.expected_firing, `${alert.id}/${item.case} fixed-clock result drifted`);
    }
    if (alert.expression_language === 'promql') {
      const refs = alert.expression.match(/clawmanager_system_backup_[a-z0-9_]+/g) ?? [];
      for (const ref of refs) assert.ok(metricNames.has(ref), `${alert.id} references unregistered metric ${ref}`);
      assert.doesNotMatch(alert.expression, /\bmax\(/, `${alert.id} must use valid scalar/vector PromQL instead of a two-argument max`);
      if (alert.expression.includes('increase(')) assert.equal(alert.counter_reset, 'prometheus_increase');
    } else {
      assert.equal(alert.counter_reset, 'persisted_state_not_reset_by_restart');
    }
  }

  const downleveled = [
    'eligible-recovery-point-missing',
    'eligible-recovery-point-rpo-exceeded',
    'recovery-point-failure-domain-shortage',
    'promotion-baseline-missing',
    'task-queue-age-warning',
    'task-queue-age-critical',
    'operation-queue-age-warning',
    'operation-queue-age-critical',
    'preflight-queue-age-warning',
    'preflight-queue-age-critical',
    'artifact-verify-queue-age-warning',
    'artifact-verify-queue-age-critical',
    'acceptance-consecutive-anomalies',
    'staging-capacity-warning',
    'staging-capacity-critical',
    'control-metadata-capacity-warning',
  ];
  for (const id of downleveled) {
    const production = byID.get(`${id}.production`);
    const development = byID.get(`${id}.development`);
    assert.ok(production, `missing production profile for ${id}`);
    assert.ok(development, `missing development profile for ${id}`);
    assert.deepEqual(production.profiles, ['production']);
    assert.deepEqual(development.profiles, ['development']);
    assert.equal(development.severity, 'info');
    assert.equal(development.expression, production.expression);
    assert.equal(development.for_seconds, production.for_seconds);
  }

  assert.equal(byID.get('backup-disabled-after-monitoring-armed.warning').for_seconds, 900);
  assert.equal(byID.get('backup-disabled-after-monitoring-armed.critical').for_seconds, 86400);
  assert.equal(byID.get('recovery-point-failure-domain-shortage.production').for_seconds, 300);
  assert.match(byID.get('task-queue-age-warning.production').expression, />= 0\.5$/);
  assert.match(byID.get('task-queue-age-critical.production').expression, />= 0\.9$/);
  assert.match(byID.get('gate-wait-near-timeout').expression, /\* 0\.8$/);
  assert.match(byID.get('capture-hold-near-limit').expression, /\* 0\.8$/);
  assert.match(byID.get('catalog-import-verification-pending-warning').expression, /> 900$/);
  assert.match(byID.get('catalog-import-verification-pending-critical').expression, /> 3600$/);
  assert.match(byID.get('confirmation-rejections-warning').expression, />= 5$/);
  assert.match(byID.get('confirmation-rejections-critical').expression, />= 20$/);
  assert.equal(byID.get('acceptance-consecutive-anomalies.production').expression_language, 'controller_state');
  assert.equal(byID.get('provider-proof-issuer-key-expiring').expression_language, 'controller_state');
  assert.ok(['credential', 'ca', 'catalog_credential', 'kek', 'signing_key', 'attestation', 'evidence'].every((name) => metricNames.has(`clawmanager_system_backup_${name}_expiry_timestamp_seconds`)));
});

test('D alert expressions preserve labeled series when joined to singleton guards and config', () => {
  const byID = new Map(metricsAlertRegistry.alerts.map((alert) => [alert.id, alert]));
  for (const id of [
    'backup-disabled-after-monitoring-armed.warning',
    'backup-disabled-after-monitoring-armed.critical',
    'eligible-recovery-point-missing.production',
    'eligible-recovery-point-rpo-exceeded.production',
    'recovery-point-failure-domain-shortage.production',
    'promotion-baseline-missing.production',
    'external-action-reconcile-warning',
    'external-action-reconcile-critical',
    'orphan-gc-stale',
  ]) assert.match(byID.get(id).expression, /and on\(\)/, `${id} must match its singleton guard without dropping labeled series`);
  for (const id of [
    'eligible-recovery-point-rpo-exceeded.production',
    'gate-wait-near-timeout',
    'gate-wait-timeout',
    'capture-hold-near-limit',
    'capture-hold-limit',
    'mutation-lease-blocked',
    'finalization-unknown-over-grace',
    'provider-capability-refresh-stale',
  ]) assert.match(byID.get(id).expression, /scalar\(clawmanager_system_backup_configured_/, `${id} must broadcast one global config sample as a scalar`);
  for (const [kind, id, labels] of [
    ['task', 'task', ['task_type', 'task_purpose']],
    ['operation', 'operation', ['operation_type']],
    ['preflight', 'preflight', ['preflight_mode']],
    ['artifact_verify', 'artifact-verify', ['verification_scope']],
  ]) {
    for (const suffix of ['warning.production', 'critical.production']) {
      assert.match(byID.get(`${id}-queue-age-${suffix}`).expression,
        new RegExp(`^clawmanager_system_backup_${kind}_queue_deadline_utilization_ratio >= `));
    }
    const utilization = metricsAlertRegistry.metrics.find((item) => item.name === `clawmanager_system_backup_${kind}_queue_deadline_utilization_ratio`);
    assert.equal(utilization.type, 'gauge');
    assert.equal(utilization.aggregation, 'max');
    assert.equal(utilization.no_data, 'zero');
    assert.match(utilization.help, /immutable creation-time deadline window/);
    assert.deepEqual(utilization.labels, labels);
  }
});

test('D queue budget reader is bound to registered low-cardinality metric names', () => {
  const source = readFileSync(join(root, 'backend/internal/systembackupcontroller/sql_queue_budget.go'), 'utf8');
  const names = new Set(metricsAlertRegistry.metrics.map((metric) => metric.name));
  for (const name of [
    'clawmanager_system_backup_task_queue_deadline_utilization_ratio',
    'clawmanager_system_backup_operation_queue_deadline_utilization_ratio',
    'clawmanager_system_backup_preflight_queue_deadline_utilization_ratio',
    'clawmanager_system_backup_artifact_verify_queue_deadline_utilization_ratio',
  ]) {
    assert.ok(names.has(name));
    assert.match(source, new RegExp(name));
  }
  assert.match(source, /ReadOnly: true, Isolation: sql\.LevelRepeatableRead/);
  assert.match(source, /status = 'pending'/);
  assert.doesNotMatch(source, /SELECT[^\n]*public_id|SELECT[^\n]*credential/i);
});

test('D controller queue metrics outlet uses registered HELP and leader-only fail-closed scrape', () => {
  const outlet = readFileSync(join(root, 'backend/internal/systembackupcontroller/metrics_http.go'), 'utf8');
  const main = readFileSync(join(root, 'backend/cmd/system-backup-controller/main.go'), 'utf8');
  for (const metric of metricsAlertRegistry.metrics.filter((item) => item.name.endsWith('_queue_deadline_utilization_ratio'))) {
    assert.match(outlet, new RegExp(metric.name));
    assert.ok(outlet.includes(`help: "${metric.help}"`), `${metric.name} HELP drifted`);
    assert.equal(metric.type, 'gauge');
  }
  assert.match(outlet, /if !h\.Leader\(\)/);
  assert.match(outlet, /if !h\.Ready\(\)/);
  assert.match(outlet, /renderQueueBudgetMetrics\(samples\)/);
  assert.match(main, /mux\.Handle\("\/metrics", metrics\[0\]\)/);
  assert.match(main, /Collector:\s+systembackupcontroller\.SQLQueueBudgetReader\{DB: sqlDB\}/);
  assert.match(main, /Leader:\s+status\.leading\.Load/);
});

test('D controller self telemetry is wired to the loop and remains leader-only', () => {
  const telemetry = readFileSync(join(root, 'backend/internal/systembackupcontroller/controller_telemetry.go'), 'utf8');
  const outlet = readFileSync(join(root, 'backend/internal/systembackupcontroller/metrics_http.go'), 'utf8');
  const main = readFileSync(join(root, 'backend/cmd/system-backup-controller/main.go'), 'utf8');
  for (const suffix of [
    'controller_leader_changes_total',
    'controller_reconcile_total',
    'controller_reconcile_seconds',
    'controller_last_success_timestamp_seconds',
  ]) {
    const metric = metricsAlertRegistry.metrics.find((item) => item.name === `clawmanager_system_backup_${suffix}`);
    assert.ok(metric, `${suffix} missing from the metrics registry`);
    assert.ok(telemetry.includes(metric.name), `${suffix} not exported`);
    assert.ok(telemetry.includes(metric.help), `${suffix} HELP drifted`);
  }
  assert.match(main, /Controller:\s+controllerTelemetry/);
  assert.match(main, /controllerTelemetry\.ObserveReconcile\(result, time\.Now\(\)\)/);
  assert.match(main, /controllerTelemetry\.LeaderStarted\(\)/);
  assert.match(outlet, /if !h\.Leader\(\) \{\s*w\.WriteHeader\(http\.StatusOK\)\s*return\s*\}\s*if !h\.Ready\(\) \{\s*http\.Error\(w, "metrics unavailable", http\.StatusServiceUnavailable\)\s*return\s*\}\s*if h\.Controller != nil/);
});

test('D controller-state predicates cover the four non-PromQL registry rules', () => {
  const source = readFileSync(join(root, 'backend/internal/systembackupcontroller/controller_state_alerts.go'), 'utf8');
  const stateReader = readFileSync(join(root, 'backend/internal/systembackupcontroller/sql_acceptance_alert_state.go'), 'utf8');
  const sequence = readFileSync(join(root, 'backend/internal/systembackupcontroller/acceptance_alert_sequence.go'), 'utf8');
  const sequenceTx = readFileSync(join(root, 'backend/internal/systembackupcontroller/acceptance_alert_transaction.go'), 'utf8');
  const stateRules = metricsAlertRegistry.alerts.filter((rule) => rule.expression_language === 'controller_state');
  assert.equal(stateRules.length, 4);
  for (const rule of stateRules) {
    const ruleStem = rule.id.replace(/\.(production|development)$/, '');
    assert.ok(source.includes(ruleStem), `${rule.id} is missing from the D predicate core`);
    assert.equal(rule.for_seconds, 0, `${rule.id} must be immediate`);
  }
  assert.match(source, /!present \|\| count >= 3/);
  assert.match(source, /candidate\.Age >= threshold/);
  assert.match(source, /issuer\.ExpiresAt\.Sub\(snapshot\.Now\) < threshold/);
  assert.match(source, /proofKeyExpiring := snapshot\.ProviderProofIssuer == nil/);
  assert.match(stateReader, /acceptanceAnomalyStateKey = "acceptance-consecutive-anomalies"/);
  assert.match(stateReader, /task_purpose = 'acceptance'/);
  assert.match(stateReader, /LIMIT 3/);
  assert.match(sequence, /outcome\.Purpose == "functional_test" \|\| outcome\.Status == "canceled"/);
  assert.match(sequence, /outcome\.Eligible \{/);
  assert.match(sequence, /next\.Count = 0/);
  assert.match(sequence, /next\.Count < math\.MaxUint32/);
  assert.match(sequence, /outcome\.Status == "succeeded" && outcome\.Purpose == "acceptance" && !outcome\.EligibilityDecided/);
  for (const required of ['db.BeginTx(ctx, nil)', 'terminalCAS(ctx, tx)', 'result.RowsAffected()', 'INSERT INTO system_backup_events', "'task_status_changed'", 'eventRows != 1', 'updateAcceptanceSequenceInTx(ctx, tx', 'tx.Commit()', 'defer tx.Rollback()', 'SELECT UTC_TIMESTAMP(6)', 'FOR UPDATE', 'origin_installation_id = ? AND public_id = ?', 'previousVersion != expectedRowVersion', 'actualConfigVersion != configVersion', 'actualRowVersion != expectedRowVersion+1']) {
    assert.ok(sequenceTx.includes(required), `acceptance transaction boundary lacks ${required}`);
  }
  assert.ok(sequenceTx.indexOf('terminalCAS(ctx, tx)') < sequenceTx.indexOf('updateAcceptanceSequenceInTx(ctx, tx'), 'alert sequence must follow successful terminal CAS');
});

test('D-owned dependency and provider capability records are closed and fail closed', () => {
  const defs = dependencyProviderCapabilitySchema.$defs;
  for (const name of ['EvidenceReference', 'OwnerTargetReference', 'DependencyHealthRecord', 'DependencyHealthProjection', 'ProviderCapabilityRecord', 'ProviderCapabilityProjection']) {
    assert.equal(defs[name].additionalProperties, false, `${name} must be closed`);
    assert.deepEqual([...defs[name].required].sort(), Object.keys(defs[name].properties).sort(), `${name} must require every property`);
  }
  assert.deepEqual(defs.DependencyKind.enum, ['artifact_credential', 'ca', 'kek', 'signing', 'catalog', 'evidence', 'attestation']);
  assert.deepEqual(defs.ObservedHealth.enum, ['healthy', 'degraded', 'unknown']);
  assert.deepEqual(defs.EffectiveHealth.enum, ['healthy', 'degraded', 'unknown', 'stale']);
  assert.deepEqual(defs.CapabilityStatus.enum, ['supported', 'degraded', 'unsupported']);
  assert.deepEqual(defs.EffectiveCapabilityState.enum, ['supported', 'degraded', 'unsupported', 'unknown']);
  assert.deepEqual(defs.ProviderRole.enum, ['artifact', 'catalog', 'evidence']);
  assert.equal(defs.OwnerTargetReference.allOf.length, 4);
  assert.equal(defs.DependencyHealthRecord.allOf[0].then.properties.health_reason.const, 'none');
  assert.equal(defs.DependencyHealthRecord.allOf[1].then.properties.observed_checksum.type, 'null');
  assert.deepEqual(defs.DependencyHealthRecord['x-unique-key'], ['dependency_kind', 'identity_hash', 'identity_version', 'owner.owner_target_type', 'owner.owner_target_public_id']);
  assert.equal(defs.ProviderCapabilityRecord.allOf.length, 5);
  assert.equal(defs.ProviderCapabilityRecord.allOf[3].then.properties.capability_reason_code.const, 'none');
  assert.deepEqual(defs.ProviderCapabilityRecord['x-unique-key'], ['provider_role', 'provider_identity_hash', 'provider_ref_version', 'capability_code']);
  assert.deepEqual(dependencyProviderCapabilitySchema['x-capability-groups'], {
    absence_proof_any_of: ['strong_read_after_write', 'versioned_absence_proof'],
    full_discovery_any_of: ['provider_snapshot_listing', 'inventory_manifest_listing'],
  });

  const union = new Set([
    ...defs.ArtifactCapabilityCode.enum,
    ...defs.CatalogCapabilityCode.enum,
    ...defs.EvidenceCapabilityCode.enum,
  ]);
  assert.deepEqual([...defs.CapabilityCode.enum].sort(), [...union].sort());
  assert.match(dependencyProviderCapabilitySchema['x-owner-boundaries'].A, /registered evidence/);
  assert.match(dependencyProviderCapabilitySchema['x-owner-boundaries'].B, /not defined here/);
  assert.match(dependencyProviderCapabilitySchema['x-owner-boundaries'].C, /C-owned/);
  const serialized = JSON.stringify(dependencyProviderCapabilitySchema);
  assert.doesNotMatch(serialized, /"(?:uri|location|credential_bytes|secret|token|expected|actual)"\s*:/i);
});

test('D-owned dependency and capability fixtures prove expiry and exact-role projections', () => {
  const defs = dependencyProviderCapabilitySchema.$defs;
  const dependency = dependencyProviderCapabilityExamples.dependency_health_projection;
  assert.deepEqual(Object.keys(dependency).sort(), Object.keys(defs.DependencyHealthProjection.properties).sort());
  assert.deepEqual(Object.keys(dependency.record).sort(), Object.keys(defs.DependencyHealthRecord.properties).sort());
  assert.deepEqual(Object.keys(dependency.record.owner).sort(), Object.keys(defs.OwnerTargetReference.properties).sort());
  assert.equal(new Date(dependency.evaluated_at) >= new Date(dependency.record.expires_at) ? 'stale' : dependency.record.observed_health, dependency.effective_health);

  const allowedByRole = {
    artifact: new Set(defs.ArtifactCapabilityCode.enum),
    catalog: new Set(defs.CatalogCapabilityCode.enum),
    evidence: new Set(defs.EvidenceCapabilityCode.enum),
  };
  assert.deepEqual(dependencyProviderCapabilityExamples.provider_capability_records.map((record) => record.provider_role), ['artifact', 'catalog', 'evidence']);
  for (const record of dependencyProviderCapabilityExamples.provider_capability_records) {
    assert.deepEqual(Object.keys(record).sort(), Object.keys(defs.ProviderCapabilityRecord.properties).sort());
    assert.ok(allowedByRole[record.provider_role].has(record.capability_code));
    assert.equal(record.status === 'supported', record.capability_reason_code === 'none');
    assert.equal(record.claim_owner === null, record.claim_expires_at === null);
    if (record.evidence !== null) assert.deepEqual(Object.keys(record.evidence).sort(), Object.keys(defs.EvidenceReference.properties).sort());
  }

  const missing = dependencyProviderCapabilityExamples.missing_provider_capability_projection;
  assert.deepEqual(Object.keys(missing).sort(), Object.keys(defs.ProviderCapabilityProjection.properties).sort());
  assert.equal(missing.record, null);
  assert.equal(missing.effective_state, 'unknown');
  assert.equal(missing.effective_reason_code, 'missing');
  const serialized = JSON.stringify(dependencyProviderCapabilityExamples);
  assert.doesNotMatch(serialized, /:\/\//);
  assert.doesNotMatch(serialized, /"(?:password|secret|token|credential_bytes|private_key|authorization|uri|location)"\s*:/i);
});

test('D-owned control-evidence sidecar is a closed encrypted summary envelope', () => {
  const defs = controlEvidenceSidecarSchema.$defs;
  assert.equal(controlEvidenceSidecarSchema.additionalProperties, false);
  assert.deepEqual([...controlEvidenceSidecarSchema.required].sort(), Object.keys(controlEvidenceSidecarSchema.properties).sort());
  for (const name of ['EvidenceReference', 'ControlExclusionProof', 'RedactionProof', 'RecordGroupSummary', 'RecordGroups', 'OwnerEvidenceSection', 'OwnerSections']) {
    assert.equal(defs[name].additionalProperties, false, `${name} must be closed`);
    assert.deepEqual([...defs[name].required].sort(), Object.keys(defs[name].properties).sort(), `${name} must require every property`);
  }
  assert.deepEqual(defs.RecordGroupName.enum, ['task_terminal', 'operation_terminal', 'event', 'audit', 'promotion', 'dependency_health', 'provider_capability', 'alert_state', 'installation_state']);
  assert.deepEqual(Object.keys(defs.RecordGroups.properties), defs.RecordGroupName.enum);
  for (const [name, schema] of Object.entries(defs.RecordGroups.properties)) assert.equal(schema.allOf[1].properties.group.const, name);
  assert.deepEqual(Object.keys(defs.OwnerSections.properties), ['A', 'B', 'C', 'D']);
  for (const [owner, schema] of Object.entries(defs.OwnerSections.properties)) assert.equal(schema.allOf[1].properties.owner.const, owner);
  assert.equal(defs.RecordGroupSummary.allOf[0].then.properties.first_recorded_at.type, 'null');
  assert.equal(defs.RecordGroupSummary.allOf[0].then.properties.last_recorded_at.type, 'null');
  assert.equal(defs.OwnerEvidenceSection.allOf[0].then.properties.reason.const, 'none');
  assert.equal(defs.OwnerEvidenceSection.allOf[1].then.properties.verifier_summary_hash.type, 'null');
  assert.equal(controlEvidenceSidecarSchema['x-artifact-path'], 'control/evidence.json.enc');
  assert.match(controlEvidenceSidecarSchema['x-encryption'], /encrypted/);
  assert.match(controlEvidenceSidecarSchema['x-checksum-boundary'], /no self-checksum/);
  assert.match(controlEvidenceSidecarSchema['x-restore-behavior'], /never imports/);
  assert.equal(controlEvidenceSidecarSchema.properties.checksum, undefined);
  assert.match(controlEvidenceSidecarSchema['x-owner-boundaries'].A, /only hashes, counts/);
  assert.match(controlEvidenceSidecarSchema['x-owner-boundaries'].B, /not embedded/);
  assert.match(controlEvidenceSidecarSchema['x-owner-boundaries'].C, /not embedded/);

  assert.deepEqual(manifestSchema.properties.control_evidence.required, ['path', 'schema_version', 'checksum']);
  assert.equal(manifestSchema.properties.control_evidence.properties.schema_version.const, 'system-backup-control-evidence.v1');
  assert.equal(manifestSchema.properties.control_evidence.properties.path.const, controlEvidenceSidecarSchema['x-artifact-path']);
});

test('control-evidence example keeps A/B/C payloads external and binds only registered evidence', () => {
  const defs = controlEvidenceSidecarSchema.$defs;
  const example = controlEvidenceSidecarExample.example;
  assert.deepEqual(Object.keys(example).sort(), Object.keys(controlEvidenceSidecarSchema.properties).sort());
  assert.deepEqual(Object.keys(example.control_exclusion).sort(), Object.keys(defs.ControlExclusionProof.properties).sort());
  assert.deepEqual(Object.keys(example.redaction_proof).sort(), Object.keys(defs.RedactionProof.properties).sort());
  assert.deepEqual(Object.keys(example.record_groups), defs.RecordGroupName.enum);
  for (const [group, summary] of Object.entries(example.record_groups)) {
    assert.deepEqual(Object.keys(summary).sort(), Object.keys(defs.RecordGroupSummary.properties).sort());
    assert.equal(summary.group, group);
    assert.equal(summary.record_count === 0, summary.first_recorded_at === null && summary.last_recorded_at === null);
    for (const evidence of summary.evidence_refs) assert.deepEqual(Object.keys(evidence).sort(), Object.keys(defs.EvidenceReference.properties).sort());
  }
  assert.deepEqual(Object.keys(example.owner_sections), ['A', 'B', 'C', 'D']);
  for (const owner of ['A', 'B', 'C']) {
    const section = example.owner_sections[owner];
    assert.equal(section.owner, owner);
    assert.equal(section.status, 'incomplete');
    assert.equal(section.reason, 'evidence_missing');
    assert.equal(section.verifier_summary_hash, null);
    assert.deepEqual(section.evidence_refs, []);
  }
  assert.equal(example.owner_sections.D.status, 'complete');
  assert.equal(example.owner_sections.D.reason, 'none');
  assert.ok(example.owner_sections.D.evidence_refs.length > 0);
  assert.equal(example.redaction_proof.applied, true);
  assert.equal(example.redaction_proof.rejected_records, 0);
  assert.equal(example.warnings[0].disqualifying, true);
  const serialized = JSON.stringify(controlEvidenceSidecarExample);
  assert.doesNotMatch(serialized, /:\/\//);
  assert.doesNotMatch(serialized, /"(?:password|secret|token|credential|private_key|authorization|uri|location|record_body|audit_body|check_result)"\s*:/i);
});

test('D-owned evidence, chunk and log persistence contract is closed and fail-closed', () => {
  const defs = evidenceChunkLogSchema.$defs;
  for (const name of ['EvidenceReference', 'OwnerTargetReference', 'TypedStorageReference', 'EncryptionEnvelopeReference', 'EvidenceRecord', 'EvidenceChunk', 'TaskReference', 'LogChunk']) {
    assert.equal(defs[name].additionalProperties, false, `${name} must be closed`);
    assert.deepEqual([...defs[name].required].sort(), Object.keys(defs[name].properties).sort(), `${name} must require every property`);
  }

  const ownerTypes = ['backup', 'backup_staging', 'external_action', 'drill', 'restore_resource', 'preflight', 'artifact_verify', 'catalog_scan', 'catalog_record', 'catalog_import', 'prune_run', 'promotion', 'system'];
  assert.deepEqual(defs.OwnerTargetReference.properties.owner_target_type.enum, ownerTypes);
  assert.equal(defs.OwnerTargetReference.allOf.length, ownerTypes.length);
  assert.deepEqual(defs.EvidenceType.enum, ['verifier_report', 'cleanup_result', 'provider_presence_proof', 'provider_absence_proof', 'provider_deletion_receipt', 'ownership_proof', 'capability_snapshot', 'catalog_scan_receipt', 'failure_domain_attestation', 'promotion_release_bundle', 'job_log_chunk', 'diagnostic']);
  assert.deepEqual(defs.StorageState.enum, ['inline', 'pending', 'write_unknown', 'write_failed', 'ready', 'deleting', 'delete_failed', 'deleted']);
  assert.deepEqual(defs.EvidenceFailureCode.enum, ['none', 'redaction_failed', 'capacity_exceeded', 'provider_unavailable', 'permission_denied', 'checksum_mismatch', 'encryption_key_unavailable', 'deadline_exceeded', 'internal']);
  assert.deepEqual(defs.MediaType.enum, ['application/json', 'application/jose', 'application/cbor', 'text/plain']);
  assert.deepEqual(defs.Encryption.enum, ['none', 'envelope_v1']);
  assert.deepEqual(defs.RedactionClassification.enum, ['public', 'internal', 'confidential', 'sensitive']);
  assert.deepEqual(defs.ObservedHealth.enum, ['healthy', 'degraded', 'unknown']);

  assert.equal(defs.TypedStorageReference.properties.provider_role.const, 'evidence');
  assert.match(defs.TypedStorageReference['x-invariant'], /server-derived/);
  assert.equal(defs.EvidenceRecord.allOf.length, 9);
  assert.deepEqual(defs.EvidenceRecord.allOf[0].if.properties.storage_state.enum, ['inline', 'pending', 'ready', 'deleting', 'deleted']);
  assert.equal(defs.EvidenceRecord.allOf[0].then.properties.evidence_failure_code.const, 'none');
  assert.deepEqual(defs.EvidenceRecord.allOf[1].then.properties.evidence_failure_code.enum, ['provider_unavailable', 'deadline_exceeded']);
  assert.equal(defs.EvidenceRecord.allOf[2].then.not.properties.evidence_failure_code.const, 'none');
  assert.deepEqual(defs.EvidenceRecord.allOf[3].then.properties.evidence_failure_code.enum, ['provider_unavailable', 'permission_denied', 'checksum_mismatch', 'deadline_exceeded', 'internal']);
  assert.equal(defs.EvidenceRecord.allOf[4].then.properties.storage_ref.type, 'null');
  assert.equal(defs.EvidenceRecord.allOf[4].then.properties.chunk_count.const, 0);
  assert.equal(defs.EvidenceRecord.allOf[4].else.properties.inline_payload_base64.type, 'null');
  assert.deepEqual(defs.EvidenceRecord.allOf[5].if.properties.storage_state.enum, ['ready', 'deleting', 'delete_failed', 'deleted']);
  assert.equal(defs.EvidenceRecord.allOf[5].then.properties.plaintext_chunk_size_bytes.const, 1048576);
  assert.equal(defs.EvidenceRecord.allOf[5].then.properties.chunk_count.minimum, 1);
  assert.equal(defs.EvidenceRecord.allOf[6].then.properties.encryption_envelope.type, 'null');
  assert.equal(defs.EvidenceRecord.allOf[6].else.properties.encryption_envelope.$ref, '#/$defs/EncryptionEnvelopeReference');
  assert.deepEqual(defs.EvidenceRecord.allOf[7].if.properties.redaction_classification.enum, ['confidential', 'sensitive']);
  assert.equal(defs.EvidenceRecord.allOf[7].then.properties.encryption.const, 'envelope_v1');
  assert.equal(defs.EvidenceRecord.allOf[8].then.properties.claim_expires_at.type, 'null');
  assert.equal(defs.EvidenceRecord.allOf[8].else.properties.claim_expires_at.type, 'string');
  assert.deepEqual(defs.EvidenceRecord['x-state-transitions'], ['pending->ready|write_unknown|write_failed', 'write_unknown->ready|write_failed', 'ready->deleting', 'deleting->deleted|delete_failed', 'delete_failed->deleting']);

  assert.equal(defs.EvidenceChunk.properties.plaintext_length.maximum, 1048576);
  assert.deepEqual(defs.EvidenceChunk['x-unique-key'], ['evidence_public_id', 'chunk_index']);
  assert.ok(defs.EvidenceChunk['x-invariants'].some((item) => item.includes('contiguous')));
  assert.ok(defs.EvidenceChunk['x-invariants'].some((item) => item.includes('JCS')));
  assert.deepEqual(defs.TaskReference.properties.task_type.enum, ['backup', 'drill', 'preflight', 'artifact_verify']);
  assert.equal(defs.TaskReference.allOf.length, 4);
  assert.deepEqual(defs.LogIngestStatus.enum, ['pending', 'ready', 'failed']);
  assert.deepEqual(defs.LogIngestFailureCode.enum, ['none', 'source_unavailable', 'redaction_failed', 'evidence_write_failed', 'sequence_conflict', 'capacity_exceeded', 'internal']);
  assert.equal(defs.LogChunk.allOf.length, 3);
  assert.equal(defs.LogChunk.properties.line_count.maximum, 1000);
  assert.equal(defs.LogChunk.allOf[0].then.properties.log_ingest_failure_code.const, 'none');
  assert.equal(defs.LogChunk.allOf[1].then.properties.line_count.const, 0);
  assert.equal(defs.LogChunk.allOf[1].then.properties.redacted_evidence.type, 'null');
  assert.equal(defs.LogChunk.allOf[2].then.properties.line_count.minimum, 1);
  assert.equal(defs.LogChunk.allOf[2].then.properties.redacted_evidence.$ref, '#/$defs/EvidenceReference');
  assert.deepEqual(defs.LogChunk['x-unique-key'], ['task.task_type', 'task.task_public_id', 'job_uid', 'job_generation', 'chunk_sequence']);
  assert.ok(defs.LogChunk['x-invariants'].some((item) => item.includes('raw stdout/stderr')));
  assert.match(evidenceChunkLogSchema['x-owner-boundaries'].A, /A-owned/);
  assert.match(evidenceChunkLogSchema['x-owner-boundaries'].B, /B-owned/);
  assert.match(evidenceChunkLogSchema['x-owner-boundaries'].C, /C-owned/);

  const manifestEntry = parseJSON(join(contractDir, 'contract-manifest.json')).artifacts.find((item) => item.id === 'evidence_chunk_log');
  assert.deepEqual(manifestEntry, { id: 'evidence_chunk_log', status: 'draft', path: 'contracts/system-backup/v12/evidence-chunk-log.schema.json' });
  assert.deepEqual(
    reviews.public_contract_reviews.find((item) => item.artifact_ids.includes('evidence_chunk_log')),
    { artifact_ids: ['evidence_chunk_log'], required_reviewers: ['A', 'B', 'C'], approved_reviewers: [] },
  );
});

test('evidence and log examples bind contiguous chunks and redacted inline bytes', () => {
  const defs = evidenceChunkLogSchema.$defs;
  assert.equal(evidenceChunkLogExamples.kind, 'system_backup_evidence_chunk_log_redacted_examples');
  assert.equal(evidenceChunkLogExamples.evidence_records.length, 2);
  for (const record of evidenceChunkLogExamples.evidence_records) {
    assert.deepEqual(Object.keys(record).sort(), Object.keys(defs.EvidenceRecord.properties).sort());
    assert.deepEqual(Object.keys(record.owner).sort(), Object.keys(defs.OwnerTargetReference.properties).sort());
    assert.equal(record.claim_owner === null, record.claim_expires_at === null);
  }

  const external = evidenceChunkLogExamples.evidence_records.find((item) => item.storage_state === 'ready');
  const inline = evidenceChunkLogExamples.evidence_records.find((item) => item.storage_state === 'inline');
  assert.ok(external);
  assert.ok(inline);
  assert.equal(external.encryption, 'envelope_v1');
  assert.equal(external.redaction_classification, 'confidential');
  assert.deepEqual(Object.keys(external.storage_ref).sort(), Object.keys(defs.TypedStorageReference.properties).sort());
  assert.deepEqual(Object.keys(external.encryption_envelope).sort(), Object.keys(defs.EncryptionEnvelopeReference.properties).sort());
  assert.doesNotMatch(external.storage_ref.relative_key, /:\/\/|(?:^|\/)\.\.?(?:\/|$)/);
  assert.equal(external.plaintext_chunk_size_bytes, 1048576);
  assert.equal(external.chunk_count, evidenceChunkLogExamples.evidence_chunks.length);

  const inlineBytes = Buffer.from(inline.inline_payload_base64, 'base64');
  assert.equal(inline.evidence_type, 'job_log_chunk');
  assert.equal(inline.encryption, 'none');
  assert.equal(inline.storage_ref, null);
  assert.equal(inline.object_checksum, null);
  assert.equal(inline.chunk_count, 0);
  assert.equal(inline.content_size_bytes, inlineBytes.length);
  assert.equal(inline.content_checksum, sha256(inlineBytes));

  const chunks = [...evidenceChunkLogExamples.evidence_chunks].sort((left, right) => left.chunk_index - right.chunk_index);
  let plaintextOffset = 0;
  let objectFrameOffset = 0;
  for (const [index, chunk] of chunks.entries()) {
    assert.deepEqual(Object.keys(chunk).sort(), Object.keys(defs.EvidenceChunk.properties).sort());
    assert.equal(chunk.evidence_public_id, external.public_id);
    assert.equal(chunk.chunk_index, index);
    assert.equal(chunk.plaintext_offset, plaintextOffset);
    assert.equal(chunk.object_frame_offset, objectFrameOffset);
    plaintextOffset += chunk.plaintext_length;
    objectFrameOffset += chunk.object_frame_length;
  }
  assert.equal(plaintextOffset, external.content_size_bytes);
  assert.equal(objectFrameOffset, external.object_size_bytes);

  const log = evidenceChunkLogExamples.log_chunk;
  assert.deepEqual(Object.keys(log).sort(), Object.keys(defs.LogChunk.properties).sort());
  assert.deepEqual(Object.keys(log.task).sort(), Object.keys(defs.TaskReference.properties).sort());
  assert.deepEqual(Object.keys(log.redacted_evidence).sort(), Object.keys(defs.EvidenceReference.properties).sort());
  assert.equal(log.ingest_status, 'ready');
  assert.equal(log.log_ingest_failure_code, 'none');
  assert.equal(log.line_count, 1);
  assert.equal(log.redacted_evidence.public_id, inline.public_id);
  assert.equal(log.redacted_evidence.sha256, inline.content_checksum);
  assert.equal(log.task.task_type, inline.owner.owner_target_type);
  assert.equal(log.task.task_public_id, inline.owner.owner_target_public_id);

  const serialized = JSON.stringify(evidenceChunkLogExamples);
  assert.doesNotMatch(serialized, /:\/\//);
  assert.doesNotMatch(serialized, /"(?:password|secret|token|credential|private_key|authorization|uri|endpoint|raw_stdout|raw_stderr|raw_line|provider_location)"\s*:/i);
});
