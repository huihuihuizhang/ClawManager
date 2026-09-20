#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalizeObservation, computeSchemaHash, observationFromRecords } from './system-backup-schema-hash.mjs';

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(dirname(scriptPath), '..');
const contractVersion = 'system-backup-plan.v12';
const algorithm = 'sha256-information-schema-canonical-v1';
const reviewers = ['A', 'B', 'C'];
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalJSON = (value) => {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`;
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(',')}}`;
  }
  throw new Error('canonical evidence input contains an unsupported JSON value');
};
const pathHash = (path) => sha256(Buffer.from(`system-backup-schema-capture-path.v1\0${resolve(path)}`, 'utf8'));
const sortedUnique = (items) => [...new Set(items)].sort();

function expectClosed(value, keys, context) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${context} must be an object`);
  const missing = keys.filter((key) => !(key in value));
  const unknown = Object.keys(value).filter((key) => !keys.includes(key));
  if (missing.length) throw new Error(`${context} is missing ${missing.join(', ')}`);
  if (unknown.length) throw new Error(`${context} has unknown fields ${unknown.join(', ')}`);
}

function expectSha256(value, context) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw new Error(`${context} must be lowercase SHA-256`);
}

function expectTimestamp(value, context) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) throw new Error(`${context} must be a date-time`);
}

export function buildSchemaHashEvidenceCandidate({ records, recordsPath, context, inventory, migrationCatalog, captureSql }) {
  expectClosed(context, ['installation_identity_hash', 'installation_identity_version', 'capture_started_at', 'capture_finished_at'], 'context');
  expectSha256(context.installation_identity_hash, 'context.installation_identity_hash');
  if (typeof context.installation_identity_version !== 'string' || !context.installation_identity_version || context.installation_identity_version.length > 128) {
    throw new Error('context.installation_identity_version must be 1..128 characters');
  }
  expectTimestamp(context.capture_started_at, 'context.capture_started_at');
  expectTimestamp(context.capture_finished_at, 'context.capture_finished_at');
  if (Date.parse(context.capture_started_at) > Date.parse(context.capture_finished_at)) throw new Error('capture_started_at must not be later than capture_finished_at');
  if (typeof records !== 'string' || !records.trim()) throw new Error('capture records must not be empty');
  if (typeof recordsPath !== 'string' || !recordsPath) throw new Error('recordsPath is required');
  if (!inventory || inventory.plan_version !== contractVersion || !Array.isArray(inventory.objects)) throw new Error('inventory must use system-backup-plan.v12');
  if (!migrationCatalog || migrationCatalog.algorithm !== 'sha256-length-prefixed-filename-normalized-content-v1') throw new Error('migration catalog is invalid');
  expectSha256(migrationCatalog.hash, 'migrationCatalog.hash');

  const observation = observationFromRecords(records);
  const canonical = canonicalizeObservation(observation);
  const result = computeSchemaHash(observation);
  const expectedKeys = sortedUnique(inventory.objects.map((item) => `${item.object_type}:${item.name}`));
  const observedKeys = sortedUnique(canonical.objects.map((item) => `${item.object_type}:${item.name}`));
  const expected = new Set(expectedKeys);
  const observed = new Set(observedKeys);
  const missing = expectedKeys.filter((key) => !observed.has(key));
  const unexpected = observedKeys.filter((key) => !expected.has(key));
  const serverContext = { server_version: observation.server_version, sql_mode: observation.sql_mode };

  return {
    kind: 'system_backup_schema_hash_live_evidence',
    contract_version: contractVersion,
    status: 'candidate',
    installation_identity_hash: context.installation_identity_hash,
    installation_identity_version: context.installation_identity_version,
    capture_started_at: context.capture_started_at,
    capture_finished_at: context.capture_finished_at,
    capture_method: 'mysql-batch-raw-no-column-names-v1',
    capture_sql_sha256: sha256(Buffer.from(captureSql, 'utf8')),
    capture_records_sha256: sha256(Buffer.from(records, 'utf8')),
    capture_record_count: records.split(/\r?\n/).filter(Boolean).length,
    server_context_hash: sha256(Buffer.from(canonicalJSON(serverContext), 'utf8')),
    inventory_snapshot_sha256: sha256(Buffer.from(JSON.stringify(inventory), 'utf8')),
    migration_catalog_hash: migrationCatalog.hash,
    result,
    inventory_comparison: {
      expected_object_count: expectedKeys.length,
      observed_object_count: observedKeys.length,
      observed_object_keys_hash: sha256(Buffer.from(canonicalJSON(observedKeys), 'utf8')),
      missing_object_keys: missing,
      unexpected_object_keys: unexpected,
      matched: missing.length === 0 && unexpected.length === 0,
    },
    records_cleanup: {
      path_hash: pathHash(recordsPath),
      status: 'pending',
      deleted_at: null,
      verified_absent: false,
    },
    registered_evidence: null,
    required_reviewers: reviewers,
    approved_reviewers: [],
  };
}

export function verifySchemaHashEvidenceCleanup(candidate, recordsPath, deletedAt) {
  if (candidate?.kind !== 'system_backup_schema_hash_live_evidence' || candidate.status !== 'candidate') throw new Error('only candidate evidence can record cleanup');
  expectTimestamp(deletedAt, 'deleted_at');
  if (Date.parse(deletedAt) < Date.parse(candidate.capture_finished_at)) throw new Error('deleted_at must not be earlier than capture_finished_at');
  if (candidate.records_cleanup?.path_hash !== pathHash(recordsPath)) throw new Error('records path does not match candidate path hash');
  if (existsSync(resolve(recordsPath))) throw new Error('capture records still exist');
  return {
    ...candidate,
    records_cleanup: {
      ...candidate.records_cleanup,
      status: 'verified',
      deleted_at: deletedAt,
      verified_absent: true,
    },
  };
}

export function validateReviewedSchemaHashEvidence(evidence, { inventory, migrationCatalog, captureSql }) {
  const rootKeys = ['kind', 'contract_version', 'status', 'installation_identity_hash', 'installation_identity_version', 'capture_started_at', 'capture_finished_at', 'capture_method', 'capture_sql_sha256', 'capture_records_sha256', 'capture_record_count', 'server_context_hash', 'inventory_snapshot_sha256', 'migration_catalog_hash', 'result', 'inventory_comparison', 'records_cleanup', 'registered_evidence', 'required_reviewers', 'approved_reviewers'];
  expectClosed(evidence, rootKeys, 'schema hash live evidence');
  if (evidence.kind !== 'system_backup_schema_hash_live_evidence' || evidence.contract_version !== contractVersion || evidence.status !== 'reviewed') throw new Error('schema hash live evidence is not reviewed for system-backup-plan.v12');
  for (const key of ['installation_identity_hash', 'capture_sql_sha256', 'capture_records_sha256', 'server_context_hash', 'inventory_snapshot_sha256', 'migration_catalog_hash']) expectSha256(evidence[key], key);
  if (typeof evidence.installation_identity_version !== 'string' || !evidence.installation_identity_version || evidence.installation_identity_version.length > 128) throw new Error('installation_identity_version must be 1..128 characters');
  expectTimestamp(evidence.capture_started_at, 'capture_started_at');
  expectTimestamp(evidence.capture_finished_at, 'capture_finished_at');
  if (Date.parse(evidence.capture_started_at) > Date.parse(evidence.capture_finished_at)) throw new Error('capture timestamps are reversed');
  if (evidence.capture_method !== 'mysql-batch-raw-no-column-names-v1') throw new Error('capture method is invalid');
  if (!Number.isSafeInteger(evidence.capture_record_count) || evidence.capture_record_count < 1) throw new Error('capture_record_count is invalid');
  if (evidence.capture_sql_sha256 !== sha256(Buffer.from(captureSql, 'utf8'))) throw new Error('capture SQL hash does not match the repository query');
  if (evidence.inventory_snapshot_sha256 !== sha256(Buffer.from(JSON.stringify(inventory), 'utf8'))) throw new Error('inventory snapshot hash does not match the repository snapshot');
  if (evidence.migration_catalog_hash !== migrationCatalog.hash) throw new Error('migration catalog hash does not match the repository migrations');

  const expectedKeys = sortedUnique(inventory.objects.map((item) => `${item.object_type}:${item.name}`));
  const comparison = evidence.inventory_comparison;
  expectClosed(comparison, ['expected_object_count', 'observed_object_count', 'observed_object_keys_hash', 'missing_object_keys', 'unexpected_object_keys', 'matched'], 'inventory_comparison');
  expectSha256(comparison.observed_object_keys_hash, 'observed_object_keys_hash');
  if (comparison.expected_object_count !== expectedKeys.length || comparison.observed_object_count !== expectedKeys.length || comparison.matched !== true) throw new Error('reviewed evidence must exactly match inventory object count');
  if (comparison.observed_object_keys_hash !== sha256(Buffer.from(canonicalJSON(expectedKeys), 'utf8'))) throw new Error('reviewed evidence object set does not match inventory');
  if (!Array.isArray(comparison.missing_object_keys) || comparison.missing_object_keys.length || !Array.isArray(comparison.unexpected_object_keys) || comparison.unexpected_object_keys.length) throw new Error('reviewed evidence cannot contain inventory differences');

  const result = evidence.result;
  expectClosed(result, ['kind', 'contract_version', 'algorithm', 'hash', 'canonical_bytes_length', 'object_count', 'object_counts'], 'schema hash result');
  if (result.kind !== 'system_backup_schema_hash_result' || result.contract_version !== contractVersion || result.algorithm !== algorithm) throw new Error('schema hash result identity is invalid');
  expectSha256(result.hash, 'result.hash');
  if (!Number.isSafeInteger(result.canonical_bytes_length) || result.canonical_bytes_length < 1 || result.object_count !== expectedKeys.length) throw new Error('schema hash result counts are invalid');
  expectClosed(result.object_counts, ['table', 'view', 'trigger', 'routine', 'mysql_event'], 'result.object_counts');
  if (Object.values(result.object_counts).some((value) => !Number.isSafeInteger(value) || value < 0) || Object.values(result.object_counts).reduce((sum, value) => sum + value, 0) !== result.object_count) throw new Error('schema hash result object_counts do not sum to object_count');
  const expectedCounts = { table: 0, view: 0, trigger: 0, routine: 0, mysql_event: 0 };
  for (const object of inventory.objects) expectedCounts[object.object_type] += 1;
  if (Object.keys(expectedCounts).some((type) => result.object_counts[type] !== expectedCounts[type])) throw new Error('schema hash result object_counts do not match inventory object types');

  const cleanup = evidence.records_cleanup;
  expectClosed(cleanup, ['path_hash', 'status', 'deleted_at', 'verified_absent'], 'records_cleanup');
  expectSha256(cleanup.path_hash, 'records_cleanup.path_hash');
  expectTimestamp(cleanup.deleted_at, 'records_cleanup.deleted_at');
  if (cleanup.status !== 'verified' || cleanup.verified_absent !== true || Date.parse(cleanup.deleted_at) < Date.parse(evidence.capture_finished_at)) throw new Error('temporary capture cleanup is not verified');
  expectClosed(evidence.registered_evidence, ['public_id', 'sha256'], 'registered_evidence');
  if (typeof evidence.registered_evidence.public_id !== 'string' || !/^sev_[A-Za-z0-9_-]+$/.test(evidence.registered_evidence.public_id)) throw new Error('registered evidence public ID is invalid');
  expectSha256(evidence.registered_evidence.sha256, 'registered_evidence.sha256');
  if (JSON.stringify(evidence.required_reviewers) !== JSON.stringify(reviewers) || JSON.stringify(evidence.approved_reviewers) !== JSON.stringify(reviewers)) throw new Error('reviewed evidence requires explicit A/B/C approval');
  return evidence;
}

function parseCandidateArgs(args) {
  if (args.length === 4 && args[0] === '--records' && args[2] === '--context') return { mode: 'candidate', recordsPath: resolve(args[1]), contextPath: resolve(args[3]) };
  if (args.length === 6 && args[0] === '--verify-cleanup' && args[2] === '--records' && args[4] === '--deleted-at') return { mode: 'cleanup', candidatePath: resolve(args[1]), recordsPath: resolve(args[3]), deletedAt: args[5] };
  throw new Error('usage: node scripts/system-backup-schema-hash-evidence.mjs --records <capture.tsv> --context <context.json> OR --verify-cleanup <candidate.json> --records <deleted-capture.tsv> --deleted-at <date-time>');
}

function main() {
  const args = parseCandidateArgs(process.argv.slice(2));
  if (args.mode === 'cleanup') {
    const candidate = JSON.parse(readFileSync(args.candidatePath, 'utf8'));
    process.stdout.write(`${JSON.stringify(verifySchemaHashEvidenceCleanup(candidate, args.recordsPath, args.deletedAt), null, 2)}\n`);
    return;
  }
  const inventoryPath = resolve(root, 'docs/system-backup-restore-schema-inventory.json');
  const registryPath = resolve(root, 'contracts/system-backup/v12/schema-registry.json');
  const captureSqlPath = resolve(root, 'contracts/system-backup/v12/schema-hash-capture.mysql.sql');
  const records = readFileSync(args.recordsPath, 'utf8');
  const context = JSON.parse(readFileSync(args.contextPath, 'utf8'));
  const inventory = JSON.parse(readFileSync(inventoryPath, 'utf8'));
  const migrationCatalog = JSON.parse(readFileSync(registryPath, 'utf8')).migration_catalog;
  const captureSql = readFileSync(captureSqlPath, 'utf8');
  const candidate = buildSchemaHashEvidenceCandidate({ records, recordsPath: args.recordsPath, context, inventory, migrationCatalog, captureSql });
  process.stdout.write(`${JSON.stringify(candidate, null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(scriptPath)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
