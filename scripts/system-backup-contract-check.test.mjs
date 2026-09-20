import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import {
  buildRegistry,
  computeMigrationCatalog,
  strictBlockers,
} from './system-backup-contract-check.mjs';
import {
  buildSchemaHashEvidenceCandidate,
  validateReviewedSchemaHashEvidence,
  verifySchemaHashEvidenceCleanup,
} from './system-backup-schema-hash-evidence.mjs';

const root = resolve(import.meta.dirname, '..');
const inventoryPath = join(root, 'docs/system-backup-restore-schema-inventory.json');
const captureSqlPath = join(root, 'contracts/system-backup/v12/schema-hash-capture.mysql.sql');
const inventory = JSON.parse(readFileSync(inventoryPath, 'utf8'));
const captureSql = readFileSync(captureSqlPath, 'utf8');

function completeSyntheticCaptureRecords() {
  const lines = [`metadata\t${JSON.stringify({ server_version: '8.0.40', sql_mode: 'STRICT_TRANS_TABLES' })}`];
  for (const object of inventory.objects) {
    assert.equal(object.object_type, 'table', `test fixture must be extended for ${object.object_type}:${object.name}`);
    lines.push(`table\t${JSON.stringify({ name: object.name })}`);
    lines.push(`column\t${JSON.stringify({
      table_name: object.name,
      name: 'synthetic_id',
      ordinal_position: 1,
      normalized_type: 'bigint unsigned',
      nullable: false,
      default: null,
      character_set: null,
      collation: null,
      extra: '',
      generation_expression: null,
    })}`);
  }
  return `${lines.join('\n')}\n`;
}

const manifest = {
  artifacts: [
    { id: 'registry_enums', status: 'draft' },
    { id: 'schema_registry', status: 'draft' },
    { id: 'admin_openapi', status: 'missing' },
  ],
};

test('migration catalog hash is deterministic and content-addressed', () => {
  const first = computeMigrationCatalog();
  const second = computeMigrationCatalog();

  assert.deepEqual(first, second);
  assert.equal(first.algorithm, 'sha256-length-prefixed-filename-normalized-content-v1');
  assert.ok(first.file_count > 0);
  assert.match(first.hash, /^[0-9a-f]{64}$/);
});

test('migration catalog hash is independent of checkout line endings', () => {
  const directory = mkdtempSync(join(tmpdir(), 'clawmanager-catalog-hash-'));
  try {
    const migration = join(directory, '001_example.sql');
    writeFileSync(migration, 'CREATE TABLE example (\n  id INT PRIMARY KEY\n);\n');
    const lf = computeMigrationCatalog(directory);

    writeFileSync(migration, 'CREATE TABLE example (\r\n  id INT PRIMARY KEY\r\n);\r\n');
    const crlf = computeMigrationCatalog(directory);

    assert.deepEqual(crlf, lf);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('draft registry covers inventory and records every D decision', () => {
  const registry = buildRegistry();
  const keys = registry.objects.map((item) => `${item.object_type}:${item.name}`);
  const dObjects = registry.objects.filter((item) => item.owner === 'D');

  assert.equal(new Set(keys).size, keys.length);
  assert.equal(registry.summary.object_count, registry.objects.length);
  assert.equal(registry.summary.policy_recorded + registry.summary.policy_pending, registry.objects.length);
  assert.ok(dObjects.length > 0);
  assert.ok(dObjects.every((item) => item.decision_status === 'owner_recorded'));
  assert.ok(dObjects.every((item) => item.verifier_id));
  assert.equal(registry.schema_hash.status, 'pending_live_evidence');
  assert.equal(registry.schema_hash.hash, null);
  assert.equal(registry.schema_hash.evidence, null);

  const securityMigration = registry.objects.find((item) => item.name === 'security_scan_configs');
  assert.ok(securityMigration.sources.migration.includes('backend/internal/db/migrations/063_add_security_scan_tables.sql'));

  const bookkeeping = registry.objects.find((item) => item.name === 'schema_migrations');
  assert.equal(bookkeeping.backup_strategy, 'metadata_only');
  assert.equal(bookkeeping.restore_strategy, 'reference_only');
});

test('P0-0a inventory exposes planned control tables absent from owner and migration coverage', () => {
  assert.equal(inventory.summary.plan_control_tables, 32);
  assert.equal(inventory.summary.plan_control_without_inventory, inventory.gaps.plan_control_without_inventory.length);
  assert.deepEqual(inventory.gaps.plan_control_without_inventory, [
    'system_backup_catalog_imports',
    'system_backup_catalog_records',
    'system_backup_catalog_scan_states',
  ]);
  const blockers = strictBlockers(buildRegistry(), manifest);
  assert.deepEqual(blockers.plan_control_without_inventory, inventory.gaps.plan_control_without_inventory);
});

test('strict blockers keep the draft contract from being reported as frozen', () => {
  const registry = buildRegistry();
  const blockers = strictBlockers(registry, manifest);

  assert.deepEqual(blockers.missing_artifacts, ['admin_openapi']);
  assert.deepEqual(blockers.draft_artifacts, ['registry_enums', 'schema_registry']);
  assert.ok(blockers.policy_pending.length > 0);
  assert.ok(blockers.cross_review_pending.length > 0);
  assert.equal(blockers.schema_hash_pending, true);
});

test('live schema-hash evidence stays pending until cleanup, registration and A/B/C review', () => {
  const directory = mkdtempSync(join(tmpdir(), 'clawmanager-schema-evidence-'));
  try {
    const recordsPath = join(directory, '.tmp-system-backup-schema-capture-test.tsv');
    const records = completeSyntheticCaptureRecords();
    writeFileSync(recordsPath, records);
    const migrationCatalog = computeMigrationCatalog();
    const context = {
      installation_identity_hash: '1'.repeat(64),
      installation_identity_version: 'synthetic-installation-ref-v1',
      capture_started_at: '2026-09-15T09:00:00Z',
      capture_finished_at: '2026-09-15T09:00:01Z',
    };
    const candidate = buildSchemaHashEvidenceCandidate({ records, recordsPath, context, inventory, migrationCatalog, captureSql });

    assert.equal(candidate.status, 'candidate');
    assert.equal(candidate.inventory_comparison.matched, true);
    assert.deepEqual(candidate.inventory_comparison.missing_object_keys, []);
    assert.deepEqual(candidate.inventory_comparison.unexpected_object_keys, []);
    assert.equal(candidate.result.object_count, inventory.objects.length);
    assert.equal(candidate.records_cleanup.status, 'pending');
    assert.equal(candidate.registered_evidence, null);
    assert.deepEqual(candidate.approved_reviewers, []);
    assert.throws(
      () => validateReviewedSchemaHashEvidence(candidate, { inventory, migrationCatalog, captureSql }),
      /not reviewed/,
    );

    rmSync(recordsPath, { force: true });
    const cleaned = verifySchemaHashEvidenceCleanup(candidate, recordsPath, '2026-09-15T09:00:02Z');
    assert.equal(cleaned.records_cleanup.status, 'verified');
    assert.equal(cleaned.records_cleanup.verified_absent, true);

    const reviewed = {
      ...cleaned,
      status: 'reviewed',
      registered_evidence: {
        public_id: 'sev_99999999-9999-4999-8999-999999999999',
        sha256: '2'.repeat(64),
      },
      approved_reviewers: ['A', 'B', 'C'],
    };
    assert.equal(validateReviewedSchemaHashEvidence(reviewed, { inventory, migrationCatalog, captureSql }), reviewed);

    const evidencePath = join(directory, 'reviewed-evidence.json');
    writeFileSync(evidencePath, JSON.stringify(reviewed));
    const observedRegistry = buildRegistry({ schemaHashEvidencePath: evidencePath });
    assert.equal(observedRegistry.schema_hash.status, 'observed');
    assert.equal(observedRegistry.schema_hash.hash, reviewed.result.hash);
    assert.deepEqual(observedRegistry.schema_hash.evidence, reviewed.registered_evidence);
    assert.equal(strictBlockers(observedRegistry, { artifacts: [], freeze_gates: { schema_hash_evidence_present: false } }).schema_hash_pending, true);
    assert.equal(strictBlockers(observedRegistry, { artifacts: [], freeze_gates: { schema_hash_evidence_present: true } }).schema_hash_pending, false);

    assert.throws(
      () => validateReviewedSchemaHashEvidence({ ...reviewed, approved_reviewers: ['A', 'B'] }, { inventory, migrationCatalog, captureSql }),
      /A\/B\/C approval/,
    );
    assert.throws(
      () => validateReviewedSchemaHashEvidence({ ...reviewed, capture_sql_sha256: '3'.repeat(64) }, { inventory, migrationCatalog, captureSql }),
      /capture SQL hash/,
    );
    assert.throws(
      () => validateReviewedSchemaHashEvidence({ ...reviewed, result: { ...reviewed.result, object_counts: { ...reviewed.result.object_counts, table: reviewed.result.object_counts.table - 1, view: 1 } } }, { inventory, migrationCatalog, captureSql }),
      /inventory object types/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
