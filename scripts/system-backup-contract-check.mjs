#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { validateReviewedSchemaHashEvidence } from './system-backup-schema-hash-evidence.mjs';

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(dirname(scriptPath), '..');
const contractDir = join(root, 'contracts/system-backup/v12');
const inventoryPath = join(root, 'docs/system-backup-restore-schema-inventory.json');
const decisionsPath = join(contractDir, 'schema-registry-decisions.json');
const enumsPath = join(contractDir, 'registry-enums.json');
const manifestPath = join(contractDir, 'contract-manifest.json');
const registryPath = join(contractDir, 'schema-registry.json');
const captureSqlPath = join(contractDir, 'schema-hash-capture.mysql.sql');
const migrationDir = join(root, 'backend/internal/db/migrations');
const contractVersion = 'system-backup-plan.v12';
const registryVersion = 'system-backup-schema-registry.v1';

const requiredArtifactIDs = [
  'registry_enums',
  'hash_algorithms',
  'schema_registry',
  'admin_openapi',
  'task_operation_dto',
  'status_failure_enums',
  'manifest_system_backup_v1',
  'artifact_index',
  'provider_finalizer_request',
  'committed_marker',
  'acceptance_marker',
  'control_evidence_sidecar',
  'recovery_catalog_records',
  'strong_auth_proof_nonce',
  'strong_auth_nonce_ledger',
  'provider_proof_registration',
  'restore_target',
  'restore_drill_resource_lifecycle',
  'status_relay',
  'job_observation_cursor',
  'verifier_contract',
  'metrics_alert_registry',
  'staging_resource_lifecycle',
  'maintenance_participant_state',
  'external_action_payload',
  'evidence_chunk_log',
  'dependency_provider_capability',
  'catalog_scan_record',
  'compact_tombstone',
  'installation_state',
  'source_writer_check_state',
  'runner_collector_normalizer_interfaces',
  'audit_cursor_redacted_examples',
  'go_typescript_dto_parity',
  'capability_evidence',
  'cross_owner_reviews',
];

const sourcePath = (path) => relative(root, path).replaceAll('\\', '/');
const sortText = (items) => [...items].sort((a, b) => a.localeCompare(b, 'en'));
const objectKey = (item) => `${item.object_type}:${item.name}`;
const parseJSON = (path) => JSON.parse(readFileSync(path, 'utf8'));

function frame(hash, value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  hash.update(length);
  hash.update(bytes);
}

export function computeMigrationCatalog(directory = migrationDir) {
  const filenames = sortText(readdirSync(directory).filter((name) => name.endsWith('.sql')));
  const hash = createHash('sha256');
  hash.update('system-backup-migration-catalog.v1\0', 'utf8');
  for (const filename of filenames) {
    frame(hash, filename);
    const normalizedContent = readFileSync(join(directory, filename), 'utf8').replace(/\r\n?/g, '\n');
    frame(hash, normalizedContent);
  }
  return {
    algorithm: 'sha256-length-prefixed-filename-normalized-content-v1',
    file_count: filenames.length,
    hash: hash.digest('hex'),
  };
}

function enumSets(enums) {
  const names = [
    'object_type',
    'owner',
    'category',
    'data_classification',
    'backup_strategy',
    'restore_strategy',
    'excluded_reason',
    'decision_status',
  ];
  return Object.fromEntries(names.map((name) => [name, new Set(enums[name] ?? [])]));
}

function validateManifest(manifest) {
  if (manifest.kind !== 'system_backup_contract_manifest' || manifest.contract_version !== contractVersion) {
    throw new Error('contract manifest kind or version does not match system-backup-plan.v12');
  }
  if (!['draft', 'frozen'].includes(manifest.contract_status)) {
    throw new Error('contract manifest status must be draft or frozen');
  }
  const artifacts = new Map();
  for (const artifact of manifest.artifacts ?? []) {
    if (artifacts.has(artifact.id)) throw new Error(`duplicate contract artifact ${artifact.id}`);
    if (!['missing', 'draft', 'frozen'].includes(artifact.status)) throw new Error(`invalid status for artifact ${artifact.id}`);
    if (artifact.status === 'missing' && artifact.path !== null) {
      throw new Error(`missing contract artifact ${artifact.id} must not point to a path`);
    }
    if (artifact.path !== null) {
      const fullPath = join(root, artifact.path);
      const repositoryRelativePath = relative(root, resolve(fullPath));
      if (repositoryRelativePath.startsWith('..') || isAbsolute(repositoryRelativePath)) {
        throw new Error(`contract artifact ${artifact.id} points outside the repository`);
      }
      if (!existsSync(fullPath) && resolve(fullPath) !== resolve(registryPath)) {
        throw new Error(`contract artifact ${artifact.id} points to missing ${artifact.path}`);
      }
    } else if (artifact.status !== 'missing') {
      throw new Error(`contract artifact ${artifact.id} has no path but is not missing`);
    }
    artifacts.set(artifact.id, artifact);
  }
  for (const id of requiredArtifactIDs) {
    if (!artifacts.has(id)) throw new Error(`contract manifest does not account for required artifact ${id}`);
  }
  const unexpected = [...artifacts.keys()].filter((id) => !requiredArtifactIDs.includes(id));
  if (unexpected.length) throw new Error(`contract manifest has unknown artifacts: ${sortText(unexpected).join(', ')}`);
  return artifacts;
}

function validateDecision(decision, inventoryObject, sets, knownKeys) {
  const key = objectKey(decision);
  if (!inventoryObject) throw new Error(`decision ${key} is not present in the ownership inventory`);
  if (decision.owner !== inventoryObject.owner) throw new Error(`decision ${key} owner does not match inventory`);
  for (const name of ['object_type', 'owner', 'data_classification', 'backup_strategy', 'restore_strategy', 'decision_status']) {
    if (!sets[name].has(decision[name])) throw new Error(`decision ${key} has invalid ${name}`);
  }
  if (decision.excluded_reason !== null && !sets.excluded_reason.has(decision.excluded_reason)) {
    throw new Error(`decision ${key} has invalid excluded_reason`);
  }
  const excluded = decision.backup_strategy === 'exclude' || decision.restore_strategy === 'exclude';
  if (excluded !== (decision.excluded_reason !== null)) {
    throw new Error(`decision ${key} must set excluded_reason exactly when a strategy is exclude`);
  }
  if (decision.restore_strategy === 'normalize' && !decision.normalizer_id) {
    throw new Error(`decision ${key} requires a normalizer_id`);
  }
  if (!decision.verifier_id) throw new Error(`decision ${key} requires a verifier_id`);
  if (Buffer.byteLength(decision.redacted_explanation ?? '', 'utf8') > 1024) {
    throw new Error(`decision ${key} redacted_explanation exceeds 1024 bytes`);
  }
  for (const dependency of decision.depends_on ?? []) {
    if (!knownKeys.has(dependency)) throw new Error(`decision ${key} depends on unknown ${dependency}`);
    if (dependency === key) throw new Error(`decision ${key} cannot depend on itself`);
  }
  const required = new Set(decision.required_cross_reviewers ?? []);
  const approved = new Set(decision.approved_cross_reviewers ?? []);
  for (const reviewer of [...required, ...approved]) {
    if (!sets.owner.has(reviewer) || reviewer === decision.owner) {
      throw new Error(`decision ${key} has invalid cross reviewer ${reviewer}`);
    }
  }
  for (const reviewer of approved) {
    if (!required.has(reviewer)) throw new Error(`decision ${key} has unrequested approval from ${reviewer}`);
  }
  if (decision.decision_status === 'frozen' && [...required].some((reviewer) => !approved.has(reviewer))) {
    throw new Error(`decision ${key} cannot be frozen before all required cross reviews`);
  }
  if (inventoryObject.category === 'system_backup' && (decision.backup_strategy !== 'metadata_only' || decision.restore_strategy !== 'reference_only')) {
    throw new Error(`system_backup decision ${key} must be metadata_only/reference_only`);
  }
}

export function buildRegistry({ schemaHashEvidencePath = null } = {}) {
  const inventory = parseJSON(inventoryPath);
  const decisions = parseJSON(decisionsPath);
  const enums = parseJSON(enumsPath);
  const manifest = parseJSON(manifestPath);
  validateManifest(manifest);
  if (inventory.plan_version !== contractVersion || decisions.contract_version !== contractVersion || enums.contract_version !== contractVersion) {
    throw new Error('inventory, decisions and enums must use system-backup-plan.v12');
  }
  const sets = enumSets(enums);
  const inventoryByKey = new Map(inventory.objects.map((item) => [objectKey(item), item]));
  const knownKeys = new Set(inventoryByKey.keys());
  const decisionsByKey = new Map();
  for (const decision of decisions.decisions ?? []) {
    const key = objectKey(decision);
    if (decisionsByKey.has(key)) throw new Error(`duplicate schema registry decision ${key}`);
    validateDecision(decision, inventoryByKey.get(key), sets, knownKeys);
    decisionsByKey.set(key, decision);
  }
  const missingDDecisions = inventory.objects
    .filter((item) => item.owner === 'D' && !decisionsByKey.has(objectKey(item)))
    .map(objectKey);
  if (missingDDecisions.length) throw new Error(`D-owned registry decisions missing: ${missingDDecisions.join(', ')}`);

  const objects = inventory.objects.map((item) => {
    if (!sets.object_type.has(item.object_type) || !sets.owner.has(item.owner) || !sets.category.has(item.category)) {
      throw new Error(`inventory object ${objectKey(item)} uses a value outside registry enums`);
    }
    const decision = decisionsByKey.get(objectKey(item));
    return {
      object_type: item.object_type,
      name: item.name,
      owner: item.owner,
      category: item.category,
      data_classification: decision?.data_classification ?? null,
      backup_strategy: decision?.backup_strategy ?? null,
      restore_strategy: decision?.restore_strategy ?? null,
      excluded_reason: decision?.excluded_reason ?? null,
      normalizer_id: decision?.normalizer_id ?? null,
      verifier_id: decision?.verifier_id ?? null,
      depends_on: sortText(decision?.depends_on ?? []),
      decision_status: decision?.decision_status ?? 'pending_owner_review',
      required_cross_reviewers: sortText(decision?.required_cross_reviewers ?? []),
      approved_cross_reviewers: sortText(decision?.approved_cross_reviewers ?? []),
      redacted_explanation: decision?.redacted_explanation ?? null,
      sources: {
        migration: item.migration_sources,
        repository_create: item.repository_create_sources,
        repository_alter: item.repository_alter_sources,
        deployment_bootstrap: item.deployment_bootstrap_create_sources,
        exception: item.source_exception,
      },
    };
  });
  const migrationCatalog = computeMigrationCatalog();
  let schemaHash = {
    algorithm: 'sha256-information-schema-canonical-v1',
    status: 'pending_live_evidence',
    hash: null,
    evidence: null,
  };
  if (schemaHashEvidencePath !== null) {
    const evidence = validateReviewedSchemaHashEvidence(parseJSON(resolve(schemaHashEvidencePath)), {
      inventory,
      migrationCatalog,
      captureSql: readFileSync(captureSqlPath, 'utf8'),
    });
    schemaHash = {
      algorithm: evidence.result.algorithm,
      status: 'observed',
      hash: evidence.result.hash,
      evidence: evidence.registered_evidence,
    };
  }

  const policyRecorded = objects.filter((item) => item.decision_status !== 'pending_owner_review').length;
  const crossReviewPending = objects.filter((item) => item.decision_status !== 'pending_owner_review'
    && item.required_cross_reviewers.some((reviewer) => !item.approved_cross_reviewers.includes(reviewer))).length;
  return {
    kind: 'system_backup_schema_registry',
    registry_version: registryVersion,
    contract_version: contractVersion,
    contract_status: 'draft',
    plan_source: inventory.plan_source,
    migration_catalog: migrationCatalog,
    schema_hash: schemaHash,
    summary: {
      object_count: objects.length,
      policy_recorded: policyRecorded,
      policy_pending: objects.length - policyRecorded,
      cross_review_pending: crossReviewPending,
    },
    objects,
  };
}

export function strictBlockers(registry, manifest) {
  const artifacts = manifest.artifacts ?? [];
  const inventory = parseJSON(inventoryPath);
  return {
    plan_control_without_inventory: inventory.gaps?.plan_control_without_inventory ?? [],
    missing_artifacts: artifacts.filter((item) => item.status === 'missing').map((item) => item.id),
    draft_artifacts: artifacts.filter((item) => item.status === 'draft').map((item) => item.id),
    policy_pending: registry.objects.filter((item) => item.decision_status === 'pending_owner_review').map(objectKey),
    cross_review_pending: registry.objects
      .filter((item) => item.required_cross_reviewers.some((reviewer) => !item.approved_cross_reviewers.includes(reviewer)))
      .map(objectKey),
    schema_hash_pending: registry.schema_hash.status !== 'observed'
      || !registry.schema_hash.hash
      || !registry.schema_hash.evidence
      || manifest.freeze_gates?.schema_hash_evidence_present !== true,
  };
}

function main() {
  const args = new Set();
  let schemaHashEvidencePath = null;
  const rawArgs = process.argv.slice(2);
  for (let index = 0; index < rawArgs.length; index += 1) {
    const arg = rawArgs[index];
    if (arg === '--schema-hash-evidence') {
      if (schemaHashEvidencePath !== null || !rawArgs[index + 1]) throw new Error('--schema-hash-evidence requires exactly one path');
      schemaHashEvidencePath = rawArgs[index + 1];
      index += 1;
    } else if (['--write', '--check', '--strict'].includes(arg)) {
      args.add(arg);
    } else {
      throw new Error(`unknown argument ${arg}`);
    }
  }
  const registry = buildRegistry({ schemaHashEvidencePath });
  const output = `${JSON.stringify(registry, null, 2)}\n`;
  if (args.has('--write')) writeFileSync(registryPath, output);
  if (args.has('--check') && (!existsSync(registryPath) || readFileSync(registryPath, 'utf8') !== output)) {
    throw new Error(`${sourcePath(registryPath)} is missing or stale; run with --write`);
  }
  const manifest = parseJSON(manifestPath);
  const blockers = strictBlockers(registry, manifest);
  process.stdout.write(`${JSON.stringify({
    contract_version: registry.contract_version,
    contract_status: registry.contract_status,
    migration_catalog: registry.migration_catalog,
    summary: registry.summary,
    blockers,
  }, null, 2)}\n`);
  if (args.has('--strict') && (blockers.plan_control_without_inventory.length
    || blockers.missing_artifacts.length
    || blockers.draft_artifacts.length
    || blockers.policy_pending.length
    || blockers.cross_review_pending.length
    || blockers.schema_hash_pending)) {
    process.exitCode = 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(scriptPath)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
