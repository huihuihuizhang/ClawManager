import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const contractDir = 'contracts/system-backup/v12';
const references = {
  skills: { user_id: 'users', published_by: 'users', current_version_id: 'skill_versions', last_scan_result_id: 'skill_scan_results' },
  skill_blobs: { last_scan_result_id: 'skill_scan_results' },
  skill_versions: { skill_id: 'skills', blob_id: 'skill_blobs' },
  instance_skills: { instance_id: 'instances', skill_id: 'skills', skill_version_id: 'skill_versions' },
  skill_scan_results: { blob_id: 'skill_blobs' },
  skill_package_materialize_jobs: { instance_id: 'instances', skill_id: 'skills', blob_id: 'skill_blobs' },
  skill_hub_tags: {},
  skill_hub_tag_assignments: { skill_id: 'skills', tag_id: 'skill_hub_tags' },
};
const sorted = (values) => [...values].sort();
const unique = (values, label) => assert.equal(new Set(values).size, values.length, `${label}: duplicate entry`);
const keys = (object, expected, label) => assert.deepEqual(sorted(Object.keys(object)), sorted(expected), `${label}: unexpected or missing property`);

export function loadSkillHubPolicyInputs(base = root) {
  const readSource = (path) => readFileSync(resolve(base, path), 'utf8');
  const json = (path) => JSON.parse(readSource(path));
  return {
    policy: json(`${contractDir}/c-skill-hub-object-policies.json`),
    decisions: json(`${contractDir}/schema-registry-decisions.json`),
    registry: json(`${contractDir}/schema-registry.json`),
    inventory: json('docs/system-backup-restore-schema-inventory.json'),
    readSource,
  };
}

// Review-time validation only. This does not grant capture or restore authority.
export function validateSkillHubPolicies({ policy, decisions, registry, inventory, readSource }) {
  keys(policy, ['kind', 'contract_version', 'status', 'scope', 'policies', 'writer_groups'], 'policy');
  assert.equal(policy.kind, 'system_backup_skill_hub_policy_draft');
  assert.equal(policy.contract_version, 'system-backup-plan.v12');
  assert.equal(policy.status, 'draft', 'candidate must not claim frozen approval');
  assert.ok(typeof policy.scope === 'string' && policy.scope.length > 0);
  const owned = inventory.objects.filter((item) => item.category === 'skill_hub');
  assert.deepEqual(sorted(owned.map((item) => item.name)), sorted(Object.keys(references)), 'inventory scope changed; review the new scope');
  assert.deepEqual(sorted(policy.policies.map((item) => item.name)), sorted(Object.keys(references)), 'exact eight-table coverage required');
  const known = new Set(inventory.objects.map((item) => `table:${item.name}`));
  let fieldCount = 0;
  for (const entry of policy.policies) {
    keys(entry, ['name', 'model_file', 'model_type', 'fields', 'references', 'identity_policy', 'object_fields', 'workspace_fields', 'state_normalization', 'evidence_redacted_fields'], entry.name);
    const name = entry.name;
    assert.ok(/^backend\/internal\/models\/[a-z_]+\.go$/.test(entry.model_file), 'model path must stay in models');
    assert.ok(/^[A-Z][A-Za-z]+$/.test(entry.model_type), 'invalid model type');
    const source = readSource(entry.model_file);
    const body = source.match(new RegExp(`type ${entry.model_type} struct \\{([\\s\\S]*?)\\n\\}`))?.[1];
    assert.ok(body, `${name}: model not found`);
    const fields = [...body.matchAll(/db:"([^",]+)(?:,[^"]*)?"/g)].map((match) => match[1]);
    unique(entry.fields, name);
    assert.deepEqual(sorted(entry.fields), sorted(fields), `${name}: model field coverage drift`);
    assert.match(source, new RegExp(`func \\([^)]* ${entry.model_type}\\) TableName\\(\\) string \\{\\s*return "${name}"`));
    assert.deepEqual(entry.references, references[name], `${name}: reference mapping changed`);
    assert.equal(entry.identity_policy, 'shared_restore_mapping');
    const dependencies = sorted([...new Set(Object.values(entry.references))].map((table) => `table:${table}`));
    for (const dependency of dependencies) assert.ok(known.has(dependency), `${name}: unknown dependency ${dependency}`);
    for (const list of [Object.keys(entry.references), entry.object_fields, entry.workspace_fields, entry.evidence_redacted_fields]) {
      unique(list, name);
      for (const field of list) assert.ok(fields.includes(field), `${name}: unknown field ${field}`);
    }
    assert.deepEqual(entry.object_fields, name === 'skill_blobs' ? ['object_key'] : []);
    assert.deepEqual(entry.workspace_fields, name === 'instance_skills' ? ['install_path', 'workspace_dir'] : name === 'skill_package_materialize_jobs' ? ['workspace_dir'] : []);
    if (name === 'skill_package_materialize_jobs') {
      assert.deepEqual(entry.state_normalization, {
        field: 'status', allowed_source_values: ['pending', 'running', 'succeeded', 'failed', 'cancelled'],
        mapping: { pending: 'cancelled', running: 'cancelled', succeeded: 'succeeded', failed: 'failed', cancelled: 'cancelled' },
      }, 'restored jobs must not replay or lose terminal history');
      const service = readSource('backend/internal/services/skill_package_materialize_service.go');
      const statuses = [...service.matchAll(/MaterializeJobStatus\w+\s*=\s*"([a-z]+)"/g)].map((match) => match[1]);
      assert.deepEqual(sorted(statuses), sorted(entry.state_normalization.allowed_source_values), 'materialize status coverage drift');
    } else {
      assert.equal(entry.state_normalization, null, `${name}: unreviewed state transformation`);
    }
    const found = decisions.decisions.filter((item) => item.name === name);
    assert.equal(found.length, 1, `${name}: exactly one decision required`);
    const decision = found[0];
    assert.equal(decision.object_type, 'table');
    assert.equal(decision.owner, 'C');
    assert.equal(decision.data_classification, name === 'skill_hub_tags' ? 'internal' : 'confidential');
    assert.equal(decision.backup_strategy, 'mysql_dump');
    assert.equal(decision.restore_strategy, 'normalize');
    assert.equal(decision.excluded_reason, null);
    assert.equal(decision.normalizer_id, `skill_hub.${name}.normalize.v1`);
    assert.equal(decision.verifier_id, `skill_hub.${name}.verify.v1`);
    assert.deepEqual(sorted(decision.depends_on), dependencies);
    assert.equal(decision.decision_status, 'owner_recorded');
    assert.deepEqual(decision.approved_cross_reviewers, [], 'this submission carries no cross-owner approval');
    const reviewers = ['A', 'D'];
    if (dependencies.includes('table:instances') || name === 'skills') reviewers.splice(1, 0, 'B');
    assert.deepEqual(sorted(decision.required_cross_reviewers), reviewers);
    const generated = registry.objects.filter((item) => item.name === name);
    assert.equal(generated.length, 1);
    assert.equal(generated[0].category, 'skill_hub');
    for (const [key, value] of Object.entries(decision)) {
      assert.deepEqual(generated[0][key], value, `${name}: generated registry drift at ${key}`);
    }
    fieldCount += fields.length;
  }
  const writerSources = policy.writer_groups.map((group) => group.source);
  unique(writerSources, 'writer sources');
  assert.deepEqual(sorted(writerSources), sorted([
    ...['skill_service', 'skill_hub_service', 'skill_package_materialize_service', 'skill_package_materialize_worker', 'skill_runtime_sync', 'skill_import', 'skill_lite_package_collect', 'instance_command_service', 'security_scan_service'].map((name) => `backend/internal/services/${name}.go`),
    'backend/internal/handlers/workspace_file_handler.go',
  ]));
  for (const group of policy.writer_groups) {
    keys(group, ['source', 'methods', 'protection', 'note', 'owner'], 'writer group');
    const owners = { 'skill_runtime_sync.go': 'B', 'instance_command_service.go': 'B', 'workspace_file_handler.go': 'B', 'security_scan_service.go': 'D' };
    assert.equal(group.owner, owners[group.source.split('/').at(-1)] ?? 'C', 'writer responsibility drift');
    assert.equal(group.protection, 'pending', 'inventory is not a runtime pause proof');
    unique(group.methods, group.source);
    assert.ok(group.methods.length > 0 && typeof group.note === 'string' && group.note.length > 0);
    const source = readSource(group.source);
    for (const method of group.methods) {
      assert.match(method, /^[A-Za-z][A-Za-z0-9]*$/);
      assert.match(source, new RegExp(`func \\([^)]*\\) ${method}\\(`), `writer method disappeared: ${method}`);
    }
  }
  const skillWriters = policy.writer_groups.find((group) => group.source.endsWith('/skill_service.go')).methods;
  for (const method of ['ListInstanceSkills', 'reconcileRemovedInstanceSkillsFromCommands', 'UploadAgentSkillPackage', 'RemoveSkillFromInstance', 'SyncAgentSkills']) assert.ok(skillWriters.includes(method), `missing indirect writer ${method}`);
  return { status: 'draft_policy_checked', tables: owned.length, model_fields: fieldCount, writer_groups: writerSources.length, runtime_ready: false, cross_review_complete: false };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    assert.ok(process.argv.slice(2).every((arg) => arg === '--check'), 'only --check is supported');
    process.stdout.write(`${JSON.stringify(validateSkillHubPolicies(loadSkillHubPolicyInputs()), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
