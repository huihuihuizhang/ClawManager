import assert from 'node:assert/strict';
import test from 'node:test';
import { loadSkillHubPolicyInputs, validateSkillHubPolicies } from './system-backup-skill-hub-policy.mjs';

const baseline = loadSkillHubPolicyInputs();
function inputs() {
  return { ...structuredClone({ ...baseline, readSource: undefined }), readSource: baseline.readSource };
}
const policy = (input, name) => input.policy.policies.find((item) => item.name === name);
const decision = (input, name) => input.decisions.decisions.find((item) => item.name === name);

test('eight policies match actual models, canonical decisions and generated registry without runtime approval', () => {
  const report = validateSkillHubPolicies(inputs());
  assert.equal(report.tables, 8);
  assert.equal(report.runtime_ready, false);
  assert.equal(report.cross_review_complete, false);
});

const cases = [
  ['missing owner', (i) => { delete i.policy.writer_groups[0].owner; }],
  ['delegate own writer', (i) => { i.policy.writer_groups[0].owner = 'B'; }],
  ['claim B runtime writer', (i) => { i.policy.writer_groups.find(g => g.source.endsWith('/skill_runtime_sync.go')).owner = 'C'; }],
  ['claim D scanner', (i) => { i.policy.writer_groups.find(g => g.source.endsWith('/security_scan_service.go')).owner = 'C'; }],
  ['missing table', (i) => i.policy.policies.pop()],
  ['duplicate table', (i) => i.policy.policies.push(i.policy.policies[0])],
  ['undeclared field', (i) => policy(i, 'skills').fields.push('new_execution_state')],
  ['missing field', (i) => policy(i, 'skills').fields.splice(1, 1)],
  ['wrong user mapping', (i) => { policy(i, 'skills').references.user_id = 'instances'; }],
  ['missing instance dependency', (i) => { decision(i, 'instance_skills').depends_on = ['table:skills', 'table:skill_versions']; }],
  ['replay pending job', (i) => { policy(i, 'skill_package_materialize_jobs').state_normalization.mapping.pending = 'pending'; }],
  ['rewrite successful job', (i) => { policy(i, 'skill_package_materialize_jobs').state_normalization.mapping.succeeded = 'cancelled'; }],
  ['omit object mapping', (i) => { policy(i, 'skill_blobs').object_fields = []; }],
  ['omit workspace mapping', (i) => { policy(i, 'instance_skills').workspace_fields = []; }],
  ['invent approval', (i) => decision(i, 'skills').approved_cross_reviewers.push('A')],
  ['self-approved frozen policy', (i) => { decision(i, 'skills').decision_status = 'frozen'; }],
  ['missing B review', (i) => { decision(i, 'instance_skills').required_cross_reviewers = ['A', 'D']; }],
  ['exclude skill payload', (i) => { decision(i, 'skill_blobs').backup_strategy = 'metadata_only'; }],
  ['generated registry drift', (i) => { i.registry.objects.find((x) => x.name === 'skills').owner = 'B'; }],
  ['omit query-side writer', (i) => { const g = i.policy.writer_groups[0]; g.methods = g.methods.filter((x) => x !== 'ListInstanceSkills'); }],
  ['claim writer protection', (i) => { i.policy.writer_groups[0].protection = 'ready'; }],
  ['unknown policy property', (i) => { i.policy.runtime_ready = true; }],
  ['unknown model property', (i) => { policy(i, 'skills').skip_validation = true; }],
  ['omit external security scanner', (i) => { i.policy.writer_groups = i.policy.writer_groups.filter((g) => !g.source.endsWith('/security_scan_service.go')); }],
  ['omit command completion writer', (i) => { i.policy.writer_groups = i.policy.writer_groups.filter((g) => !g.source.endsWith('/instance_command_service.go')); }],
  ['omit workspace deletion writer', (i) => { i.policy.writer_groups = i.policy.writer_groups.filter((g) => !g.source.endsWith('/workspace_file_handler.go')); }],
];
for (const [name, corrupt] of cases) {
  test(`reject ${name}`, () => {
    const input = inputs();
    corrupt(input);
    assert.throws(() => validateSkillHubPolicies(input));
  });
}

test('a new model column requires a policy revision even if the JSON is unchanged', () => {
  const input = inputs();
  input.readSource = (path) => baseline.readSource(path).replace('type Skill struct {', 'type Skill struct {\n AutoRun bool `db:"auto_run"`');
  assert.throws(() => validateSkillHubPolicies(input), /model field coverage drift/);
});

test('a new runnable job state requires a normalization revision', () => {
  const input = inputs();
  input.readSource = (path) => baseline.readSource(path) + (path.endsWith('skill_package_materialize_service.go') ? '\nconst MaterializeJobStatusRetrying = "retrying"\n' : '');
  assert.throws(() => validateSkillHubPolicies(input), /status coverage drift/);
});
