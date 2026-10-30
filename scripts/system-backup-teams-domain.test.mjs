import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
const root = new URL('../', import.meta.url);
const read = path => JSON.parse(readFileSync(new URL(path, root), 'utf8'));
const contract = read('contracts/system-backup/teams-domain-adapter.v1.json');

test('C SQL shape covers every declared Team table and matches the trusted current repository schema', () => {
  const shape = read(contract.module.schema);
  const current = read('backend/internal/systembackup/schema.json');
  assert.equal(shape.length, 11);
  assert.deepEqual(shape.map(t => t.name).sort(), [...contract.sql_tables].sort());
  for (const table of shape) assert.deepEqual(table, current.find(t => t.name === table.name));
  assert.equal(contract.module.sql_dependency.operation, 'capture-database');
  assert.equal(contract.module.sql_dependency.owner, 'B');
});

test('C decisions preserve explicit cross-owner review and match both registry projections', () => {
  const registry = read('contracts/system-backup/v12/schema-registry.json');
  assert.deepEqual(registry, read('backend/internal/systembackupbusinessa/testdata/schema-registry.json'));
  const decisions = read('contracts/system-backup/v12/schema-registry-decisions.json').decisions;
  for (const name of contract.sql_tables) {
    const row = registry.objects.find(x => x.object_type === 'table' && x.name === name);
    const decision = decisions.find(x => x.object_type === 'table' && x.name === name);
    assert.equal(row.owner, 'C');
    assert.ok(['owner_recorded', 'frozen'].includes(row.decision_status));
    assert.deepEqual(row.required_cross_reviewers, ['A', 'B', 'D']);
    for (const reviewer of row.approved_cross_reviewers) assert.ok(row.required_cross_reviewers.includes(reviewer));
    if (row.decision_status === 'frozen') assert.deepEqual([...row.approved_cross_reviewers].sort(), ['A', 'B', 'D']);
    for (const field of Object.keys(decision)) if (field in row) assert.deepEqual(row[field], decision[field]);
  }
  assert.ok(registry.objects.find(x => x.name === 'owner_team_provision_steps').depends_on.includes('table:northbound_operations'));
  assert.equal(registry.objects.find(x => x.name === 'northbound_operations').owner, 'B');
});

test('the handoff declares real source adapters and keeps unimplemented physical evidence separate', () => {
  assert.deepEqual(contract.operations.map(x => x.name), ['capture-workspace', 'capture-team-redis', 'capture-team-objects']);
  assert.ok(contract.operations.slice(1).every(x => x.provider_mode_only));
  assert.ok(contract.writers.every(x => x.physical_proof.includes('pending')));
  assert.match(contract.production_admission, /acceptance_ready=false/);
});
