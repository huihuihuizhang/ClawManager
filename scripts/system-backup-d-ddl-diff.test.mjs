import assert from 'node:assert/strict';
import test from 'node:test';

import { compareDDLCaptures, parseDDLCapture } from './system-backup-d-ddl-diff.mjs';

const registry = {
  contract_version: 'system-backup-plan.v12',
  objects: [{ owner: 'D', object_type: 'table', name: 'd_table' }, { owner: 'A', object_type: 'table', name: 'a_table' }],
};

function capture({ engine = 'InnoDB', clause = '(`id` > 0)', enforced = 1, includeD = true, reverse = false, aComment = '' } = {}) {
  const rows = [
    ['table_option', { table_name: 'a_table', engine: 'InnoDB', table_collation: 'utf8mb4_0900_ai_ci', row_format: 'Dynamic', create_options: '', table_comment: aComment }],
  ];
  if (includeD) rows.push(
    ['table_option', { table_name: 'd_table', engine, table_collation: 'utf8mb4_0900_ai_ci', row_format: 'Dynamic', create_options: '', table_comment: '' }],
    ['check', { table_name: 'd_table', name: 'chk_d_positive', clause, enforced }],
  );
  return `${(reverse ? rows.reverse() : rows).map(([type, value]) => `${type}\t${JSON.stringify(value)}`).join('\n')}\n`;
}

test('DDL diff ignores record order and A-owned table changes', () => {
  const report = compareDDLCaptures(capture(), capture({ reverse: true, aComment: 'changed' }), registry);
  assert.equal(report.matched, true);
  assert.equal(report.table_count, 1);
  assert.equal(report.fresh_d_check_count, 1);
});

test('DDL diff names table option and CHECK clause or enforcement drift', () => {
  const report = compareDDLCaptures(capture(), capture({ engine: 'MyISAM', clause: '(`id` >= 0)', enforced: 0 }), registry);
  assert.equal(report.matched, false);
  assert.deepEqual(report.differences.map((item) => item.path), [
    'table.d_table.options.engine',
    'table.d_table.checks.chk_d_positive.clause',
    'table.d_table.checks.chk_d_positive.enforced',
  ]);
  const missing = compareDDLCaptures(capture(), capture({ includeD: false }), registry);
  assert.ok(missing.differences.some((item) => item.path === 'table.d_table'));
  assert.ok(missing.differences.some((item) => item.path === 'table.d_table.checks.chk_d_positive'));
});

test('DDL parser rejects duplicate or malformed records', () => {
  assert.throws(() => parseDDLCapture(capture() + capture()), /duplicate table option/);
  assert.throws(() => parseDDLCapture('check\t{}\n'), /payload fields are invalid/);
});
