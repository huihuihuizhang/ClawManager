import assert from 'node:assert/strict';
import test from 'node:test';

import { compareDSchemaRecords } from './system-backup-schema-diff.mjs';

const registry = {
  contract_version: 'system-backup-plan.v12',
  objects: [{ owner: 'D', object_type: 'table', name: 'd_table' }, { owner: 'A', object_type: 'table', name: 'a_table' }],
};

function records({ type = 'int', index = 'PRIMARY', includeD = true, reverse = false } = {}) {
  const rows = [
    ['metadata', { server_version: '8.4.8', sql_mode: 'STRICT_TRANS_TABLES' }],
    ['table', { name: 'a_table' }],
    ['column', { table_name: 'a_table', name: 'id', ordinal_position: 1, normalized_type: 'int', nullable: 0, default: null, character_set: null, collation: null, extra: '', generation_expression: null }],
  ];
  if (includeD) rows.push(
    ['table', { name: 'd_table' }],
    ['column', { table_name: 'd_table', name: 'id', ordinal_position: 1, normalized_type: type, nullable: 0, default: null, character_set: null, collation: null, extra: '', generation_expression: null }],
    ['index', { table_name: 'd_table', name: index, kind: index === 'PRIMARY' ? 'primary' : 'ordinary', index_type: 'BTREE', visible: 1, ordinal_position: 1, column_name: 'id', expression: null, prefix_length: null, sort_direction: 'asc' }],
    ['foreign_key', { table_name: 'd_table', name: 'fk_d_a', referenced_table_name: 'a_table', update_rule: 'RESTRICT', delete_rule: 'CASCADE', match_option: 'NONE', ordinal_position: 1, column_name: 'id', referenced_column_name: 'id' }],
  );
  return `${(reverse ? rows.reverse() : rows).map(([kind, payload]) => `${kind}\t${JSON.stringify(payload)}`).join('\n')}\n`;
}

test('D schema diff ignores record ordering and non-D changes', () => {
  const live = records({ reverse: true }).replace('"table_name":"a_table","name":"id","ordinal_position":1,"normalized_type":"int"', '"table_name":"a_table","name":"id","ordinal_position":1,"normalized_type":"bigint"');
  const result = compareDSchemaRecords(records(), live, registry);
  assert.equal(result.matched, true);
  assert.equal(result.table_count, 1);
  assert.equal(result.difference_count, 0);
});

test('D schema diff names changed columns, indexes and missing tables', () => {
  const result = compareDSchemaRecords(records(), records({ type: 'bigint', index: 'idx_d' }), registry);
  assert.equal(result.matched, false);
  assert.ok(result.differences.some((item) => item.path === 'table.d_table.columns.id.normalized_type'));
  assert.ok(result.differences.some((item) => item.path === 'table.d_table.indexes.PRIMARY'));
  assert.ok(result.differences.some((item) => item.path === 'table.d_table.indexes.idx_d'));

  const missing = compareDSchemaRecords(records(), records({ includeD: false }), registry);
  assert.deepEqual(missing.differences, [{ path: 'table.d_table', fresh: 'present', live: 'missing' }]);
});

test('D schema diff rejects incomplete capture records', () => {
  assert.throws(() => compareDSchemaRecords(records(), 'table\t{}\n', registry), /metadata record/);
});
