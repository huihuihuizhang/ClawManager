import assert from 'node:assert/strict';
import test from 'node:test';
import { computeSchemaHash, observationFromRecords } from './system-backup-schema-hash.mjs';

function fixture() {
  return {
    kind: 'system_backup_information_schema_observation',
    contract_version: 'system-backup-plan.v12',
    algorithm: 'sha256-information-schema-canonical-v1',
    server_version: '8.0.40',
    sql_mode: 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION',
    objects: [
      {
        object_type: 'table',
        name: 'example_children',
        columns: [
          { name: 'id', ordinal_position: 1, normalized_type: 'bigint unsigned', nullable: false, default: null, character_set: null, collation: null, extra: 'auto_increment', generation_expression: null },
          { name: 'parent_id', ordinal_position: 2, normalized_type: 'bigint unsigned', nullable: false, default: null, character_set: null, collation: null, extra: '', generation_expression: null },
          { name: 'label', ordinal_position: 3, normalized_type: 'varchar(64)', nullable: true, default: null, character_set: 'utf8mb4', collation: 'utf8mb4_0900_ai_ci', extra: '', generation_expression: null }
        ],
        indexes: [
          { name: 'idx_example_parent', kind: 'ordinary', index_type: 'BTREE', visible: true, columns: [{ ordinal_position: 1, column_name: 'parent_id', expression: null, prefix_length: null, sort_direction: 'asc' }] },
          { name: 'PRIMARY', kind: 'primary', index_type: 'BTREE', visible: true, columns: [{ ordinal_position: 1, column_name: 'id', expression: null, prefix_length: null, sort_direction: 'asc' }] }
        ],
        foreign_keys: [
          { name: 'fk_example_parent', referenced_table_name: 'example_parents', update_rule: 'RESTRICT', delete_rule: 'CASCADE', match_option: 'NONE', columns: [{ ordinal_position: 1, column_name: 'parent_id', referenced_column_name: 'id' }] }
        ]
      },
      {
        object_type: 'view',
        name: 'example_child_names',
        definition: 'select `example_children`.`id` AS `id`\r\nfrom `example_children`'
      }
    ]
  };
}

test('schema hash has a fixed canonical test vector', () => {
  const result = computeSchemaHash(fixture());
  assert.equal(result.kind, 'system_backup_schema_hash_result');
  assert.equal(result.algorithm, 'sha256-information-schema-canonical-v1');
  assert.equal(result.object_count, 2);
  assert.deepEqual(result.object_counts, { mysql_event: 0, routine: 0, table: 1, trigger: 0, view: 1 });
  assert.equal(result.hash, 'f103576c96dc5d4272e9692d5173aaccb4d1a014706527713f1132272b85b801');
});

test('schema hash ignores observation order and non-table line-ending style', () => {
  const original = fixture();
  const reordered = fixture();
  reordered.objects.reverse();
  reordered.objects.find((object) => object.object_type === 'table').columns.reverse();
  reordered.objects.find((object) => object.object_type === 'table').indexes.reverse();
  reordered.objects.find((object) => object.object_type === 'view').definition = reordered.objects.find((object) => object.object_type === 'view').definition.replace('\r\n', '\n');
  assert.equal(computeSchemaHash(reordered).hash, computeSchemaHash(original).hash);
});

test('schema hash changes when a structural table field changes', () => {
  const changed = fixture();
  changed.objects.find((object) => object.object_type === 'table').columns[2].nullable = false;
  assert.notEqual(computeSchemaHash(changed).hash, computeSchemaHash(fixture()).hash);
});

test('schema hash rejects ambiguous or open observations', () => {
  const duplicate = fixture();
  duplicate.objects.push(structuredClone(duplicate.objects[0]));
  assert.throws(() => computeSchemaHash(duplicate), /duplicate table:example_children/);

  const open = fixture();
  open.objects[0].engine = 'InnoDB';
  assert.throws(() => computeSchemaHash(open), /unknown fields engine/);

  const missingContext = fixture();
  missingContext.server_version = null;
  assert.throws(() => computeSchemaHash(missingContext), /server_version is required/);
});

test('read-only capture records assemble to the same canonical observation', () => {
  const source = fixture();
  const table = source.objects.find((object) => object.object_type === 'table');
  const view = source.objects.find((object) => object.object_type === 'view');
  const rows = [
    ['metadata', { server_version: source.server_version, sql_mode: source.sql_mode }],
    ['table', { name: table.name }],
    ...table.columns.map((column) => ['column', { table_name: table.name, ...column, nullable: column.nullable ? 1 : 0 }]),
    ...table.indexes.flatMap((index) => index.columns.map((column) => ['index', { table_name: table.name, name: index.name, kind: index.kind, index_type: index.index_type, visible: index.visible ? 1 : 0, ...column }])),
    ...table.foreign_keys.flatMap((foreignKey) => foreignKey.columns.map((column) => ['foreign_key', { table_name: table.name, name: foreignKey.name, referenced_table_name: foreignKey.referenced_table_name, update_rule: foreignKey.update_rule, delete_rule: foreignKey.delete_rule, match_option: foreignKey.match_option, ...column }])),
    ['definition', view],
  ];
  const records = `${rows.reverse().map(([type, payload]) => `${type}\t${JSON.stringify(payload)}`).join('\n')}\n`;
  assert.equal(computeSchemaHash(observationFromRecords(records)).hash, computeSchemaHash(source).hash);
});

test('capture records fail closed on non-boolean information_schema flags', () => {
  const records = [
    ['metadata', { server_version: '8.0.40', sql_mode: '' }],
    ['table', { name: 'example' }],
    ['column', { table_name: 'example', name: 'id', ordinal_position: 1, normalized_type: 'bigint', nullable: 'NO', default: null, character_set: null, collation: null, extra: '', generation_expression: null }],
  ].map(([type, payload]) => `${type}\t${JSON.stringify(payload)}`).join('\n');
  assert.throws(() => observationFromRecords(records), /nullable must be a JSON boolean or 0\/1/);
});
