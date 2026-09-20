#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const contractVersion = 'system-backup-plan.v12';
const algorithm = 'sha256-information-schema-canonical-v1';
const objectTypes = new Set(['table', 'view', 'trigger', 'routine', 'mysql_event']);

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
function compareText(left, right) {
  const leftPoints = [...left].map((character) => character.codePointAt(0));
  const rightPoints = [...right].map((character) => character.codePointAt(0));
  for (let index = 0; index < Math.min(leftPoints.length, rightPoints.length); index += 1) {
    if (leftPoints[index] !== rightPoints[index]) return leftPoints[index] - rightPoints[index];
  }
  return leftPoints.length - rightPoints.length;
}

function canonicalJSON(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`;
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort(compareText).map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(',')}}`;
  }
  throw new Error('canonical schema input contains an unsupported JSON value');
}

function expectObject(value, context) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${context} must be a JSON object`);
  }
}

function expectClosed(value, required, context) {
  expectObject(value, context);
  const allowed = new Set(required);
  const missing = required.filter((key) => !(key in value));
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (missing.length) throw new Error(`${context} is missing ${missing.join(', ')}`);
  if (unknown.length) throw new Error(`${context} has unknown fields ${unknown.join(', ')}`);
}

function expectString(value, context, { allowEmpty = false } = {}) {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0)) throw new Error(`${context} must be a string`);
  return value;
}

function expectNullableString(value, context) {
  if (value !== null) expectString(value, context, { allowEmpty: true });
  return value;
}

function expectBoolean(value, context) {
  if (typeof value !== 'boolean') throw new Error(`${context} must be a boolean`);
  return value;
}

function expectNullableBoolean(value, context) {
  if (value !== null) expectBoolean(value, context);
  return value;
}

function expectPosition(value, context) {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${context} must be a positive integer`);
  return value;
}

function expectNullablePosition(value, context) {
  if (value !== null) expectPosition(value, context);
  return value;
}

function expectArray(value, context) {
  if (!Array.isArray(value)) throw new Error(`${context} must be an array`);
  return value;
}

function assertUnique(items, key, context) {
  const seen = new Set();
  for (const item of items) {
    const value = key(item);
    if (seen.has(value)) throw new Error(`${context} contains duplicate ${value}`);
    seen.add(value);
  }
}

function assertContiguous(items, context) {
  for (const [index, item] of items.entries()) {
    if (item.ordinal_position !== index + 1) throw new Error(`${context} ordinal positions must be contiguous from 1`);
  }
}

function parseRecordPayload(payload, required, context) {
  expectClosed(payload, required, context);
  return payload;
}

function captureBoolean(value, context) {
  if (value === true || value === 1) return true;
  if (value === false || value === 0) return false;
  throw new Error(`${context} must be a JSON boolean or 0/1`);
}

export function observationFromRecords(text) {
  const records = [];
  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    if (!rawLine) continue;
    const separator = rawLine.indexOf('\t');
    if (separator < 1) throw new Error(`records line ${index + 1} must contain record type and JSON payload`);
    const recordType = rawLine.slice(0, separator);
    let payload;
    try {
      payload = JSON.parse(rawLine.slice(separator + 1));
    } catch {
      throw new Error(`records line ${index + 1} has invalid JSON payload`);
    }
    records.push({ recordType, payload, line: index + 1 });
  }

  const metadataRecords = records.filter((record) => record.recordType === 'metadata');
  if (metadataRecords.length !== 1) throw new Error('records must contain exactly one metadata record');
  const metadata = parseRecordPayload(metadataRecords[0].payload, ['server_version', 'sql_mode'], `records line ${metadataRecords[0].line}`);
  expectString(metadata.server_version, 'metadata.server_version');
  expectString(metadata.sql_mode, 'metadata.sql_mode', { allowEmpty: true });

  const tables = new Map();
  const definitions = [];
  for (const record of records.filter((item) => item.recordType === 'table')) {
    const context = `records line ${record.line}`;
    const payload = parseRecordPayload(record.payload, ['name'], context);
    const name = expectString(payload.name, `${context}.name`);
    if (tables.has(name)) throw new Error(`records contain duplicate table:${name}`);
    tables.set(name, { object_type: 'table', name, columns: [], indexes: new Map(), foreign_keys: new Map() });
  }
  for (const record of records) {
    const context = `records line ${record.line}`;
    if (record.recordType === 'metadata') continue;
    if (record.recordType === 'table') continue;
    if (record.recordType === 'definition') {
      const payload = parseRecordPayload(record.payload, ['object_type', 'name', 'definition'], context);
      if (!objectTypes.has(payload.object_type) || payload.object_type === 'table') throw new Error(`${context}.object_type is invalid`);
      definitions.push({
        object_type: payload.object_type,
        name: expectString(payload.name, `${context}.name`),
        definition: expectString(payload.definition, `${context}.definition`, { allowEmpty: true }),
      });
      continue;
    }
    if (!['column', 'index', 'foreign_key'].includes(record.recordType)) throw new Error(`${context} has unknown record type ${record.recordType}`);

    const commonFields = record.recordType === 'column'
      ? ['table_name', 'name', 'ordinal_position', 'normalized_type', 'nullable', 'default', 'character_set', 'collation', 'extra', 'generation_expression']
      : record.recordType === 'index'
        ? ['table_name', 'name', 'kind', 'index_type', 'visible', 'ordinal_position', 'column_name', 'expression', 'prefix_length', 'sort_direction']
        : ['table_name', 'name', 'referenced_table_name', 'update_rule', 'delete_rule', 'match_option', 'ordinal_position', 'column_name', 'referenced_column_name'];
    const payload = parseRecordPayload(record.payload, commonFields, context);
    const tableName = expectString(payload.table_name, `${context}.table_name`);
    const table = tables.get(tableName);
    if (!table) throw new Error(`${context} references unknown table:${tableName}`);

    if (record.recordType === 'column') {
      table.columns.push({
        name: payload.name,
        ordinal_position: payload.ordinal_position,
        normalized_type: payload.normalized_type,
        nullable: captureBoolean(payload.nullable, `${context}.nullable`),
        default: payload.default,
        character_set: payload.character_set,
        collation: payload.collation,
        extra: payload.extra,
        generation_expression: payload.generation_expression,
      });
      continue;
    }

    if (record.recordType === 'index') {
      const name = expectString(payload.name, `${context}.name`);
      const header = { kind: payload.kind, index_type: payload.index_type, visible: captureBoolean(payload.visible, `${context}.visible`) };
      const existing = table.indexes.get(name);
      if (existing && (existing.kind !== header.kind || existing.index_type !== header.index_type || existing.visible !== header.visible)) {
        throw new Error(`${context} conflicts with other rows for index ${tableName}.${name}`);
      }
      const index = existing ?? { name, ...header, columns: [] };
      index.columns.push({
        ordinal_position: payload.ordinal_position,
        column_name: payload.column_name,
        expression: payload.expression,
        prefix_length: payload.prefix_length,
        sort_direction: payload.sort_direction,
      });
      table.indexes.set(name, index);
      continue;
    }

    const name = expectString(payload.name, `${context}.name`);
    const header = {
      referenced_table_name: payload.referenced_table_name,
      update_rule: payload.update_rule,
      delete_rule: payload.delete_rule,
      match_option: payload.match_option,
    };
    const existing = table.foreign_keys.get(name);
    if (existing && Object.keys(header).some((key) => existing[key] !== header[key])) {
      throw new Error(`${context} conflicts with other rows for foreign key ${tableName}.${name}`);
    }
    const foreignKey = existing ?? { name, ...header, columns: [] };
    foreignKey.columns.push({
      ordinal_position: payload.ordinal_position,
      column_name: payload.column_name,
      referenced_column_name: payload.referenced_column_name,
    });
    table.foreign_keys.set(name, foreignKey);
  }

  const objects = [
    ...[...tables.values()].map((table) => ({
      object_type: table.object_type,
      name: table.name,
      columns: table.columns,
      indexes: [...table.indexes.values()],
      foreign_keys: [...table.foreign_keys.values()],
    })),
    ...definitions,
  ];
  return {
    kind: 'system_backup_information_schema_observation',
    contract_version: contractVersion,
    algorithm,
    server_version: metadata.server_version,
    sql_mode: metadata.sql_mode,
    objects,
  };
}

function normalizeColumn(column, context) {
  expectClosed(column, ['name', 'ordinal_position', 'normalized_type', 'nullable', 'default', 'character_set', 'collation', 'extra', 'generation_expression'], context);
  return {
    name: expectString(column.name, `${context}.name`),
    ordinal_position: expectPosition(column.ordinal_position, `${context}.ordinal_position`),
    normalized_type: expectString(column.normalized_type, `${context}.normalized_type`),
    nullable: expectBoolean(column.nullable, `${context}.nullable`),
    default: expectNullableString(column.default, `${context}.default`),
    character_set: expectNullableString(column.character_set, `${context}.character_set`),
    collation: expectNullableString(column.collation, `${context}.collation`),
    extra: expectString(column.extra, `${context}.extra`, { allowEmpty: true }),
    generation_expression: expectNullableString(column.generation_expression, `${context}.generation_expression`),
  };
}

function normalizeIndexColumn(column, context) {
  expectClosed(column, ['ordinal_position', 'column_name', 'expression', 'prefix_length', 'sort_direction'], context);
  const normalized = {
    ordinal_position: expectPosition(column.ordinal_position, `${context}.ordinal_position`),
    column_name: expectNullableString(column.column_name, `${context}.column_name`),
    expression: expectNullableString(column.expression, `${context}.expression`),
    prefix_length: expectNullablePosition(column.prefix_length, `${context}.prefix_length`),
    sort_direction: column.sort_direction,
  };
  if ((normalized.column_name === null) === (normalized.expression === null)) {
    throw new Error(`${context} must contain exactly one of column_name or expression`);
  }
  if (![null, 'asc', 'desc'].includes(normalized.sort_direction)) {
    throw new Error(`${context}.sort_direction must be asc, desc or null`);
  }
  return normalized;
}

function normalizeIndex(index, context) {
  expectClosed(index, ['name', 'kind', 'index_type', 'visible', 'columns'], context);
  const name = expectString(index.name, `${context}.name`);
  if (!['primary', 'unique', 'ordinary'].includes(index.kind)) throw new Error(`${context}.kind is invalid`);
  if ((index.kind === 'primary') !== (name === 'PRIMARY')) throw new Error(`${context} primary index must be named PRIMARY and only PRIMARY may use primary kind`);
  const columns = expectArray(index.columns, `${context}.columns`)
    .map((column, position) => normalizeIndexColumn(column, `${context}.columns[${position}]`))
    .sort((left, right) => left.ordinal_position - right.ordinal_position);
  if (!columns.length) throw new Error(`${context}.columns must not be empty`);
  assertContiguous(columns, `${context}.columns`);
  return {
    name,
    kind: index.kind,
    index_type: expectString(index.index_type, `${context}.index_type`),
    visible: expectNullableBoolean(index.visible, `${context}.visible`),
    columns,
  };
}

function normalizeForeignKeyColumn(column, context) {
  expectClosed(column, ['ordinal_position', 'column_name', 'referenced_column_name'], context);
  return {
    ordinal_position: expectPosition(column.ordinal_position, `${context}.ordinal_position`),
    column_name: expectString(column.column_name, `${context}.column_name`),
    referenced_column_name: expectString(column.referenced_column_name, `${context}.referenced_column_name`),
  };
}

function normalizeForeignKey(foreignKey, context) {
  expectClosed(foreignKey, ['name', 'referenced_table_name', 'update_rule', 'delete_rule', 'match_option', 'columns'], context);
  const columns = expectArray(foreignKey.columns, `${context}.columns`)
    .map((column, position) => normalizeForeignKeyColumn(column, `${context}.columns[${position}]`))
    .sort((left, right) => left.ordinal_position - right.ordinal_position);
  if (!columns.length) throw new Error(`${context}.columns must not be empty`);
  assertContiguous(columns, `${context}.columns`);
  return {
    name: expectString(foreignKey.name, `${context}.name`),
    referenced_table_name: expectString(foreignKey.referenced_table_name, `${context}.referenced_table_name`),
    update_rule: expectString(foreignKey.update_rule, `${context}.update_rule`),
    delete_rule: expectString(foreignKey.delete_rule, `${context}.delete_rule`),
    match_option: expectString(foreignKey.match_option, `${context}.match_option`),
    columns,
  };
}

function normalizeTable(table, context) {
  expectClosed(table, ['object_type', 'name', 'columns', 'indexes', 'foreign_keys'], context);
  const columns = expectArray(table.columns, `${context}.columns`)
    .map((column, position) => normalizeColumn(column, `${context}.columns[${position}]`))
    .sort((left, right) => left.ordinal_position - right.ordinal_position);
  if (!columns.length) throw new Error(`${context}.columns must not be empty`);
  assertContiguous(columns, `${context}.columns`);
  assertUnique(columns, (column) => column.name, `${context}.columns`);

  const indexes = expectArray(table.indexes, `${context}.indexes`)
    .map((index, position) => normalizeIndex(index, `${context}.indexes[${position}]`))
    .sort((left, right) => compareText(left.name, right.name));
  assertUnique(indexes, (index) => index.name, `${context}.indexes`);
  if (indexes.filter((index) => index.kind === 'primary').length > 1) throw new Error(`${context} has multiple primary indexes`);

  const foreignKeys = expectArray(table.foreign_keys, `${context}.foreign_keys`)
    .map((foreignKey, position) => normalizeForeignKey(foreignKey, `${context}.foreign_keys[${position}]`))
    .sort((left, right) => compareText(left.name, right.name));
  assertUnique(foreignKeys, (foreignKey) => foreignKey.name, `${context}.foreign_keys`);

  return {
    object_type: 'table',
    name: expectString(table.name, `${context}.name`),
    columns,
    indexes,
    foreign_keys: foreignKeys,
  };
}

function normalizeNonTable(object, context, serverVersion, sqlMode) {
  expectClosed(object, ['object_type', 'name', 'definition'], context);
  if (typeof serverVersion !== 'string' || !serverVersion) throw new Error('server_version is required when non-table objects are present');
  if (typeof sqlMode !== 'string') throw new Error('sql_mode is required when non-table objects are present');
  const definition = expectString(object.definition, `${context}.definition`, { allowEmpty: true }).replace(/\r\n?/g, '\n');
  return {
    object_type: object.object_type,
    name: expectString(object.name, `${context}.name`),
    server_version: serverVersion,
    sql_mode: sqlMode,
    definition_sha256: sha256(Buffer.from(definition, 'utf8')),
  };
}

export function canonicalizeObservation(observation) {
  expectClosed(observation, ['kind', 'contract_version', 'algorithm', 'server_version', 'sql_mode', 'objects'], 'observation');
  if (observation.kind !== 'system_backup_information_schema_observation') throw new Error('observation.kind is invalid');
  if (observation.contract_version !== contractVersion) throw new Error(`observation.contract_version must be ${contractVersion}`);
  if (observation.algorithm !== algorithm) throw new Error(`observation.algorithm must be ${algorithm}`);
  if (observation.server_version !== null) expectString(observation.server_version, 'observation.server_version');
  if (observation.sql_mode !== null) expectString(observation.sql_mode, 'observation.sql_mode', { allowEmpty: true });

  const objects = expectArray(observation.objects, 'observation.objects').map((object, position) => {
    expectObject(object, `observation.objects[${position}]`);
    if (!objectTypes.has(object.object_type)) throw new Error(`observation.objects[${position}].object_type is invalid`);
    return object.object_type === 'table'
      ? normalizeTable(object, `observation.objects[${position}]`)
      : normalizeNonTable(object, `observation.objects[${position}]`, observation.server_version, observation.sql_mode);
  }).sort((left, right) => compareText(left.object_type, right.object_type) || compareText(left.name, right.name));
  assertUnique(objects, (object) => `${object.object_type}:${object.name}`, 'observation.objects');
  return { algorithm, objects };
}

export function computeSchemaHash(observation) {
  const canonical = canonicalizeObservation(observation);
  const canonicalBytes = Buffer.from(canonicalJSON(canonical), 'utf8');
  const objectCounts = Object.fromEntries([...objectTypes].sort(compareText).map((type) => [type, canonical.objects.filter((object) => object.object_type === type).length]));
  return {
    kind: 'system_backup_schema_hash_result',
    contract_version: contractVersion,
    algorithm,
    hash: sha256(canonicalBytes),
    canonical_bytes_length: canonicalBytes.length,
    object_count: canonical.objects.length,
    object_counts: objectCounts,
  };
}

function main() {
  const args = process.argv.slice(2);
  if (args.length !== 2 || !['--input', '--records'].includes(args[0]) || !args[1]) {
    throw new Error('usage: node scripts/system-backup-schema-hash.mjs (--input <observation.json> | --records <capture.tsv>)');
  }
  const input = readFileSync(resolve(args[1]), 'utf8');
  const observation = args[0] === '--input' ? JSON.parse(input) : observationFromRecords(input);
  process.stdout.write(`${JSON.stringify(computeSchemaHash(observation), null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
