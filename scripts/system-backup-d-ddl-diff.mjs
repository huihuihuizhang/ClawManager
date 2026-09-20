#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const maxBytes = 8 * 1024 * 1024;
const maxReportedDifferences = 100;
const tableFields = ['table_name', 'engine', 'table_collation', 'row_format', 'create_options', 'table_comment'];
const checkFields = ['table_name', 'name', 'clause', 'enforced'];

function closedObject(value, fields, line) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`line ${line} payload must be an object`);
  if (fields.some((field) => !(field in value)) || Object.keys(value).some((field) => !fields.includes(field))) {
    throw new Error(`line ${line} payload fields are invalid`);
  }
}

function nullableString(value, line, field) {
  if (value !== null && typeof value !== 'string') throw new Error(`line ${line} ${field} must be a string or null`);
  return value;
}

export function parseDDLCapture(records) {
  const tables = new Map();
  const checks = new Map();
  let count = 0;
  for (const [index, line] of records.split(/\r?\n/).entries()) {
    if (!line) continue;
    count += 1;
    const tab = line.indexOf('\t');
    if (tab < 1) throw new Error(`line ${index + 1} has no record type and JSON payload`);
    const type = line.slice(0, tab);
    let value;
    try { value = JSON.parse(line.slice(tab + 1)); } catch { throw new Error(`line ${index + 1} has invalid JSON`); }
    if (type === 'table_option') {
      closedObject(value, tableFields, index + 1);
      if (typeof value.table_name !== 'string' || !value.table_name) throw new Error(`line ${index + 1} has invalid table name`);
      for (const field of tableFields.slice(1)) nullableString(value[field], index + 1, field);
      if (tables.has(value.table_name)) throw new Error(`duplicate table option for ${value.table_name}`);
      tables.set(value.table_name, value);
    } else if (type === 'check') {
      closedObject(value, checkFields, index + 1);
      if (typeof value.table_name !== 'string' || !value.table_name || typeof value.name !== 'string' || !value.name || typeof value.clause !== 'string' || !value.clause) {
        throw new Error(`line ${index + 1} has invalid CHECK identity or clause`);
      }
      if (![0, 1, true, false].includes(value.enforced)) throw new Error(`line ${index + 1} has invalid CHECK enforcement`);
      const key = `${value.table_name}\0${value.name}`;
      if (checks.has(key)) throw new Error(`duplicate CHECK ${value.table_name}.${value.name}`);
      checks.set(key, { ...value, enforced: Boolean(value.enforced) });
    } else {
      throw new Error(`line ${index + 1} has unknown record type ${type}`);
    }
  }
  if (!count || !tables.size) throw new Error('DDL capture is empty');
  for (const value of checks.values()) {
    if (!tables.has(value.table_name)) throw new Error(`CHECK references missing table option ${value.table_name}`);
  }
  return { tables, checks, record_count: count };
}

function compareFields(fresh, live, fields, path, differences) {
  for (const field of fields) {
    if (!Object.is(fresh[field], live[field])) differences.push({ path: `${path}.${field}`, fresh: fresh[field], live: live[field] });
  }
}

export function compareDDLCaptures(freshRecords, liveRecords, registry) {
  if (registry?.contract_version !== 'system-backup-plan.v12' || !Array.isArray(registry.objects)) {
    throw new Error('schema registry version or objects are invalid');
  }
  const names = registry.objects.filter((item) => item.owner === 'D').map((item) => {
    if (item.object_type !== 'table' || typeof item.name !== 'string') throw new Error('D registry object is not a table');
    return item.name;
  }).sort();
  if (!names.length || new Set(names).size !== names.length) throw new Error('D registry tables are missing or duplicated');
  const fresh = parseDDLCapture(freshRecords);
  const live = parseDDLCapture(liveRecords);
  const differences = [];
  let freshCheckCount = 0;
  let liveCheckCount = 0;
  for (const name of names) {
    const freshTable = fresh.tables.get(name);
    const liveTable = live.tables.get(name);
    if (!freshTable || !liveTable) {
      differences.push({ path: `table.${name}`, fresh: freshTable ? 'present' : 'missing', live: liveTable ? 'present' : 'missing' });
    } else {
      compareFields(freshTable, liveTable, tableFields.slice(1), `table.${name}.options`, differences);
    }
    const freshChecks = new Map([...fresh.checks.values()].filter((item) => item.table_name === name).map((item) => [item.name, item]));
    const liveChecks = new Map([...live.checks.values()].filter((item) => item.table_name === name).map((item) => [item.name, item]));
    freshCheckCount += freshChecks.size;
    liveCheckCount += liveChecks.size;
    for (const checkName of [...new Set([...freshChecks.keys(), ...liveChecks.keys()])].sort()) {
      const freshCheck = freshChecks.get(checkName);
      const liveCheck = liveChecks.get(checkName);
      if (!freshCheck || !liveCheck) {
        differences.push({ path: `table.${name}.checks.${checkName}`, fresh: freshCheck ? 'present' : 'missing', live: liveCheck ? 'present' : 'missing' });
      } else {
        compareFields(freshCheck, liveCheck, ['clause', 'enforced'], `table.${name}.checks.${checkName}`, differences);
      }
    }
  }
  return {
    kind: 'system_backup_d_ddl_diff',
    contract_version: registry.contract_version,
    table_count: names.length,
    fresh_record_count: fresh.record_count,
    live_record_count: live.record_count,
    fresh_d_check_count: freshCheckCount,
    live_d_check_count: liveCheckCount,
    difference_count: differences.length,
    differences: differences.slice(0, maxReportedDifferences),
    differences_truncated: differences.length > maxReportedDifferences,
    matched: differences.length === 0,
  };
}

function readRecords(path) {
  const resolved = resolve(path);
  const size = statSync(resolved).size;
  if (!size || size > maxBytes) throw new Error(`${resolved} must be nonempty and at most ${maxBytes} bytes`);
  return new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(resolved));
}

function main() {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== '--fresh' || args[2] !== '--live' || !args[1] || !args[3]) {
    throw new Error('usage: node scripts/system-backup-d-ddl-diff.mjs --fresh <fresh-ddl.tsv> --live <live-ddl.tsv>');
  }
  if (resolve(args[1]) === resolve(args[3])) throw new Error('fresh and live must be different files');
  const freshRecords = readRecords(args[1]);
  const liveRecords = readRecords(args[3]);
  const registry = JSON.parse(readFileSync(join(root, 'contracts/system-backup/v12/schema-registry.json'), 'utf8'));
  const report = compareDDLCaptures(freshRecords, liveRecords, registry);
  report.input_sha256 = {
    fresh: createHash('sha256').update(freshRecords, 'utf8').digest('hex'),
    live: createHash('sha256').update(liveRecords, 'utf8').digest('hex'),
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.matched) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
