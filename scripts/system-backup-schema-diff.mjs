#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalizeObservation, observationFromRecords } from './system-backup-schema-hash.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const maxBytes = 64 * 1024 * 1024;
const maxReportedDifferences = 100;

function objectMap(items) {
  return new Map(items.map((item) => [item.name, item]));
}

function collectValueDifferences(fresh, live, path, output) {
  if (Object.is(fresh, live)) return;
  if (Array.isArray(fresh) && Array.isArray(live)) {
    for (let index = 0; index < Math.max(fresh.length, live.length); index += 1) {
      collectValueDifferences(fresh[index], live[index], `${path}[${index}]`, output);
    }
    return;
  }
  if (fresh && live && typeof fresh === 'object' && typeof live === 'object') {
    for (const key of new Set([...Object.keys(fresh), ...Object.keys(live)])) {
      collectValueDifferences(fresh[key], live[key], `${path}.${key}`, output);
    }
    return;
  }
  output.push({ path, fresh: fresh ?? null, live: live ?? null });
}

function compareNamedMembers(fresh, live, path, differences) {
  const freshMap = objectMap(fresh);
  const liveMap = objectMap(live);
  for (const name of [...new Set([...freshMap.keys(), ...liveMap.keys()])].sort()) {
    const freshMember = freshMap.get(name);
    const liveMember = liveMap.get(name);
    if (!freshMember || !liveMember) {
      differences.push({ path: `${path}.${name}`, fresh: freshMember ? 'present' : 'missing', live: liveMember ? 'present' : 'missing' });
    } else {
      collectValueDifferences(freshMember, liveMember, `${path}.${name}`, differences);
    }
  }
}

export function compareDSchemaRecords(freshRecords, liveRecords, registry) {
  if (registry?.contract_version !== 'system-backup-plan.v12' || !Array.isArray(registry.objects)) {
    throw new Error('schema registry version or objects are invalid');
  }
  const expected = registry.objects.filter((item) => item.owner === 'D');
  if (!expected.length || expected.some((item) => item.object_type !== 'table')) {
    throw new Error('D registry must contain table objects');
  }
  const freshObservation = observationFromRecords(freshRecords);
  const liveObservation = observationFromRecords(liveRecords);
  const fresh = canonicalizeObservation(freshObservation);
  const live = canonicalizeObservation(liveObservation);
  const freshMap = objectMap(fresh.objects.filter((item) => item.object_type === 'table'));
  const liveMap = objectMap(live.objects.filter((item) => item.object_type === 'table'));
  const differences = [];
  if (freshObservation.server_version !== liveObservation.server_version) {
    differences.push({ path: 'server_version', fresh: freshObservation.server_version, live: liveObservation.server_version });
  }
  for (const { name } of expected) {
    const freshTable = freshMap.get(name);
    const liveTable = liveMap.get(name);
    if (!freshTable || !liveTable) {
      differences.push({ path: `table.${name}`, fresh: freshTable ? 'present' : 'missing', live: liveTable ? 'present' : 'missing' });
      continue;
    }
    for (const section of ['columns', 'indexes', 'foreign_keys']) {
      compareNamedMembers(freshTable[section], liveTable[section], `table.${name}.${section}`, differences);
    }
  }
  return {
    kind: 'system_backup_d_schema_diff',
    contract_version: registry.contract_version,
    reference: 'fresh embedded migration replay',
    table_count: expected.length,
    fresh_observed_objects: fresh.objects.length,
    live_observed_objects: live.objects.length,
    difference_count: differences.length,
    differences: differences.slice(0, maxReportedDifferences),
    differences_truncated: differences.length > maxReportedDifferences,
    matched: differences.length === 0,
  };
}

function readRecords(path) {
  const resolved = resolve(path);
  const size = statSync(resolved).size;
  if (size === 0 || size > maxBytes) throw new Error(`${resolved} must be nonempty and at most ${maxBytes} bytes`);
  return new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(resolved));
}

function main() {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== '--fresh' || args[2] !== '--live' || !args[1] || !args[3]) {
    throw new Error('usage: node scripts/system-backup-schema-diff.mjs --fresh <fresh.tsv> --live <live.tsv>');
  }
  if (resolve(args[1]) === resolve(args[3])) throw new Error('fresh and live must be different files');
  const registry = JSON.parse(readFileSync(join(root, 'contracts/system-backup/v12/schema-registry.json'), 'utf8'));
  const freshRecords = readRecords(args[1]);
  const liveRecords = readRecords(args[3]);
  const report = compareDSchemaRecords(freshRecords, liveRecords, registry);
  report.input_sha256 = {
    fresh: createHash('sha256').update(freshRecords, 'utf8').digest('hex'),
    live: createHash('sha256').update(liveRecords, 'utf8').digest('hex'),
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.matched) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
