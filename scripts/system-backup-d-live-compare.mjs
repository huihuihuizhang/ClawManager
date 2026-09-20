#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { compareDDLCaptures } from './system-backup-d-ddl-diff.mjs';
import { compareDSchemaRecords } from './system-backup-schema-diff.mjs';
import { computeSchemaHash, observationFromRecords } from './system-backup-schema-hash.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const flags = ['--fresh-schema', '--live-schema', '--fresh-ddl', '--live-ddl'];
if (args.length !== 8 || flags.some((flag, index) => args[index * 2] !== flag || !args[index * 2 + 1])) {
  throw new Error(`usage: node scripts/system-backup-d-live-compare.mjs ${flags.map((flag) => `${flag} <tsv>`).join(' ')}`);
}

const paths = args.filter((_, index) => index % 2 === 1).map((path) => resolve(path));
if (new Set(paths).size !== paths.length) throw new Error('capture inputs must be different files');
const records = paths.map((path, index) => {
  const limit = index < 2 ? 64 * 1024 * 1024 : 8 * 1024 * 1024;
  const size = statSync(path).size;
  if (!size || size > limit) throw new Error(`capture ${index + 1} must be nonempty and at most ${limit} bytes`);
  return new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(path));
});
const registry = JSON.parse(readFileSync(join(root, 'contracts/system-backup/v12/schema-registry.json'), 'utf8'));
const [freshSchema, liveSchema, freshDDL, liveDDL] = records;
const schema = compareDSchemaRecords(freshSchema, liveSchema, registry);
const ddl = compareDDLCaptures(freshDDL, liveDDL, registry);
const freshHash = computeSchemaHash(observationFromRecords(freshSchema));
const liveHash = computeSchemaHash(observationFromRecords(liveSchema));
const fullSchemaMatched = freshHash.hash === liveHash.hash;
const report = {
  kind: 'system_backup_d_live_comparison',
  contract_version: registry.contract_version,
  input_sha256: Object.fromEntries(flags.map((flag, index) => [flag.slice(2).replaceAll('-', '_'), createHash('sha256').update(records[index], 'utf8').digest('hex')])),
  full_schema: {
    fresh_hash: freshHash.hash,
    live_hash: liveHash.hash,
    fresh_object_count: freshHash.object_count,
    live_object_count: liveHash.object_count,
    matched: fullSchemaMatched,
  },
  d_schema: {
    table_count: schema.table_count,
    difference_count: schema.difference_count,
    difference_paths: schema.differences.map((item) => item.path),
    differences_truncated: schema.differences_truncated,
    matched: schema.matched,
  },
  d_ddl: {
    table_count: ddl.table_count,
    fresh_check_count: ddl.fresh_d_check_count,
    live_check_count: ddl.live_d_check_count,
    difference_count: ddl.difference_count,
    difference_paths: ddl.differences.map((item) => item.path),
    differences_truncated: ddl.differences_truncated,
    matched: ddl.matched,
  },
  matched: fullSchemaMatched && schema.matched && ddl.matched,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (!report.matched) process.exitCode = 1;
