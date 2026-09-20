#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmdirSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildSchemaHashEvidenceCandidate, verifySchemaHashEvidenceCleanup } from './system-backup-schema-hash-evidence.mjs';

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(dirname(scriptPath), '..');
const maxCaptureBytes = 64 * 1024 * 1024;

// The caller supplies only the read-only capture query. Raw records live in a
// private temporary directory until the candidate is built, then are removed
// before any result is returned. This does not register or approve evidence.
export function captureSchemaHashCandidate({ command, context, inventory, migrationCatalog, captureSql, temporaryRoot = tmpdir(), now = () => new Date(), runCommand = spawnSync }) {
  if (!Array.isArray(command) || command.length === 0 || command.some((item) => typeof item !== 'string' || !item)) {
    throw new Error('capture command must be a nonempty argument vector');
  }
  if (typeof captureSql !== 'string' || !captureSql.trim()) throw new Error('capture SQL is required');
  const captureStartedAt = now().toISOString();
  const result = runCommand(command[0], command.slice(1), {
    input: captureSql,
    maxBuffer: maxCaptureBytes,
    timeout: 120_000,
    windowsHide: true,
    shell: false,
  });
  const captureFinishedAt = now().toISOString();
  if (result.error || result.status !== 0 || result.signal) {
    // stderr can contain connection details. Only the exit status is safe to
    // report; never return raw stdout/stderr from a failed capture.
    throw new Error(`schema capture failed (exit=${result.status ?? 'unknown'})`);
  }
  let records;
  try {
    records = new TextDecoder('utf-8', { fatal: true }).decode(result.stdout);
  } catch {
    throw new Error('schema capture output is not valid UTF-8');
  }
  if (!records.trim()) throw new Error('schema capture returned no records');

  const directory = mkdtempSync(join(temporaryRoot, 'system-backup-schema-'));
  const recordsPath = join(directory, 'records.tsv');
  try {
    writeFileSync(recordsPath, records, { flag: 'wx', mode: 0o600 });
    const candidate = buildSchemaHashEvidenceCandidate({
      records,
      recordsPath,
      context: {
        ...context,
        capture_started_at: captureStartedAt,
        capture_finished_at: captureFinishedAt,
      },
      inventory,
      migrationCatalog,
      captureSql,
    });
    unlinkSync(recordsPath);
    return verifySchemaHashEvidenceCleanup(candidate, recordsPath, now().toISOString());
  } finally {
    if (existsSync(recordsPath)) unlinkSync(recordsPath);
    rmdirSync(directory);
  }
}

function parseArgs(args) {
  const localNames = ['--mysql-defaults-file', '--database', '--installation-identity-hash', '--installation-identity-version'];
  const kubectlNames = ['--kubectl-context', '--namespace', '--database', '--installation-identity-hash', '--installation-identity-version'];
  const names = args[0] === '--kubectl-context' ? kubectlNames : localNames;
  if (args.length !== names.length * 2 || names.some((name, index) => args[index * 2] !== name || !args[index * 2 + 1])) {
    throw new Error(`usage: node scripts/system-backup-schema-hash-capture.mjs ${localNames.map((name) => `${name} <value>`).join(' ')} OR ${kubectlNames.map((name) => `${name} <value>`).join(' ')}`);
  }
  const values = args.filter((_, index) => index % 2 === 1);
  const [database, installationIdentityHash, installationIdentityVersion] = names === kubectlNames
    ? [values[2], values[3], values[4]] : [values[1], values[2], values[3]];
  if (!/^[A-Za-z0-9_]+$/.test(database)) throw new Error('database must be a simple MySQL identifier');
  if (names === kubectlNames) {
    const [kubectlContext, namespace] = values;
    if (!/^[A-Za-z0-9][A-Za-z0-9_.@-]*$/.test(kubectlContext)) throw new Error('kubectl context contains invalid characters');
    if (!/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(namespace)) throw new Error('namespace is invalid');
    return { kubectlContext, namespace, database, installationIdentityHash, installationIdentityVersion };
  }
  const resolvedDefaultsFile = resolve(values[0]);
  if (!statSync(resolvedDefaultsFile).isFile()) throw new Error('MySQL defaults file must be a regular file');
  return { resolvedDefaultsFile, database, installationIdentityHash, installationIdentityVersion };
}

export function kubectlCaptureCommand({ kubectlContext, namespace, database }) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.@-]*$/.test(kubectlContext) || !/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(namespace) || !/^[A-Za-z0-9_]+$/.test(database)) {
    throw new Error('invalid kubectl capture target');
  }
  // The fixed SQL arrives on stdin. The password stays inside the Pod's
  // environment and is never included in kubectl arguments or the candidate.
  return ['kubectl', `--context=${kubectlContext}`, `--namespace=${namespace}`, 'exec', '-i', 'deploy/mysql', '--',
    'sh', '-c', 'set -eu; MYSQL_PWD="$MYSQL_PASSWORD" exec mysql --user="$MYSQL_USER" --batch --raw --skip-column-names --default-character-set=utf8mb4 --database="$1"',
    'schema-capture', database];
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const captureSql = readFileSync(join(root, 'contracts/system-backup/v12/schema-hash-capture.mysql.sql'), 'utf8');
  const inventory = JSON.parse(readFileSync(join(root, 'docs/system-backup-restore-schema-inventory.json'), 'utf8'));
  const migrationCatalog = JSON.parse(readFileSync(join(root, 'contracts/system-backup/v12/schema-registry.json'), 'utf8')).migration_catalog;
  const candidate = captureSchemaHashCandidate({
    command: args.kubectlContext ? kubectlCaptureCommand(args) : [
      'mysql', `--defaults-extra-file=${args.resolvedDefaultsFile}`,
      '--batch', '--raw', '--skip-column-names', '--default-character-set=utf8mb4', `--database=${args.database}`,
    ],
    context: {
      installation_identity_hash: args.installationIdentityHash,
      installation_identity_version: args.installationIdentityVersion,
    },
    inventory,
    migrationCatalog,
    captureSql,
  });
  process.stdout.write(`${JSON.stringify(candidate, null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(scriptPath)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
