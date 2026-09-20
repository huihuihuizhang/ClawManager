import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { captureSchemaHashCandidate, kubectlCaptureCommand } from './system-backup-schema-hash-capture.mjs';

const captureSql = 'SELECT 1;';
const records = [
  ['metadata', { server_version: '8.4.8', sql_mode: 'STRICT_TRANS_TABLES' }],
  ['table', { name: 'd_example' }],
  ['column', { table_name: 'd_example', name: 'id', ordinal_position: 1, normalized_type: 'bigint', nullable: 0, default: null, character_set: null, collation: null, extra: '', generation_expression: null }],
].map(([type, payload]) => `${type}\t${JSON.stringify(payload)}`).join('\n') + '\n';
const context = { installation_identity_hash: 'a'.repeat(64), installation_identity_version: 'fixture-v1' };
const inventory = { plan_version: 'system-backup-plan.v12', objects: [{ object_type: 'table', name: 'd_example' }] };
const migrationCatalog = { algorithm: 'sha256-length-prefixed-filename-normalized-content-v1', hash: 'b'.repeat(64) };

function fixtureRun(output = records, exit = 0) {
  return (executable, args, options) => {
    assert.equal(executable, 'mysql');
    assert.deepEqual(args, ['--batch', '--raw', '--skip-column-names']);
    assert.equal(options.input, captureSql);
    assert.equal(options.shell, false);
    return { stdout: Buffer.from(output), stderr: Buffer.from('private connection detail'), status: exit, signal: null, error: null };
  };
}

function withTemporaryRoot(t) {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'system-backup-schema-test-'));
  t.after(() => rmdirSync(temporaryRoot));
  return temporaryRoot;
}

function capture(runCommand, temporaryRoot) {
  return captureSchemaHashCandidate({
    command: ['mysql', '--batch', '--raw', '--skip-column-names'],
    context,
    inventory,
    migrationCatalog,
    captureSql,
    temporaryRoot,
    runCommand,
  });
}

test('schema capture builds a candidate and proves raw records were removed', (t) => {
  const temporaryRoot = withTemporaryRoot(t);
  const candidate = capture(fixtureRun(), temporaryRoot);
  assert.equal(candidate.status, 'candidate');
  assert.equal(candidate.result.object_count, 1);
  assert.equal(candidate.inventory_comparison.matched, true);
  assert.deepEqual(candidate.approved_reviewers, []);
  assert.equal(candidate.registered_evidence, null);
  assert.deepEqual(candidate.records_cleanup.status, 'verified');
  assert.equal(candidate.records_cleanup.verified_absent, true);
  assert.deepEqual(readdirSync(temporaryRoot), []);
});

test('failed capture and malformed records expose no raw output or temporary file', (t) => {
  const temporaryRoot = withTemporaryRoot(t);
  assert.throws(() => capture(fixtureRun('secret-in-stderr', 7), temporaryRoot), (error) => {
    assert.match(error.message, /schema capture failed/);
    assert.doesNotMatch(error.message, /secret-in-stderr/);
    return true;
  });
  assert.deepEqual(readdirSync(temporaryRoot), []);
  assert.throws(() => capture(fixtureRun('not-a-record\n'), temporaryRoot), /record type and JSON payload/);
  assert.deepEqual(readdirSync(temporaryRoot), []);
});

test('schema capture fails closed on incomplete inventory without leaving raw records', (t) => {
  const temporaryRoot = withTemporaryRoot(t);
  assert.throws(() => captureSchemaHashCandidate({
    command: ['mysql', '--batch', '--raw', '--skip-column-names'], context,
    inventory: { plan_version: 'wrong', objects: inventory.objects },
    migrationCatalog, captureSql, temporaryRoot, runCommand: fixtureRun(),
  }), /inventory must use system-backup-plan.v12/);
  assert.deepEqual(readdirSync(temporaryRoot), []);
});

test('kubectl capture uses fixed Pod, stdin SQL and an in-Pod password environment', (t) => {
  const command = kubectlCaptureCommand({ kubectlContext: 'kubernetes-admin@kubernetes', namespace: 'clawmanager-zhanghui08-system', database: 'clawmanager' });
  assert.deepEqual(command.slice(0, 7), ['kubectl', '--context=kubernetes-admin@kubernetes', '--namespace=clawmanager-zhanghui08-system', 'exec', '-i', 'deploy/mysql', '--']);
  assert.match(command[9], /MYSQL_PWD="\$MYSQL_PASSWORD" exec mysql --user="\$MYSQL_USER"/);
  assert.equal(command.at(-1), 'clawmanager');
  assert.throws(() => kubectlCaptureCommand({ kubectlContext: 'a;rm', namespace: 'test', database: 'clawmanager' }), /invalid kubectl capture target/);
  const temporaryRoot = withTemporaryRoot(t);
  const candidate = captureSchemaHashCandidate({ command, context, inventory, migrationCatalog, captureSql, temporaryRoot,
    runCommand: (executable, args, options) => {
      assert.equal(executable, 'kubectl');
      assert.deepEqual(args, command.slice(1));
      assert.equal(options.input, captureSql);
      return { stdout: Buffer.from(records), stderr: Buffer.alloc(0), status: 0, signal: null, error: null };
    },
  });
  assert.equal(candidate.inventory_comparison.matched, true);
  assert.deepEqual(readdirSync(temporaryRoot), []);
});
