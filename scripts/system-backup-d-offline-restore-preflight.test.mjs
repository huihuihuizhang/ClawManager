import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, unlinkSync, mkdtempSync, rmdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import { capacityTemplate, root } from './system-backup-d-capacity-deployment.mjs';
import { reviewOfflineRestoreMaterials, localMaterialPath } from './system-backup-d-offline-restore-preflight.mjs';

test('default offline execution reports missing materials and cannot claim readiness', () => {
  const result = spawnSync(process.execPath, ['scripts/system-backup-d-offline-restore-preflight.mjs'], { encoding: 'utf8', windowsHide: true, env: { ...process.env, KUBECONFIG: 'do-not-open', SBK_OBSERVER_DSN_FILE: 'do-not-open' } });
  assert.equal(result.status, 2);
  const report = JSON.parse(result.stdout);
  assert.equal(report.missing_materials.length, 5);
  for (const flag of ['network_attempted', 'cluster_checked', 'database_mutated', 'credentials_read', 'readiness_proven', 'acceptance_eligible']) assert.equal(report[flag], false);
  assert.ok(report.onsite_required.some(x => x.includes('revoke writer')));
});

test('reuses capacity contract and rejects unsafe target without reflecting secrets', () => {
  const p = { ...capacityTemplate(), namespace_uid: 'uid', context: 'offline', image: `example.invalid/image@sha256:${'a'.repeat(64)}`, mysql_pod: 'mysql', mysql_pod_uid: 'pod-uid', mysql_container: 'mysql', mysql_node: 'node', mysql_data_pvc: 'mysql-data', server_uuid: '11111111-2222-3333-4444-555555555555', collector_db_user: 'reader', collector_uid: 999, credentials_secret: 'dsn-reference', report_pvc: 'report' };
  const report = reviewOfflineRestoreMaterials({ capacity_plan: p, restore_target: { password: 'NEVER_EMIT' } });
  assert.equal(report.checks[0].passed, true);
  assert.ok(report.missing_materials.includes('isolated_restore_target_plan_has_distinct_public_identities'));
  assert.ok(!JSON.stringify(report).includes('NEVER_EMIT'));
  assert.throws(() => reviewOfflineRestoreMaterials({ live: true }));
  assert.throws(() => reviewOfflineRestoreMaterials({ remote_command: 'kubectl' }));
});

test('entry point has no subprocess/network execution and no live opt-in', () => {
  const code = readFileSync(new URL('./system-backup-d-offline-restore-preflight.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(code, /from ['"]node:(child_process|http|https|net|tls|dgram)['"]/);
  assert.doesNotMatch(code, /runRuntimePreflight\s*\(|fetch\s*\(/);
  const live = spawnSync(process.execPath, ['scripts/system-backup-d-offline-restore-preflight.mjs', '--live', 'true'], { encoding: 'utf8', windowsHide: true });
  assert.equal(live.status, 1); assert.equal(live.stdout, '');
});

test('remote/device/ADS/escape paths fail before any filesystem probe for read and write', () => {
  for (const raw of ['\\\\server\\share\\file.json', '//server/share/file.json', '\\\\?\\C:\\file', '\\\\.\\NUL', 'https://host/file', 'file://host/file', 'C:relative', 'material.json:stream', '../outside', 'a/../outside', 'NUL', 'aux.json', 'folder./file', 'file\0name']) {
    for (const output of [false, true]) {
      let probes = 0;
      assert.throws(() => localMaterialPath(raw, { output, inspect() { probes++; throw new Error('must not probe'); } }), raw);
      assert.equal(probes, 0, raw);
    }
  }
});

test('existing ancestor junction/symlink blocks reads and output without following it', () => {
  for (const output of [false, true]) {
    let probes = 0;
    assert.throws(() => localMaterialPath('docs/review.json', { output, inspect() {
      probes++; return { isSymbolicLink: () => true, isDirectory: () => true, isFile: () => true, size: 1 };
    } }));
    assert.equal(probes, 1);
  }
});

test('local JSON larger than sixteen bytes is accepted and output never overwrites', () => {
  const directory = mkdtempSync(join(root, '.offline-review-test-'));
  const input = join(directory, 'input.json'), output = join(directory, 'output.json');
  try {
    writeFileSync(input, JSON.stringify({ capacity_plan: {} }, null, 2));
    assert.ok(readFileSync(input).length > 16);
    assert.equal(localMaterialPath(input), input);
    const args = ['scripts/system-backup-d-offline-restore-preflight.mjs', '--input', relative(root,input), '--output', relative(root,output)];
    const result = spawnSync(process.execPath,args,{encoding:'utf8',windowsHide:true});
    assert.equal(result.status,2,result.stderr);
    assert.equal(JSON.parse(readFileSync(output,'utf8')).mode,'offline');
    const before = readFileSync(output);
    assert.equal(spawnSync(process.execPath,args,{encoding:'utf8',windowsHide:true}).status,1);
    assert.deepEqual(readFileSync(output),before);
  } finally { for(const path of [input,output]) { try { unlinkSync(path); } catch {} } rmdirSync(directory); }
});

test('material file size enforces sixteen MiB including exact boundary', () => {
  for (const size of [17,16 << 20,(16 << 20)+1]) {
    const options={inspect:()=>({isSymbolicLink:()=>false,isDirectory:()=>true,isFile:()=>true,size})};
    if(size <= (16 << 20)) assert.ok(localMaterialPath('docs/synthetic.json',options));
    else assert.throws(()=>localMaterialPath('docs/synthetic.json',options));
  }
});
