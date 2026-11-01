#!/usr/bin/env node
// Offline material review ONLY. No subprocess, network, credential discovery,
// cluster connection, SQL execution, migration, deployment or file cleanup.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, lstatSync } from 'node:fs';
import { resolve, posix, parse, sep, relative, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderCapacityDeployment, jsonBytes, root } from './system-backup-d-capacity-deployment.mjs';
import { checkFreshReference } from './system-backup-d-runtime-preflight.mjs';

export const onsiteChecks = Object.freeze([
  'Reobserve namespace/Pod/node/PVC/PV UIDs and CSI/NFS backing isolation immediately before execution.',
  'On the pinned node, verify Runtime image digest, UID/GID, DAC permissions and authorized mounts without chown or fsGroup on source data.',
  'Run system-backup-d-runtime-preflight.mjs explicitly onsite; check fresh schema/reference provenance and capacity source/report permissions.',
  'Use system-backup-d-observer-sql-preflight.sh with an independently provisioned observer; verify actual identity, TLS, no roles/wildcard/write grants and denied writes.',
  'Authenticate catalog/manifest/container, SecretPolicy and every key version through existing A contracts; local material presence proves no authorization.',
  'Provision a fresh isolated target and current fence; verify distinct source/target credentials, database, object bucket/prefix, Redis history namespace and workspace mounts.',
  'After restore Job exit, revoke writer credentials and test authentication failure before independent SQL/object/file/Redis readback.',
  'Verify nonempty users/instances/Teams/eight Skill tables, versioned object bytes, edited installation/workspace files and no active queue replay; originally stopped instances stay stopped.',
  'Inject cancellation/failure and reconcile owned partial targets and source writer recovery; do not clean other runs or retry into partial targets.',
]);

// Files must be staged inside THIS local checkout. Reject lexical escapes
// before even lstat: a UNC/URL/device/ADS path must never reach the filesystem.
// Walk every existing ancestor without following symlinks/junctions. The
// checkout and its parent directories must remain locally owned during review.
export function localMaterialPath(raw, { directory = root, inspect = lstatSync, output = false } = {}) {
  assert.ok(typeof raw === 'string' && raw.length > 0 && raw.length <= 4096);
  assert.ok(!/[\x00-\x1f]/.test(raw) && !/^[\\/]{2}/.test(raw));
  assert.ok(!/^[a-z][a-z0-9+.-]*:/i.test(raw) || /^[a-z]:[\\/]/i.test(raw));
  assert.ok(!raw.replace(/^[a-z]:/i, '').includes(':')); // ADS and URL schemes
  assert.ok(raw.split(/[\\/]/).every(p => p !== '..' && !/[. ]$/.test(p) && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(p)));
  const base = resolve(directory), file = resolve(base, raw), rel = relative(base, file);
  assert.ok(rel && !rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel));
  const anchor = parse(base).root;
  // root is from the running local module, never an input-supplied drive.
  let current = anchor;
  const components = file.slice(anchor.length).split(sep);
  for (let i = 0; i < components.length; i++) {
    current = resolve(current, components[i]);
    if (output && i === components.length - 1) break; // wx rejects existing leaves
    const stat = inspect(current);
    assert.ok(!stat.isSymbolicLink());
    assert.ok(i === components.length - 1 ? stat.isFile() && stat.size <= (16 << 20) : stat.isDirectory());
  }
  return file;
}

export function reviewOfflineRestoreMaterials(input = {}) {
  assert.ok(input && typeof input === 'object' && !Array.isArray(input));
  assert.ok(Object.keys(input).every(k => ['capacity_plan', 'fresh_reference', 'public_inventory', 'observer_observation', 'restore_target'].includes(k)));
  const checks = [], missing = [];
  const check = (name, fn) => {
    let passed = false;
    try { passed = fn() === true; } catch { /* never echo supplied values/errors */ }
    checks.push({ name, passed }); if (!passed) missing.push(name);
  };
  check('capacity_plan_matches_existing_local_contract', () => {
    const rendered = renderCapacityDeployment(input.capacity_plan);
    return rendered.report.initial_replicas === 0 && rendered.report.cluster_checked === false;
  });
  check('fresh_reference_bytes_and_migration_catalog', () => {
    checkFreshReference(input.fresh_reference); return true;
  });
  check('public_runtime_node_and_mount_inventory', () => {
    const p = input.capacity_plan, doc = input.public_inventory;
    assert.equal(doc.kind, 'List'); assert.ok(Array.isArray(doc.items) && doc.items.length <= 10000);
    assert.ok(doc.items.every(x => ['Namespace', 'Pod', 'Node', 'PersistentVolumeClaim', 'PersistentVolume'].includes(x.kind)));
    const select = (kind, name) => {
      const xs = doc.items.filter(x => x.kind === kind && x.metadata?.name === name);
      assert.equal(xs.length, 1); return xs[0];
    };
    assert.equal(select('Namespace', p.namespace).metadata.uid, p.namespace_uid);
    const pod = select('Pod', p.mysql_pod), node = select('Node', p.mysql_node);
    assert.equal(pod.metadata.uid, p.mysql_pod_uid); assert.equal(pod.metadata.namespace, p.namespace);
    assert.equal(pod.spec.nodeName, p.mysql_node); assert.ok(node.metadata.uid);
    const container = pod.spec.containers.find(c => c.name === p.mysql_container);
    const mount = container.volumeMounts.find(m => m.mountPath === p.data_directory);
    assert.ok(mount && !mount.subPathExpr && (mount.subPath ?? '') === p.mysql_data_subpath);
    assert.equal(pod.spec.volumes.find(v => v.name === mount.name)?.persistentVolumeClaim?.claimName, p.mysql_data_pvc);
    const source = select('PersistentVolumeClaim', p.mysql_data_pvc), report = select('PersistentVolumeClaim', p.report_pvc);
    for (const pvc of [source, report]) {
      assert.equal(pvc.metadata.namespace, p.namespace); assert.ok(pvc.metadata.uid);
      assert.equal(pvc.status.phase, 'Bound'); assert.ok(pvc.spec.volumeName);
    }
    assert.notEqual(source.spec.volumeName, report.spec.volumeName);
    assert.ok(report.spec.accessModes.includes('ReadWriteMany'));
    return true;
  });
  check('observer_saved_tuple_is_explicitly_read_only', () => {
    const x = input.observer_observation;
    assert.equal(x.schemaVersion, 'system-backup-sql-observation.v1');
    assert.equal(x.readOnly, true); assert.equal(x.snapshotRolledBack, true); assert.equal(x.tupleBound, true);
    assert.match(x.publicID, /^(sbk|spf)_[0-9a-f-]{36}$/);
    assert.ok(typeof x.installationID === 'string' && x.installationID.length > 0);
    assert.ok(Number.isSafeInteger(x.configVersion) && x.configVersion > 0);
    return true; // saved bytes only; account/grants/revocation require onsite proof
  });
  check('isolated_restore_target_plan_has_distinct_public_identities', () => {
    const t = input.restore_target;
    assert.deepEqual(Object.keys(t).sort(), ['namespace', 'database', 'server_uuid', 'writer_user', 'verifier_user', 'workspace', 'object_bucket', 'object_prefix', 'redis_history_prefix'].sort());
    assert.match(t.namespace, /^cm-drill-[a-z0-9-]{1,45}$/); assert.match(t.database, /^cm_drill_[a-z0-9_]{1,50}$/);
    assert.match(t.server_uuid, /^[a-f0-9-]{36}$/);
    for (const k of ['writer_user', 'verifier_user']) { assert.match(t[k], /^[a-z][a-z0-9_]{0,31}$/); assert.notEqual(t[k], 'root'); }
    assert.notEqual(t.writer_user, t.verifier_user);
    assert.ok(t.database !== input.capacity_plan.database || t.server_uuid !== input.capacity_plan.server_uuid);
    assert.ok(posix.isAbsolute(t.workspace) && posix.normalize(t.workspace) === t.workspace && t.workspace !== '/' && !/[\\\x00-\x1f]/.test(t.workspace));
    assert.match(t.object_bucket, /^cm-drill-[a-z0-9-]+$/);
    assert.match(t.object_prefix, /^restore\/[a-z0-9-]+\/$/);
    assert.match(t.redis_history_prefix, /^cm:restore-history:[a-z0-9_-]+:$/);
    return true;
  });
  return {
    schema_version: 'd-offline-restore-material-review.v1',
    status: missing.length ? 'MISSING_LOCAL_MATERIALS' : 'LOCAL_MATERIALS_REVIEWED',
    mode: 'offline', network_attempted: false, cluster_checked: false, database_mutated: false,
    credentials_read: false, readiness_proven: false, acceptance_eligible: false,
    checks, missing_materials: missing, onsite_required: [...onsiteChecks],
    security_inputs: ['A authenticated SecretPolicy/signer/capability/provider and KEK coverage contracts; never plaintext credentials'],
    limitation: 'Caller-supplied saved observations may be stale or fabricated. This report cannot authorize execution or prove production readiness.',
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2), opts = {};
    for (let i = 0; i < args.length; i += 2) {
      assert.ok(['--input', '--output'].includes(args[i]) && args[i+1] && !opts[args[i]]); opts[args[i]] = args[i+1];
    }
    let input = {};
    if (opts['--input']) {
      const file = localMaterialPath(opts['--input']);
      input = JSON.parse(readFileSync(file, 'utf8'));
    }
    const report = reviewOfflineRestoreMaterials(input);
    if (opts['--output']) writeFileSync(localMaterialPath(opts['--output'], { output: true }), jsonBytes(report), { flag: 'wx' });
    console.log(jsonBytes(report)); process.exitCode = report.missing_materials.length ? 2 : 0;
  } catch { console.error('Offline restore material input rejected; no connection or mutation attempted.'); process.exitCode = 1; }
}
