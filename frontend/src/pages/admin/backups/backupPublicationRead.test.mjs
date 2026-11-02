import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

const exports = {};
runInNewContext(ts.transpileModule(readFileSync(new URL('./backupPublicationRead.ts', import.meta.url), 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText, { exports, crypto: webcrypto, TextEncoder, TextDecoder, AbortController, DOMException });
const { createPublicationReadClient } = exports;
const hash = raw => createHash('sha256').update(raw, 'utf8').digest('hex');
const canonical = value => value === null || typeof value !== 'object' ? JSON.stringify(value)
  : Array.isArray(value) ? '[' + value.map(canonical).join(',') + ']'
    : '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
const installation = 'installation_original';
const backup = 'sbk_11111111-1111-4111-8111-111111111111';
const id = 'scr_11111111-1111-5111-8111-111111111111';
const h = 'a'.repeat(64), now = '2026-11-02T09:00:00Z';
const partNames = ['mysql', 'redis', 'object_storage', 'workspace', 'deployment_resources', 'secret_bundle'];
const response = (raw, headers = {}, status = 200) => new Response(raw, { status, headers: { 'Content-Type': 'application/json', 'X-System-Backup-Data-Source': 'live', ...headers } });
const signal = () => new AbortController().signal;

// Explicit unsigned CONTENT data. These tests establish byte/schema/request
// boundaries, never client signature trust, Ready or a backup execution receipt.
function fixture(changeManifest = x => x) {
  const manifest = changeManifest({
    schema_version: 'system-backup.v1', app_version: 'content<source>&😀', git_commit: '0123456789abcdef', generated_at: now,
    origin_installation_id: installation, backup_public_id: backup, attempt_no: 1, orchestrator: 'kubernetes', deployment_profile: 'cluster', runner_type: 'kubernetes', task_purpose: 'functional_test',
    migration_catalog_hash: h, schema_hash: h, capture_context_hash: h, capture_certificate_hash: h,
    target: { target_class: 'same-cluster-copy', failure_domain_id: 'original-domain', risks: [], attestation_id: null, attestation_hash: null },
    kek_recovery: { provider: 'external-kms', key_id: 'content', key_version: '1', source_independent: false, recovery_proof_hash: null },
    consistency: 'strong', precommit_eligibility: { required_parts_complete: true, required_verifiers_complete: true, disqualifier_codes: ['functional_test', 'attestation_invalid', 'kek_not_recoverable'], inputs_hash: h },
    parts: Object.fromEntries(partNames.map(name => [name, { required: true, status: 'completed', consistency: 'strong', checkpoint_type: 'gate_staging', checkpoint_hash: h, captured_at: now, objects: 1, bytes: 1, ciphertext_sha256: h, evidence_ids: ['sev_content'] }])),
    artifact_index: { path: 'artifact-index.json', checksum: h }, commit_marker: { path: '_COMMITTED', schema_version: 'system-backup-committed.v1' },
    control_evidence: { path: 'control/evidence.json.enc', schema_version: 'system-backup-control-evidence.v1', checksum: h }, secret_policy: { registry_version: '1', registry_hash: h, required_entries: 1, captured_entries: 1 },
    schema_object_coverage: { registry_version: '1', registry_hash: h, covered: 1, excluded: 0 }, config_recovery: { config_version: 1, snapshot_hash: h, redacted_parameters: {} },
    business_summaries: Object.fromEntries(['users', 'instances', 'ai_gateway', 'teams', 'resources', 'skill_hub'].map(name => [name, { objects: 1, rows: 1, bytes: 1, verifier_summary_hash: h }])), warnings: [],
  });
  const manifestRaw = canonical(manifest);
  const record = { payload: {
    schema_version: 'system-backup-catalog-record.v1', origin_installation_id: installation, backup_public_id: backup, attempt_no: 1, record_id: id, recorded_at: now,
    signing_key: { purpose: 'catalog_record', key_id: 'content<source>&😀', key_version: '1' }, event_type: 'artifact_registered',
    manifest: { provider: 's3', identity_hash: h, key: `${installation}/${backup}/1/manifest.json`, version: 'original-v1' },
    manifest_checksum: hash(manifestRaw), marker_checksum: h, acceptance_checksum: h, capture_certificate_hash: h, artifact_index_checksum: h,
  }, signature: { algorithm: 'EdDSA', domain_separator: 'clawmanager.system-backup.catalog_record.v1', key_id: 'content<source>&😀', key_purpose: 'catalog_record', key_version: '1', protected_header: 'CONTENT', value: 'A'.repeat(86) } };
  const raw = canonical(record), item = { id, record_sha256: hash(raw), record };
  const detail = { task: { public_id: backup, origin_installation_id: installation, status: 'succeeded', config_version: 1 }, task_purpose: 'functional_test', artifact_state: 'committed', artifact_registration_id: id, artifact_registration_hash: hash(raw), requested_parts: partNames,
    checksums: { manifest: hash(manifestRaw), index: h, marker: h, acceptance: h, catalog: hash(raw) } };
  return { raw, item, detail, manifestRaw };
}

test('original nested canonical bytes and manifest bytes are hashed without object reserialization', async () => {
  const f = fixture(), paths = [];
  const client = createPublicationReadClient(async path => { paths.push(path); return response(path.endsWith('/manifest') ? f.manifestRaw : canonical(f.item)); });
  const r = await client.record(installation, id, signal());
  assert.equal(r.raw, f.raw); assert.equal(r.record_sha256, hash(f.raw));
  const m = await client.manifest(f.detail, signal());
  assert.equal(m.raw, f.manifestRaw); assert.equal(m.sha256, hash(f.manifestRaw));
  assert.equal(paths.at(-1), `/api/v1/admin/system-backups/${backup}/manifest`);
  assert.equal(f.detail.task_purpose, 'functional_test'); // READ never changes purpose/eligibility.
});

test('catalog rejects duplicates, aliases, unknown fields, noncanonical records and hash drift', async () => {
  const f = fixture(), original = canonical(f.item);
  for (const body of [
    original.replace('"id":', '"id":"' + id + '","id":'),
    original.replace('"id":', '"\\u0069d":"' + id + '","id":'),
    original.replace('"record":', '"unknown":true,"record":'),
    original.replace('"payload":{', '"payload": {'),
    original.replace('content<source>', 'changed<source>'),
    original.replace('"attempt_no":1', '"attempt_no":9007199254740992'),
    original + '{}',
  ]) await assert.rejects(createPublicationReadClient(async () => response(body)).record(installation, id, signal()));
  const other = JSON.parse(original); other.record.payload.origin_installation_id = 'installation_other'; other.record_sha256 = hash(canonical(other.record));
  await assert.rejects(createPublicationReadClient(async () => response(canonical(other))).record(installation, id, signal()));
});

test('eventual local pagination is closed, bounded and refuses duplicate IDs/cursors', async () => {
  const f = fixture(); let path;
  const client = body => createPublicationReadClient(async p => { path = p; return response(canonical(body)); });
  const page = await client({ items: [f.item], next_cursor: 'abc.def', consistency: 'eventual' }).catalog(installation, signal());
  assert.equal(page.items.length, 1); assert.equal(path, '/api/v1/admin/system-backup-catalog-records?limit=50');
  for (const body of [
    { items: [f.item, f.item], next_cursor: null, consistency: 'eventual' },
    { items: [], next_cursor: null, consistency: 'stable_cutoff' },
    { items: [], next_cursor: null, consistency: 'eventual', approved: true },
    { items: [], next_cursor: 'abc.def', consistency: 'eventual' },
  ]) await assert.rejects(client(body).catalog(installation, signal(), 'abc.def'));
});

test('manifest rejects original-byte drift, mismatched registration and unknown nested fields', async () => {
  const f = fixture();
  for (const manifest of [f.manifestRaw + '\n', f.manifestRaw.replace('content<source>', 'changed<source>')]) {
    const client = createPublicationReadClient(async path => response(path.endsWith('/manifest') ? manifest : canonical(f.item)));
    await assert.rejects(client.manifest(f.detail, signal()));
  }
  const changed = fixture(m => ({ ...m, target: { ...m.target, claimed_ready: true } }));
  await assert.rejects(createPublicationReadClient(async path => response(path.endsWith('/manifest') ? changed.manifestRaw : canonical(changed.item))).manifest(changed.detail, signal()));
  await assert.rejects(createPublicationReadClient(async () => response(canonical(f.item))).manifest({ ...f.detail, artifact_registration_hash: h }, signal()));
});

test('authorization, non-live, invalid UTF8, oversized bodies and aborted reads never return success', async () => {
  const f = fixture();
  for (const r of [response('{}', {}, 401), response('{}', {}, 403), response('{}', {}, 503), response(canonical(f.item), { 'X-System-Backup-Data-Source': 'preview' }), response('<html>error</html>', { 'Content-Type': 'text/html' }), response(' '.repeat(20001)), response(new Uint8Array([0xff]))]) {
    await assert.rejects(createPublicationReadClient(async () => r).record(installation, id, signal()));
  }
  const controller = new AbortController(); controller.abort();
  await assert.rejects(createPublicationReadClient(async () => response(canonical(f.item))).record(installation, id, controller.signal));
});

test('publication transport preserves raw text and uses the existing authenticated interceptor', async () => {
  const raw = '{"record":"<source>&😀"}', calls = [], service = {};
  runInNewContext(ts.transpileModule(readFileSync(new URL('../../../services/systemBackupReadService.ts', import.meta.url), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
  }).outputText, { exports: service, Response, require: name => {
    if (name === 'axios') return { isAxiosError: () => false };
    if (name === './api') return { get: async (...args) => { calls.push(args); return { status: 200, data: raw, headers: { 'content-type': 'application/json', 'x-system-backup-data-source': 'live' } }; } };
    if (name.endsWith('backupApiRead')) return { createBackupApiReadClient: () => ({}) };
    if (name.endsWith('backupPublicationRead')) return { createPublicationReadClient: transport => ({ transport }) };
    throw new Error(name);
  } });
  const s = signal();
  const r = await service.systemBackupPublicationReadService.transport(`/api/v1/admin/system-backups/${backup}/manifest`, s);
  assert.equal(await r.text(), raw); assert.equal(calls[0][0], `/admin/system-backups/${backup}/manifest`);
  assert.equal(calls[0][1].signal, s); assert.equal(calls[0][1].responseType, 'text');
  assert.equal(calls[0][1].transformResponse[0](raw), raw);
});
