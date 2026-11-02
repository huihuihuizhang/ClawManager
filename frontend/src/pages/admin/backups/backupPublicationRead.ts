import type { BackupDetailResource } from '../../../types/systemBackupContract';

export type PublicationTransport = (path: string, signal: AbortSignal) => Promise<Response>;
type ObjectValue = Record<string, unknown>;
type JSONNode = { value: unknown; start: number; end: number; members?: Map<string, JSONNode>; items?: JSONNode[] };
const digest = /^[0-9a-f]{64}$/;
const recordID = /^scr_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const backupID = /^sbk_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const installationID = /^installation_[A-Za-z0-9._:-]{1,115}$/;
const parts = ['mysql', 'redis', 'object_storage', 'workspace', 'deployment_resources', 'secret_bundle'];
const invalid = (): never => { throw new Error('invalid_publication_response'); };
const object = (value: unknown): ObjectValue => value !== null && typeof value === 'object' && !Array.isArray(value) ? value as ObjectValue : invalid();
const closed = (value: unknown, fields: string, optional = ''): ObjectValue => {
  const v = object(value), required = fields.split(' '), allowed = new Set([...required, ...optional.split(' ')]);
  if (required.some(k => !Object.hasOwn(v, k)) || Object.keys(v).some(k => !allowed.has(k))) invalid();
  return v;
};
const string = (v: unknown, max = 256): string => typeof v === 'string' && v.length > 0 && v.length <= max ? v : invalid();
const sum = (v: unknown): string => typeof v === 'string' && digest.test(v) ? v : invalid();
const count = (v: unknown): number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? v : invalid();
const positive = (v: unknown): number => count(v) > 0 ? v as number : invalid();
const oneOf = (v: unknown, allowed: string[]): string => allowed.includes(string(v)) ? v as string : invalid();
const strings = (v: unknown, max: number): string[] => {
  if (!Array.isArray(v) || v.length > max || v.some(x => typeof x !== 'string') || new Set(v).size !== v.length) invalid();
  return v as string[];
};
const date = (v: unknown): string => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(string(v, 64)) && Number.isFinite(Date.parse(v as string)) ? v as string : invalid();
const nullableSum = (v: unknown) => { if (v !== null) sum(v); };
const hasControl = (value: string) => Array.from(value).some(ch => ch.charCodeAt(0) < 32);

// Retain source spans and reject decoded duplicate keys before creating objects.
// No parsed object is serialized to obtain a hash. Bounds apply to all nested data.
function parseJSON(text: string): JSONNode {
  let at = 0, nodes = 0;
  const white = () => { while (/[\x20\t\r\n]/.test(text[at] ?? '') && at < text.length) at++; };
  const quoted = (): string => {
    const begin = at++;
    while (at < text.length) {
      const ch = text[at++];
      if (ch === '\\') { at++; continue; }
      if (ch === '"') {
        let value: unknown;
        try { value = JSON.parse(text.slice(begin, at)); } catch { return invalid(); }
        if (typeof value !== 'string') return invalid();
        for (let i = 0; i < value.length; i++) {
          const c = value.charCodeAt(i);
          if (c >= 0xd800 && c <= 0xdbff) { const next = value.charCodeAt(++i); if (!(next >= 0xdc00 && next <= 0xdfff)) invalid(); }
          else if (c >= 0xdc00 && c <= 0xdfff) invalid();
        }
        return value;
      }
    }
    return invalid();
  };
  const value = (depth: number): JSONNode => {
    white();
    if (depth > 32 || ++nodes > 100000) invalid();
    const start = at;
    if (text[at] === '{') {
      at++; white();
      const members = new Map<string, JSONNode>(), result: ObjectValue = Object.create(null);
      if (text[at] !== '}') while (true) {
        white(); if (text[at] !== '"') invalid();
        const key = quoted(); white(); if (text[at++] !== ':' || members.has(key)) invalid();
        const child = value(depth + 1); members.set(key, child); result[key] = child.value; white();
        if (text[at] === '}') break;
        if (text[at++] !== ',') invalid();
      }
      at++; return { value: result, start, end: at, members };
    }
    if (text[at] === '[') {
      at++; white(); const items: JSONNode[] = [];
      if (text[at] !== ']') while (true) {
        items.push(value(depth + 1)); white(); if (text[at] === ']') break;
        if (text[at++] !== ',') invalid();
      }
      at++; return { value: items.map(x => x.value), start, end: at, items };
    }
    if (text[at] === '"') { const result = quoted(); return { value: result, start, end: at }; }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at))?.[0];
    if (!token) return invalid();
    at += token.length;
    const result: unknown = JSON.parse(token);
    if (typeof result === 'number' && (!Number.isFinite(result) || Number.isInteger(result) && !Number.isSafeInteger(result))) invalid();
    return { value: result, start, end: at };
  };
  const root = value(0); white(); if (at !== text.length) invalid(); return root;
}

function canonical(node: JSONNode, text: string): boolean {
  const raw = text.slice(node.start, node.end);
  if (node.members) {
    const keys = [...node.members.keys()];
    if (keys.some((k, i) => i > 0 && keys[i - 1] >= k)) return false;
    return keys.every(k => canonical(node.members!.get(k)!, text)) && raw === '{' + keys.map(k => JSON.stringify(k) + ':' + text.slice(node.members!.get(k)!.start, node.members!.get(k)!.end)).join(',') + '}';
  }
  if (node.items) return node.items.every(n => canonical(n, text)) && raw === '[' + node.items.map(n => text.slice(n.start, n.end)).join(',') + ']';
  return raw === JSON.stringify(node.value); // primitives only, never an object hash
}

async function sha(raw: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw));
  return [...new Uint8Array(hash)].map(n => n.toString(16).padStart(2, '0')).join('');
}

async function responseText(response: Response, signal: AbortSignal, maximum: number): Promise<string> {
  signal.throwIfAborted();
  if (response.status !== 200 || response.headers.get('X-System-Backup-Data-Source') !== 'live'
      || !/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '') || !response.body) return invalid();
  const reader = response.body.getReader(), chunks: Uint8Array[] = []; let size = 0;
  const abort = () => { void reader.cancel(); };
  signal.addEventListener('abort', abort, { once: true });
  try {
    while (true) {
      signal.throwIfAborted(); const part = await reader.read(); signal.throwIfAborted();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > maximum) { await reader.cancel(); invalid(); }
      chunks.push(part.value);
    }
  } finally { signal.removeEventListener('abort', abort); reader.releaseLock(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
}

export interface CatalogRecord {
  id: string; record_sha256: string; raw: string;
  backup: string; installation: string; attempt: number; manifestSHA256: string;
  indexSHA256: string; markerSHA256: string; acceptanceSHA256: string; captureSHA256: string;
}
export interface CatalogPage { items: CatalogRecord[]; next_cursor: string | null; consistency: 'eventual' }
export interface PublicationManifest { raw: string; sha256: string }

async function catalogItem(node: JSONNode, text: string, installation: string): Promise<CatalogRecord> {
  const item = closed(node.value, 'id record_sha256 record');
  if (!recordID.test(string(item.id))) invalid(); sum(item.record_sha256);
  const record = node.members?.get('record');
  if (!record || record.end - record.start > 16384 || !canonical(record, text)) return invalid();
  const raw = text.slice(record.start, record.end);
  if (new TextEncoder().encode(raw).byteLength > 16384 || await sha(raw) !== item.record_sha256) invalid();
  const envelope = closed(item.record, 'payload signature');
  const p = closed(envelope.payload, 'schema_version origin_installation_id backup_public_id attempt_no record_id recorded_at signing_key event_type manifest manifest_checksum marker_checksum acceptance_checksum capture_certificate_hash artifact_index_checksum');
  if (p.schema_version !== 'system-backup-catalog-record.v1' || p.event_type !== 'artifact_registered' || p.origin_installation_id !== installation || p.record_id !== item.id || !backupID.test(string(p.backup_public_id))) invalid();
  positive(p.attempt_no); date(p.recorded_at);
  const key = closed(p.signing_key, 'purpose key_id key_version');
  if (key.purpose !== 'catalog_record') invalid(); string(key.key_id); string(key.key_version, 128);
  const locator = closed(p.manifest, 'provider identity_hash key version');
  if (locator.provider !== 's3') invalid(); sum(locator.identity_hash);
  const path = string(locator.key, 1024), version = string(locator.version);
  if (path.startsWith('/') || path.includes('\\') || hasControl(path) || path.split('/').some(x => !x || x === '.' || x === '..') || !path.endsWith('/' + p.backup_public_id + '/' + p.attempt_no + '/manifest.json') || ['latest', 'current', 'null'].includes(version) || hasControl(version)) invalid();
  const sig = closed(envelope.signature, 'algorithm domain_separator key_id key_purpose key_version protected_header value');
  if (sig.algorithm !== 'EdDSA' || sig.domain_separator !== 'clawmanager.system-backup.catalog_record.v1' || sig.key_purpose !== 'catalog_record' || sig.key_id !== key.key_id || sig.key_version !== key.key_version) invalid();
  for (const field of ['protected_header', 'value']) if (!/^[A-Za-z0-9_-]+$/.test(string(sig[field], field === 'value' ? 512 : 4096))) invalid();
  if ((sig.value as string).length !== 86) invalid();
  sum(p.capture_certificate_hash);
  return { id: item.id as string, record_sha256: item.record_sha256 as string, raw, backup: p.backup_public_id as string, installation, attempt: p.attempt_no as number, manifestSHA256: sum(p.manifest_checksum), indexSHA256: sum(p.artifact_index_checksum), markerSHA256: sum(p.marker_checksum), acceptanceSHA256: sum(p.acceptance_checksum), captureSHA256: sum(p.capture_certificate_hash) };
}

function manifestShape(value: unknown, detail: BackupDetailResource, record: CatalogRecord) {
  const m = closed(value, 'schema_version app_version git_commit generated_at origin_installation_id backup_public_id attempt_no orchestrator deployment_profile runner_type task_purpose migration_catalog_hash schema_hash capture_context_hash capture_certificate_hash target kek_recovery consistency precommit_eligibility parts artifact_index commit_marker control_evidence secret_policy schema_object_coverage config_recovery business_summaries warnings');
  if (m.schema_version !== 'system-backup.v1' || m.origin_installation_id !== detail.task.origin_installation_id || m.backup_public_id !== detail.task.public_id || m.attempt_no !== record.attempt || m.task_purpose !== detail.task_purpose || m.capture_certificate_hash !== record.captureSHA256) invalid();
  string(m.app_version, 128); if (!/^[a-f0-9]{7,64}$/.test(string(m.git_commit, 64))) invalid(); date(m.generated_at);
  oneOf(m.orchestrator, ['kubernetes', 'k3s']); oneOf(m.deployment_profile, ['cluster', 'single-node']); if (m.runner_type !== 'kubernetes') invalid();
  oneOf(m.consistency, ['strong', 'bounded', 'weak']);
  for (const field of ['migration_catalog_hash', 'schema_hash', 'capture_context_hash', 'capture_certificate_hash']) sum(m[field]);
  const target = closed(m.target, 'target_class failure_domain_id risks attestation_id attestation_hash');
  oneOf(target.target_class, ['dr-ready-external', 'same-cluster-copy']); string(target.failure_domain_id, 128);
  for (const risk of strings(target.risks, 12)) oneOf(risk, ['source_overlap', 'same_failure_domain', 'artifact_credential_source_dependent', 'kek_source_dependent', 'signing_key_source_dependent', 'catalog_source_dependent', 'attestation_missing', 'attestation_expired', 'conditional_commit_unavailable', 'transport_unverified', 'broad_egress', 'provider_capability_degraded']);
  nullableSum(target.attestation_hash);
  if (target.attestation_id !== null) string(target.attestation_id, 128);
  if ((target.attestation_id === null) !== (target.attestation_hash === null)) invalid();
  const kek = closed(m.kek_recovery, 'provider key_id key_version source_independent recovery_proof_hash');
  oneOf(kek.provider, ['external-kms', 'external-secret', 'k8s-secret']); string(kek.key_id); string(kek.key_version, 128); nullableSum(kek.recovery_proof_hash);
  if (typeof kek.source_independent !== 'boolean' || kek.source_independent && kek.recovery_proof_hash === null) invalid();
  const eligibility = closed(m.precommit_eligibility, 'required_parts_complete required_verifiers_complete disqualifier_codes inputs_hash');
  if (eligibility.required_parts_complete !== true || eligibility.required_verifiers_complete !== true) invalid();
  for (const reason of strings(eligibility.disqualifier_codes, 7)) oneOf(reason, ['functional_test', 'consistency_not_strong', 'disqualifying_warning', 'target_not_external', 'target_risk', 'attestation_invalid', 'kek_not_recoverable']);
  sum(eligibility.inputs_hash);
  const captured = closed(m.parts, detail.requested_parts.join(' '));
  if (detail.requested_parts.some(p => !parts.includes(p))) invalid();
  for (const part of Object.values(captured)) {
    const p = closed(part, 'required status consistency checkpoint_type checkpoint_hash captured_at objects bytes ciphertext_sha256 evidence_ids');
    if (p.required !== true || p.status !== 'completed') invalid(); oneOf(p.consistency, ['strong', 'bounded', 'weak']);
    oneOf(p.checkpoint_type, ['mysql_transaction', 'redis_rdb', 'redis_scan_window', 'csi_snapshot', 'object_version_copy', 'gate_staging']); sum(p.checkpoint_hash); date(p.captured_at); count(p.objects); count(p.bytes); sum(p.ciphertext_sha256); strings(p.evidence_ids, 10000);
  }
  const index = closed(m.artifact_index, 'path checksum'); if (index.path !== 'artifact-index.json' || index.checksum !== record.indexSHA256) invalid();
  const marker = closed(m.commit_marker, 'path schema_version'); if (marker.path !== '_COMMITTED' || marker.schema_version !== 'system-backup-committed.v1') invalid();
  const control = closed(m.control_evidence, 'path schema_version checksum'); if (control.path !== 'control/evidence.json.enc' || control.schema_version !== 'system-backup-control-evidence.v1') invalid(); sum(control.checksum);
  const secret = closed(m.secret_policy, 'registry_version registry_hash required_entries captured_entries'); string(secret.registry_version, 128); sum(secret.registry_hash); if (count(secret.captured_entries) < count(secret.required_entries)) invalid();
  const coverage = closed(m.schema_object_coverage, 'registry_version registry_hash covered excluded'); string(coverage.registry_version, 128); sum(coverage.registry_hash); count(coverage.covered); count(coverage.excluded);
  const config = closed(m.config_recovery, 'config_version snapshot_hash redacted_parameters'); if (config.config_version !== detail.task.config_version) invalid(); sum(config.snapshot_hash); if (Object.keys(object(config.redacted_parameters)).length > 64) invalid();
  const business = closed(m.business_summaries, 'users instances ai_gateway teams resources skill_hub');
  for (const summary of Object.values(business)) { const v = closed(summary, 'objects rows bytes verifier_summary_hash'); count(v.objects); count(v.rows); count(v.bytes); sum(v.verifier_summary_hash); }
  if (!Array.isArray(m.warnings) || m.warnings.length > 10000) invalid();
  for (const warning of m.warnings as unknown[]) { const v = closed(warning, 'code category disqualifying', 'details_hash'); string(v.code, 128); oneOf(v.category, ['data-integrity-warning', 'consistency-warning', 'operational-warning', 'unsupported-evidence-warning']); if (typeof v.disqualifying !== 'boolean') invalid(); if (Object.hasOwn(v, 'details_hash')) nullableSum(v.details_hash); }
}

export function createPublicationReadClient(transport: PublicationTransport) {
  const scope = (installation: string) => { if (!installationID.test(installation)) invalid(); };
  const read = async (path: string, signal: AbortSignal, max: number) => { signal.throwIfAborted(); return responseText(await transport(path, signal), signal, max); };
  return {
    async catalog(installation: string, signal: AbortSignal, cursor?: string): Promise<CatalogPage> {
      scope(installation); if (cursor !== undefined && (!/^[A-Za-z0-9_.-]+$/.test(cursor) || cursor.length > 4096)) invalid();
      const text = await read('/api/v1/admin/system-backup-catalog-records?limit=50' + (cursor ? '&cursor=' + encodeURIComponent(cursor) : ''), signal, 1 << 20);
      const root = parseJSON(text), page = closed(root.value, 'items next_cursor consistency');
      if (page.consistency !== 'eventual' || !Array.isArray(page.items) || page.items.length > 50 || page.next_cursor !== null && (typeof page.next_cursor !== 'string' || !/^[A-Za-z0-9_.-]{1,4096}$/.test(page.next_cursor))) invalid();
      const items: CatalogRecord[] = [];
      for (const node of root.members!.get('items')!.items ?? []) { signal.throwIfAborted(); items.push(await catalogItem(node, text, installation)); }
      signal.throwIfAborted(); if (new Set(items.map(i => i.id)).size !== items.length || page.next_cursor === cursor) invalid();
      return { items, next_cursor: page.next_cursor as string | null, consistency: 'eventual' };
    },
    async record(installation: string, id: string, signal: AbortSignal): Promise<CatalogRecord> {
      scope(installation); if (!recordID.test(id)) invalid();
      const text = await read('/api/v1/admin/system-backup-catalog-records/' + id, signal, 20000);
      const result = await catalogItem(parseJSON(text), text, installation); signal.throwIfAborted(); if (result.id !== id) invalid(); return result;
    },
    async manifest(detail: BackupDetailResource, signal: AbortSignal): Promise<PublicationManifest> {
      scope(detail.task.origin_installation_id);
      if (!backupID.test(detail.task.public_id) || detail.task.status !== 'succeeded' || detail.artifact_state !== 'committed' || !detail.artifact_registration_id || !detail.artifact_registration_hash || !detail.checksums.manifest) return invalid();
      const record = await this.record(detail.task.origin_installation_id, detail.artifact_registration_id, signal);
      if (record.backup !== detail.task.public_id || record.record_sha256 !== detail.artifact_registration_hash || record.record_sha256 !== detail.checksums.catalog || record.manifestSHA256 !== detail.checksums.manifest || record.indexSHA256 !== detail.checksums.index || record.markerSHA256 !== detail.checksums.marker || record.acceptanceSHA256 !== detail.checksums.acceptance) invalid();
      const raw = await read('/api/v1/admin/system-backups/' + detail.task.public_id + '/manifest', signal, 262144);
      const node = parseJSON(raw); if (node.start !== 0 || node.end !== raw.length || !canonical(node, raw)) invalid();
      const hash = await sha(raw); signal.throwIfAborted(); if (hash !== detail.checksums.manifest) invalid();
      manifestShape(node.value, detail, record); return { raw, sha256: hash };
    },
  };
}

// Each view owns a gate. Replacement/unmount cancels the old request, and even
// a transport that ignores abort cannot publish a result into the new view.
export function createPublicationRequestGate() {
  let current: AbortController | null = null;
  return {
    start() { current?.abort(); const controller = new AbortController(); current = controller; return { signal: controller.signal, active: () => current === controller && !controller.signal.aborted }; },
    cancel() { current?.abort(); current = null; },
  };
}

// Allocated by useMemo for a reader/scope pair. Activation belongs to the
// layout-effect commit, so a speculative render cannot withdraw a live view.
export function createPublicationViewContext(reader: unknown, scope: string) {
  let committed = false;
  const page = createPublicationRequestGate(), record = createPublicationRequestGate();
  return {
    reader, scope, page, record,
    active: () => committed,
    commit() {
      committed = true;
      return () => { committed = false; page.cancel(); record.cancel(); };
    },
  };
}
