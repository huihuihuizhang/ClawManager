export const evidenceDownloadLimit = 8 * 1024 * 1024;
export const evidenceIdPattern = /^sev_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const operationIdPattern = /^sop_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const proofPath = '/api/v1/admin/system-backup-strong-auth/proof';
const evidencePath = '/api/v1/admin/system-backup-evidence/';
const proofHeader = 'X-Strong-Auth-Proof';

export type EvidenceDownloadFailure = 'validation' | 'authentication' | 'permission' | 'notFound' | 'notReady'
  | 'tooLarge' | 'conflict' | 'rateLimited' | 'integrity' | 'network' | 'sessionChanged' | 'secureOrigin';
export class EvidenceDownloadError extends Error {
  readonly code: EvidenceDownloadFailure;
  constructor(code: EvidenceDownloadFailure) { super(code); this.name = 'EvidenceDownloadError'; this.code = code; }
}
export interface EvidenceDownloadRequest {
  evidenceId: string;
  installation: string | null;
  credentials?: { password: string; code: string };
}
export interface EvidenceDownloadFile {
  evidenceId: string;
  operationId: string | null;
  sha256: string;
  filename: string;
  blob: Blob;
}
export interface EvidenceDownloadTransport {
  request(path: string, init: RequestInit): Promise<Response>;
  session(): string | null;
}

export function createEvidenceDownloadTransport(options: {
  origin: string; baseURL: string; session: () => string | null;
  fetch: (url: URL, init: RequestInit) => Promise<Response>;
}): EvidenceDownloadTransport {
  return {
    session: options.session,
    request: async (path, init) => {
      const origin = new URL(options.origin);
      const base = new URL(options.baseURL, origin);
      if (origin.protocol !== 'https:' || base.origin !== origin.origin || base.search || base.hash || base.username || base.password
        || path !== proofPath && !(path.startsWith(evidencePath) && evidenceIdPattern.test(path.slice(evidencePath.length)))) {
        throw new EvidenceDownloadError('secureOrigin');
      }
      return options.fetch(new URL(base.pathname.replace(/\/$/, '') + path.slice('/api/v1'.length), base.origin), init);
    },
  };
}

export function evidenceDownloadEnabled(value: string | undefined): boolean { return value === '1'; }

async function boundedBody(response: Response, limit: number, signal: AbortSignal): Promise<Uint8Array<ArrayBuffer>> {
  const reader = response.body?.getReader();
  if (!reader) throw new EvidenceDownloadError('integrity');
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      signal.throwIfAborted();
      const { done, value } = await reader.read();
      signal.throwIfAborted();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new EvidenceDownloadError('tooLarge');
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}

function statusError(status: number): EvidenceDownloadError {
  const code: EvidenceDownloadFailure = status === 206 ? 'integrity' : status === 401 ? 'authentication' : status === 403 ? 'permission'
    : status === 404 ? 'notFound' : status === 409 || status === 410 ? 'conflict'
    : status === 413 || status === 416 ? 'tooLarge' : status === 429 ? 'rateLimited'
    : status === 400 ? 'validation' : status === 422 || status === 503 ? 'notReady' : 'network';
  return new EvidenceDownloadError(code);
}

// Selectors are frozen before any await. No retry, refresh, Range continuation,
// credentials persistence, or fallback to sample content occurs here.
export async function downloadBackupEvidence(
  transport: EvidenceDownloadTransport, input: EvidenceDownloadRequest, signal: AbortSignal,
): Promise<EvidenceDownloadFile> {
  signal.throwIfAborted();
  const { evidenceId, installation } = input;
  const credentials = input.credentials && { ...input.credentials };
  if (!evidenceIdPattern.test(evidenceId) || installation !== null && !/^installation_[A-Za-z0-9._:-]{1,115}$/.test(installation)
    || credentials && (!credentials.password || new TextEncoder().encode(credentials.password).length > 1024 || !/^\d{6}$/.test(credentials.code))) {
    throw new EvidenceDownloadError('validation');
  }
  const session = transport.session();
  if (!session) throw new EvidenceDownloadError('authentication');
  if (!globalThis.crypto?.subtle || typeof globalThis.crypto.randomUUID !== 'function') throw new EvidenceDownloadError('secureOrigin');
  const key = `evidence_${crypto.randomUUID()}`;
  const headers: Record<string, string> = { Authorization: `Bearer ${session}`, 'Idempotency-Key': key };
  const current = () => {
    signal.throwIfAborted();
    if (transport.session() !== session) throw new EvidenceDownloadError('sessionChanged');
  };
  const request = async (path: string, init: RequestInit) => {
    current();
    const response = await transport.request(path, { ...init, signal, cache: 'no-store', redirect: 'error', credentials: 'omit' });
    try { current(); } catch (error) { await response.body?.cancel().catch(() => {}); throw error; }
    if (response.status !== 200) {
      await response.body?.cancel().catch(() => {});
      throw statusError(response.status);
    }
    if (!response.headers.get('Cache-Control')?.split(',').some(value => value.trim().toLowerCase() === 'no-store')) {
      await response.body?.cancel().catch(() => {});
      throw new EvidenceDownloadError('integrity');
    }
    return response;
  };
  try {
    if (credentials) {
      let body = JSON.stringify({ password: credentials.password, code: credentials.code, endpoint: 'getSystemBackupEvidence',
        idempotency_key: key, request: { evidence_id: evidenceId } });
      credentials.password = ''; credentials.code = '';
      let response: Response;
      try { response = await request(proofPath, { method: 'POST', headers: { Authorization: headers.Authorization, 'Content-Type': 'application/json' }, body }); }
      finally { body = ''; }
      const raw = await boundedBody(response, 24 * 1024, signal);
      current();
      const proof = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)) as Record<string, unknown> | null;
      if (proof === null || typeof proof !== 'object' || Array.isArray(proof)
        || Object.keys(proof).sort().join(',') !== 'header_name,header_value' || proof.header_name !== proofHeader
        || typeof proof.header_value !== 'string' || proof.header_value.length > 16384 || proof.header_value.length % 4 !== 0
        || !/^[A-Za-z0-9+/]+={0,2}$/.test(proof.header_value)) throw new EvidenceDownloadError('integrity');
      let decoded: { payload?: Record<string, unknown> } | null;
      try { decoded = JSON.parse(atob(proof.header_value)); } catch { throw new EvidenceDownloadError('integrity'); }
      if (decoded?.payload?.endpoint !== 'getSystemBackupEvidence' || decoded.payload.idempotency_key !== key
        || typeof decoded.payload.audience !== 'string' || !/^installation_[A-Za-z0-9_-]{1,115}$/.test(decoded.payload.audience)
        || installation !== null && decoded.payload.audience !== installation) throw new EvidenceDownloadError('integrity');
      // The server verifies the signature, nonce, current subject/session and
      // exact server-derived manifest/range binding; this is only wire checking.
      headers[proofHeader] = proof.header_value;
    }
    const response = await request(evidencePath + evidenceId, { method: 'GET', headers });
    const media = response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase();
    const extension = media === 'application/json' ? 'json' : media === 'text/plain' ? 'txt'
      : media === 'application/jose' ? 'jose' : media === 'application/cbor' ? 'cbor' : null;
    const length = response.headers.get('Content-Length');
    const etag = response.headers.get('ETag');
    const operationId = response.headers.get('X-System-Backup-Operation-Id');
    if (!extension || !length || !/^[1-9]\d*$/.test(length) || !Number.isSafeInteger(Number(length))
      || Number(length) > evidenceDownloadLimit || !etag || !/^"[0-9a-f]{64}"$/.test(etag)
      || !/^attachment(?:;|$)/i.test(response.headers.get('Content-Disposition') ?? '')
      || response.headers.has('Content-Range') || operationId !== null && !operationIdPattern.test(operationId)
      || credentials && operationId === null) {
      await response.body?.cancel().catch(() => {});
      throw new EvidenceDownloadError(Number(length) > evidenceDownloadLimit ? 'tooLarge' : 'integrity');
    }
    const bytes = await boundedBody(response, evidenceDownloadLimit, signal);
    current();
    if (bytes.length !== Number(length)) throw new EvidenceDownloadError('integrity');
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    const sha256 = Array.from(digest, value => value.toString(16).padStart(2, '0')).join('');
    current();
    if (sha256 !== etag.slice(1, -1)) throw new EvidenceDownloadError('integrity');
    return { evidenceId, operationId, sha256, filename: `${evidenceId}.${extension}`, blob: new Blob([bytes], { type: 'application/octet-stream' }) };
  } catch (error) {
    signal.throwIfAborted();
    if (error instanceof EvidenceDownloadError) throw error;
    if (error instanceof SyntaxError || error instanceof TypeError && error.message.includes('encoded')) throw new EvidenceDownloadError('integrity');
    throw new EvidenceDownloadError('network');
  } finally {
    delete headers[proofHeader];
    headers.Authorization = '';
    if (credentials) { credentials.password = ''; credentials.code = ''; }
  }
}
