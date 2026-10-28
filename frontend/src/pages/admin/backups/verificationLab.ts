import { createBackupApiReadClient } from './backupApiRead.ts';
import { downloadBackupEvidence, EvidenceDownloadError } from './backupEvidenceDownload.ts';
import type { EvidenceDownloadRequest } from './backupEvidenceDownload.ts';

export const labInstallation = 'installation_local_verification_lab';
export type LabScenario = 'match' | 'mismatch' | 'missing-proof';
export type LabState = { prepared: { id: string; scenario: LabScenario } | null; running: boolean; run_count: number };
export type LabCheck = { id: string; status: string; expected: Record<string, unknown>; actual: Record<string, unknown>; failure_category: string };

export function labPath(path: string): string {
  const root = '/api/v1/admin/system-backup-artifact-verifications';
  if (path === root) return '/verification-lab/tasks';
  if (new RegExp(`^${root}/sav_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$`).test(path)) {
    return '/verification-lab/tasks/' + path.slice(root.length + 1);
  }
  throw new Error('Unsupported lab resource');
}

export const labReader = createBackupApiReadClient((path, signal) => fetch(labPath(path), { signal, cache: 'no-store', credentials: 'omit', redirect: 'error' }));

export async function labRequest<T>(path: '/state' | '/prepare' | '/execute' | '/reset' | `/tasks/${string}/checks`, signal: AbortSignal, body?: unknown): Promise<T> {
  const response = await fetch('/verification-lab' + path, {
    method: body === undefined ? 'GET' : 'POST', headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-Verification-Lab': '1' },
    body: body === undefined ? undefined : JSON.stringify(body), signal, cache: 'no-store', credentials: 'omit', redirect: 'error',
  });
  if (!response.ok) throw new Error(`测试服务请求失败（${response.status}），请刷新状态后重试。`);
  return response.json() as Promise<T>;
}

// Reuse the normal bounded receive, SHA-256 and attachment checks. The local
// transport is restricted to lab reports and never sends a business session.
export function labDownload(expectedSHA256: string) {
  return async (input: EvidenceDownloadRequest, signal: AbortSignal) => {
    if (input.installation !== labInstallation || input.credentials) throw new EvidenceDownloadError('validation');
    const file = await downloadBackupEvidence({
      session: () => 'isolated-local-lab',
      request: async (path, init) => {
        const prefix = '/api/v1/admin/system-backup-evidence/';
        if (!path.startsWith(prefix)) throw new EvidenceDownloadError('validation');
        return fetch('/verification-lab/reports/' + path.slice(prefix.length), { ...init, headers: {}, credentials: 'omit' });
      },
    }, input, signal);
    if (file.sha256 !== expectedSHA256) throw new EvidenceDownloadError('integrity');
    return file;
  };
}
