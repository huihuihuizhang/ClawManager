import { downloadBackupEvidence, createEvidenceDownloadTransport } from '../pages/admin/backups/backupEvidenceDownload.ts';
import type { EvidenceDownloadRequest } from '../pages/admin/backups/backupEvidenceDownload.ts';

// Separate from the global Axios refresh interceptor: an MFA/nonce/download
// request must never be silently replayed with another login session.
export function systemBackupDownload(request: EvidenceDownloadRequest, signal: AbortSignal) {
  return downloadBackupEvidence(createEvidenceDownloadTransport({
    origin: window.location.origin,
    baseURL: import.meta.env.VITE_API_URL || '/api/v1',
    session: () => localStorage.getItem('access_token'),
    fetch: (url, init) => fetch(url, init),
  }), request, signal);
}
