import { useEffect, useRef, useState } from 'react';
import { backupActivityExpired, readBackupLiveActivity } from './backupLiveActivity';
import { readBackupLiveEvents } from './backupLiveEvents';
import type { BackupActivityChannel, BackupActivityPage } from './backupLiveActivity';
import type { BackupDetailSelection } from './backupLiveDetail';
import { systemBackupReadService } from '../../../services/systemBackupReadService';
import { useBackupText } from './useBackupText';
import BackupEvidenceDownload from './BackupEvidenceDownload.tsx';
import { evidenceDownloadEnabled } from './backupEvidenceDownload.ts';

type ActivityPage = BackupActivityPage<'events'> | BackupActivityPage<'logs'>;

type ActivityState = { kind: 'loading' } | { kind: 'error' } | { kind: 'expired' }
  | { kind: 'ready'; page: ActivityPage };

export default function BackupLiveActivity({ selection, channel, viewEvents }: {
  selection: BackupDetailSelection; channel: BackupActivityChannel; viewEvents: () => void;
}) {
  const { b, label, date, number } = useBackupText();
  const [state, setState] = useState<ActivityState>({ kind: 'loading' });
  const [revision, setRevision] = useState(0);
  const [busy, setBusy] = useState(false);
  const [downloadEvidence, setDownloadEvidence] = useState<string | null>(null);
  const request = useRef<AbortController | null>(null);
  const { kind, public_id, origin_installation_id, row_version } = selection;
  const readPage = (selected: BackupDetailSelection, signal: AbortSignal, current?: ActivityPage): Promise<ActivityPage> => {
    if (channel === 'events') return readBackupLiveEvents(systemBackupReadService, selected, signal, current?.channel === 'events' ? current : undefined);
    return readBackupLiveActivity(systemBackupReadService, selected, 'logs', signal, current?.channel === 'logs' ? current : undefined);
  };
  const failed = (error: unknown) => setState({ kind: backupActivityExpired(channel, error) ? 'expired' : 'error' });
  useEffect(() => {
    const controller = new AbortController();
    request.current = controller;
    readPage({ kind, public_id, origin_installation_id, row_version }, controller.signal)
      .then((page) => { if (!controller.signal.aborted) setState({ kind: 'ready', page }); })
      .catch((error: unknown) => {
        if (!controller.signal.aborted) setState({ kind: backupActivityExpired(channel, error) ? 'expired' : 'error' });
      });
    return () => request.current?.abort();
  }, [kind, public_id, origin_installation_id, row_version, channel, revision]);

  const refresh = () => {
    request.current?.abort();
    setDownloadEvidence(null);
    setState({ kind: 'loading' });
    setBusy(false);
    setRevision((value) => value + 1);
  };
  const loadMore = () => {
    if (state.kind !== 'ready' || busy || state.page.next_cursor === null) return;
    const controller = new AbortController();
    request.current?.abort();
    request.current = controller;
    setBusy(true);
    readPage(selection, controller.signal, state.page)
      .then((page) => { if (!controller.signal.aborted) setState({ kind: 'ready', page }); })
      .catch((error: unknown) => { if (!controller.signal.aborted) failed(error); })
      .finally(() => { if (!controller.signal.aborted) setBusy(false); });
  };
  const buttonClass = 'rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 disabled:opacity-50';
  return <div className="mt-5 space-y-4">
    {state.kind !== 'expired' && <button type="button" className={buttonClass} onClick={refresh} disabled={state.kind === 'loading'}>{b('refresh')}</button>}
    {state.kind === 'loading' && <p role="status" aria-busy="true" className="text-sm text-slate-500">{b('loading')}</p>}
    {state.kind === 'error' && <p role="alert" className="text-sm text-red-700">{b('readError')}</p>}
    {state.kind === 'expired' && <div role="status" className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
      <p>{b('scenario_logs_expired')} · {b('logsStopped')}</p>
      <button type="button" className={`${buttonClass} mt-3`} onClick={viewEvents}>{b('viewEvents')}</button>
    </div>}
    {state.kind === 'ready' && <>
      {downloadEvidence !== null && <div className="space-y-2"><button type="button" className={buttonClass} onClick={() => setDownloadEvidence(null)}>{b('detailClose')}</button>
        <BackupEvidenceDownload installation={origin_installation_id} evidenceId={downloadEvidence} /></div>}
      {state.page.items.length === 0 && state.page.next_cursor === null && <p className="text-sm text-slate-500">{channel === 'events' ? b('noEvents') : b('noLogs')}</p>}
      <ol className={channel === 'logs' ? 'overflow-auto rounded-lg bg-slate-950 p-4 font-mono text-xs leading-7 text-slate-200' : 'space-y-4'}
        aria-label={channel === 'logs' ? b('redactedLogs') : b('events')}>
        {state.page.items.map((item, index) => item.schema_version === 'system-backup-event.v1'
          ? <li key={index} className="border-l-2 border-slate-200 pl-4"><div className="text-xs text-slate-500">{date(item.created_at)} · {label(item.level)}</div>
            <p className="mt-1 whitespace-pre-wrap break-words text-sm text-slate-800">{item.message}</p>
            {item.details?.evidence_public_id && evidenceDownloadEnabled(import.meta.env.VITE_SYSTEM_BACKUP_EVIDENCE_DOWNLOAD) && <button type="button" className={`${buttonClass} mt-2`}
              onClick={() => setDownloadEvidence(item.details?.evidence_public_id ?? null)}>{b('evidenceDownloadTitle')}</button>}
            {item.details?.truncated && <p className="mt-1 text-xs text-slate-500">{b('activityTruncated')}</p>}</li>
          : <li key={index} className="whitespace-pre-wrap break-all">{date(item.timestamp)} [{b('detailAttempt')} {number(item.attempt_number)} · {label(item.phase)} · {item.stream}] {item.message}</li>)}
      </ol>
      {state.page.next_cursor !== null && <button type="button" className={buttonClass} onClick={loadMore} disabled={busy}>{busy ? b('loadingMore') : b('loadMore')}</button>}
    </>}
  </div>;
}
