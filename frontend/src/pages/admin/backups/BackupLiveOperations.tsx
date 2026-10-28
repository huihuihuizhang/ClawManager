import { useEffect, useRef, useState } from 'react';
import type { SystemBackupOperation } from '../../../types/systemBackupContract';
import { systemBackupReadService } from '../../../services/systemBackupReadService';
import { backupReadNotReady } from './backupLiveRecords';
import { readBackupOperation, readBackupOperations } from './backupLiveOperations';
import type { BackupOperationPage, BackupOperationSelection } from './backupLiveOperations';
import { useBackupText } from './useBackupText';
import BackupEvidenceDownload from './BackupEvidenceDownload.tsx';

type PageState = { kind: 'loading' | 'error' | 'unavailable' } | { kind: 'ready'; page: BackupOperationPage };
type DetailState = null | { kind: 'loading' | 'error' | 'unavailable' } | { kind: 'ready'; value: SystemBackupOperation };

export default function BackupLiveOperations({ installation }: { installation: string | null }) {
  const { b, label, date, number } = useBackupText();
  const [open, setOpen] = useState(false);
  const [state, setState] = useState<PageState>({ kind: 'loading' });
  const [detail, setDetail] = useState<DetailState>(null);
  const [revision, setRevision] = useState(0);
  const [busy, setBusy] = useState(false);
  const pageRequest = useRef<AbortController | null>(null);
  const detailRequest = useRef<AbortController | null>(null);
  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    pageRequest.current = controller;
    readBackupOperations(systemBackupReadService, installation, controller.signal)
      .then((page) => { if (!controller.signal.aborted) setState({ kind: 'ready', page }); })
      .catch((error: unknown) => { if (!controller.signal.aborted) setState({ kind: backupReadNotReady(error) ? 'unavailable' : 'error' }); });
    return () => { pageRequest.current?.abort(); detailRequest.current?.abort(); };
  }, [installation, open, revision]);
  const reset = () => {
    pageRequest.current?.abort(); detailRequest.current?.abort();
    setState({ kind: 'loading' }); setDetail(null); setBusy(false);
  };
  const loadMore = () => {
    if (state.kind !== 'ready' || busy || state.page.next_cursor === null) return;
    const controller = new AbortController();
    pageRequest.current?.abort(); pageRequest.current = controller;
    setBusy(true);
    readBackupOperations(systemBackupReadService, installation, controller.signal, state.page)
      .then((page) => { if (!controller.signal.aborted) setState({ kind: 'ready', page }); })
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          detailRequest.current?.abort(); setDetail(null);
          setState({ kind: backupReadNotReady(error) ? 'unavailable' : 'error' });
        }
      }).finally(() => { if (!controller.signal.aborted) setBusy(false); });
  };
  const select = (selection: BackupOperationSelection) => {
    const controller = new AbortController();
    detailRequest.current?.abort(); detailRequest.current = controller;
    setDetail({ kind: 'loading' });
    readBackupOperation(systemBackupReadService, selection, controller.signal)
      .then((value) => { if (!controller.signal.aborted) setDetail({ kind: 'ready', value }); })
      .catch((error: unknown) => { if (!controller.signal.aborted) setDetail({ kind: backupReadNotReady(error) ? 'unavailable' : 'error' }); });
  };
  const button = 'rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 disabled:opacity-50';
  return <section className="rounded-xl border border-slate-200 bg-white p-5">
    <div className="flex flex-wrap items-center justify-between gap-3"><h2 className="font-semibold text-slate-900">{b('operationRecords')}</h2>
      <button type="button" className={button} aria-expanded={open} aria-controls="system-backup-live-operations"
        onClick={() => { reset(); setOpen((value) => !value); }}>{open ? b('detailClose') : b('operationRecordsOpen')}</button></div>
    {open && <div id="system-backup-live-operations" className="mt-4 space-y-4">
      <p className="text-sm text-slate-500">{b('operationRecordsNote')}</p>
      <button type="button" className={button} disabled={state.kind === 'loading'} onClick={() => { reset(); setRevision((value) => value + 1); }}>{b('refresh')}</button>
      {state.kind === 'loading' && <p role="status" aria-busy="true">{b('loading')}</p>}
      {state.kind === 'error' && <p role="alert" className="text-sm text-red-700">{b('readError')}</p>}
      {state.kind === 'unavailable' && <p role="status" className="text-sm text-slate-500">{b('readResourceUnavailable')}</p>}
      {state.kind === 'ready' && <>
        {state.page.items.length === 0 ? <p className="text-sm text-slate-500">{b('noRecords')}</p> : <div className="overflow-x-auto">
          <table className="w-full text-left text-sm"><thead><tr className="border-b border-slate-200 text-slate-500">
            {['ID', b('operationType'), b('executionStatus'), b('operationUpdatedAt')].map((name) => <th key={name} scope="col" className="py-2 pr-4 font-medium">{name}</th>)}
          </tr></thead><tbody>{state.page.items.map((item) => <tr key={item.public_id} className="border-b border-slate-100">
            <td className="py-2 pr-4"><button type="button" className="break-all text-left font-mono text-xs text-rose-700 underline underline-offset-4"
              aria-label={`${b('detailOpen')} ${item.public_id}`} onClick={() => select(item)}>{item.public_id}</button></td>
            <td className="py-2 pr-4">{label(item.operation_type)}</td><td className="py-2 pr-4">{label(item.status)}</td><td className="py-2 pr-4">{date(item.updated_at)}</td>
          </tr>)}</tbody></table></div>}
        {state.page.next_cursor !== null && <button type="button" className={button} disabled={busy} onClick={loadMore}>{busy ? b('loadingMore') : b('loadMore')}</button>}
      </>}
      {detail?.kind === 'loading' && <p role="status" aria-busy="true">{b('loading')}</p>}
      {detail?.kind === 'error' && <p role="alert" className="text-sm text-red-700">{b('readError')}</p>}
      {detail?.kind === 'unavailable' && <p role="status" className="text-sm text-slate-500">{b('readResourceUnavailable')}</p>}
      {detail?.kind === 'ready' && <article className="rounded-lg border border-slate-200 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3"><h3 className="break-all font-mono text-xs">{detail.value.public_id}</h3>
          <button type="button" className={button} onClick={() => { detailRequest.current?.abort(); setDetail(null); }}>{b('detailClose')}</button></div>
        <dl className="mt-4 grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-3">{[
          [b('operationType'), label(detail.value.operation_type)], [b('executionStatus'), label(detail.value.status)],
          [b('target'), detail.value.target_public_id], [b('operationInstallation'), detail.value.origin_installation_id],
          [b('operationUpdatedAt'), date(detail.value.updated_at)], [b('operationFailure'), label(detail.value.failure_category)],
          [b('configVersion'), detail.value.result_config_version === null ? '—' : `v${number(detail.value.result_config_version)}`],
        ].map(([name, value]) => <div key={name}><dt className="text-slate-500">{name}</dt><dd className="mt-1 break-words text-slate-900">{value}</dd></div>)}</dl>
        {detail.value.target_type === 'evidence' && <div className="mt-4"><BackupEvidenceDownload
          installation={detail.value.origin_installation_id} evidenceId={detail.value.target_public_id} /></div>}
      </article>}
    </div>}
  </section>;
}
