import { useEffect, useRef, useState } from 'react';
import type { ConfigResource } from '../../../types/systemBackupContract';
import { readBackupConfigHistory, readBackupConfigVersion } from './backupLiveConfig';
import type { BackupConfigBaseline, BackupConfigHistory } from './backupLiveConfig';
import { systemBackupReadService } from '../../../services/systemBackupReadService';
import { useBackupText } from './useBackupText';

type HistoryState = { kind: 'loading' } | { kind: 'error' } | { kind: 'ready'; page: BackupConfigHistory };
type VersionState = null | { kind: 'loading' | 'error'; version: number } | { kind: 'ready'; resource: ConfigResource };

export default function BackupLiveConfigHistory({ baseline }: { baseline: BackupConfigBaseline }) {
  const { b, label, date, number } = useBackupText();
  const [state, setState] = useState<HistoryState>({ kind: 'loading' });
  const [selected, setSelected] = useState<VersionState>(null);
  const [revision, setRevision] = useState(0);
  const [busy, setBusy] = useState(false);
  const pageRequest = useRef<AbortController | null>(null);
  const versionRequest = useRef<AbortController | null>(null);
  const { origin_installation_id, version, row_version, effective_enabled } = baseline;
  useEffect(() => {
    const controller = new AbortController();
    pageRequest.current = controller;
    readBackupConfigHistory(systemBackupReadService, { origin_installation_id, version, row_version, effective_enabled }, controller.signal)
      .then((page) => { if (!controller.signal.aborted) setState({ kind: 'ready', page }); })
      .catch(() => { if (!controller.signal.aborted) setState({ kind: 'error' }); });
    return () => { pageRequest.current?.abort(); versionRequest.current?.abort(); };
  }, [origin_installation_id, version, row_version, effective_enabled, revision]);

  const refresh = () => {
    pageRequest.current?.abort();
    versionRequest.current?.abort();
    setState({ kind: 'loading' });
    setSelected(null);
    setBusy(false);
    setRevision((value) => value + 1);
  };
  const loadMore = () => {
    if (state.kind !== 'ready' || busy || state.page.next_cursor === null) return;
    const controller = new AbortController();
    pageRequest.current?.abort();
    pageRequest.current = controller;
    setBusy(true);
    readBackupConfigHistory(systemBackupReadService, baseline, controller.signal, state.page)
      .then((page) => { if (!controller.signal.aborted) setState({ kind: 'ready', page }); })
      .catch(() => {
        if (!controller.signal.aborted) {
          versionRequest.current?.abort();
          setSelected(null);
          setState({ kind: 'error' });
        }
      }).finally(() => { if (!controller.signal.aborted) setBusy(false); });
  };
  const selectVersion = (item: ConfigResource) => {
    const controller = new AbortController();
    versionRequest.current?.abort();
    versionRequest.current = controller;
    setSelected({ kind: 'loading', version: item.version });
    readBackupConfigVersion(systemBackupReadService, baseline, item.version, item.row_version, controller.signal)
      .then((resource) => { if (!controller.signal.aborted) setSelected({ kind: 'ready', resource }); })
      .catch(() => { if (!controller.signal.aborted) setSelected({ kind: 'error', version: item.version }); });
  };
  const buttonClass = 'rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 disabled:opacity-50';
  return <div className="mt-5 space-y-4 border-t border-slate-100 pt-5">
    <div className="flex items-center justify-between gap-3"><h3 className="font-medium text-slate-900">{b('configHistory')}</h3>
      <button type="button" className={buttonClass} disabled={state.kind === 'loading'} onClick={refresh}>{b('refresh')}</button></div>
    {state.kind === 'loading' && <p role="status" aria-busy="true" className="text-sm text-slate-500">{b('loading')}</p>}
    {state.kind === 'error' && <p role="alert" className="text-sm text-red-700">{b('readError')}</p>}
    {state.kind === 'ready' && <>
      <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr className="border-b border-slate-200 text-slate-500">
        {[b('configVersion'), b('activation'), b('configCreatedAt'), b('changeReason')].map((name) => <th key={name} scope="col" className="py-2 pr-4 font-medium">{name}</th>)}</tr></thead>
        <tbody>{state.page.items.map((item) => <tr key={item.version} className="border-b border-slate-100">
          <td className="py-2 pr-4"><button type="button" className="text-rose-700 underline underline-offset-4" onClick={() => selectVersion(item)}
            aria-label={`${b('detailOpen')} v${number(item.version)}`}>v{number(item.version)}</button></td>
          <td className="py-2 pr-4">{item.active ? b('activated') : b('notActivated')}</td>
          <td className="py-2 pr-4">{date(item.created_at)}</td><td className="max-w-sm whitespace-pre-wrap break-words py-2">{item.change_reason ?? '—'}</td>
        </tr>)}</tbody></table></div>
      {state.page.next_cursor !== null && <button type="button" className={buttonClass} disabled={busy} onClick={loadMore}>{busy ? b('loadingMore') : b('loadMore')}</button>}
    </>}
    {selected?.kind === 'loading' && <p role="status" aria-busy="true" className="text-sm text-slate-500">v{number(selected.version)} · {b('loading')}</p>}
    {selected?.kind === 'error' && <p role="alert" className="text-sm text-red-700">v{number(selected.version)} · {b('readError')}</p>}
    {selected?.kind === 'ready' && <article className="rounded-lg border border-slate-200 p-4">
      <h4 className="font-medium text-slate-900">{b('configVersion')} v{number(selected.resource.version)}</h4>
      <dl className="mt-4 grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-3">{[
        [b('activation'), selected.resource.active ? b('activated') : b('notActivated')],
        [b('configConfiguredEnabled'), selected.resource.config.enabled ? b('enabled') : b('disabled')],
        [b('minimumPoints'), number(selected.resource.config.minimum_recovery_points)],
        [b('alertProfile'), label(selected.resource.config.alert_profile)],
        [b('configCreatedAt'), date(selected.resource.created_at)], [b('configCreatedBy'), selected.resource.created_by],
      ].map(([name, value]) => <div key={name}><dt className="text-slate-500">{name}</dt><dd className="mt-1 break-words text-slate-900">{value}</dd></div>)}</dl>
      <details className="mt-4"><summary className="cursor-pointer text-sm text-slate-700">{b('configParameters')}</summary>
        <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-slate-50 p-4 text-xs text-slate-700">{JSON.stringify(selected.resource.config, null, 2)}</pre></details>
    </article>}
  </div>;
}
