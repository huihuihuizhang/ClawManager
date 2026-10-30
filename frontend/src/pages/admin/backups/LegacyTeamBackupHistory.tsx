import { useEffect, useRef, useState } from 'react';
import { getLegacyTeamBackupHistory, listLegacyTeamBackupHistory } from '../../../services/legacyTeamBackupHistory';
import type { LegacyTeamBackupJob, LegacyTeamBackupPage } from '../../../services/legacyTeamBackupHistory';
import { useBackupText } from './useBackupText';

export default function LegacyTeamBackupHistory() {
  const { b, date, label, number } = useBackupText();
  const [open, setOpen] = useState(false);
  const [page, setPage] = useState<LegacyTeamBackupPage | null>(null);
  const [selected, setSelected] = useState<LegacyTeamBackupJob | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const pending = useRef<AbortController | null>(null);
  useEffect(() => () => pending.current?.abort(), []);
  const read = async (before?: string, id?: string) => {
    pending.current?.abort();
    const request = new AbortController();
    pending.current = request;
    setBusy(true); setError(false);
    try {
      if (id) {
        const next = await getLegacyTeamBackupHistory(id, request.signal);
        if (!request.signal.aborted) setSelected(next);
      } else {
        const next = await listLegacyTeamBackupHistory(before, request.signal);
        if (!request.signal.aborted) {
          setPage(current => ({ ...next, items: before && current ? [...current.items, ...next.items.filter(item => !current.items.some(old => old.public_id === item.public_id))] : next.items }));
          setSelected(null);
        }
      }
    } catch { if (!request.signal.aborted) setError(true); }
    finally { if (!request.signal.aborted) setBusy(false); }
  };
  return <section className="rounded-xl border border-slate-200 bg-white p-5">
    <button type="button" aria-expanded={open} className="font-semibold text-slate-900" onClick={() => {
      setOpen(value => !value); if (!open && page === null) void read();
    }}>{b('legacyTeamHistory')}</button>
    {open && <div className="mt-4 space-y-3">
      <p className="text-sm text-slate-600">{b('legacyTeamReadOnly')}</p>
      {page !== null && page.unfinished_count > 0 && <p role="status" className="text-sm text-amber-800">{b('legacyTeamUnfinished', { count: number(page.unfinished_count) })}</p>}
      {error && <p role="alert" className="text-sm text-red-700">{b('readError')}</p>}
      <button type="button" disabled={busy} onClick={() => void read()} className="rounded border px-3 py-1 text-sm disabled:opacity-50">{b('refresh')}</button>
      {busy && <p role="status">{b('loading')}</p>}
      {page?.items.length === 0 && <p className="text-sm text-slate-500">{b('noRecords')}</p>}
      {page?.items.map(item => <div key={item.public_id} className="rounded border border-slate-100 p-3 text-sm">
        <button type="button" disabled={busy} className="break-all text-blue-700" onClick={() => void read(undefined, item.public_id)}>{item.public_id}</button>
        <p>{item.operation} · {label(item.status)} · {item.phase} · {date(item.created_at)}</p>
        {item.error_code && <p>{item.error_code}</p>}
        {item.requires_inspection && <p className="text-amber-800">{b('legacyTeamInspect')}</p>}
      </div>)}
      {page?.next_cursor && <button type="button" disabled={busy} onClick={() => void read(page.next_cursor)} className="rounded border px-3 py-1 text-sm">{b('loadMore')}</button>}
      {selected && <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-3 text-xs">{JSON.stringify(selected, null, 2)}</pre>}
    </div>}
  </section>;
}
