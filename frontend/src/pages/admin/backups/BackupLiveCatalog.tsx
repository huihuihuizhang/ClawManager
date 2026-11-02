import { useLayoutEffect, useMemo, useState } from 'react';
import { systemBackupPublicationReadService } from '../../../services/systemBackupReadService';
import { createPublicationViewContext } from './backupPublicationRead';
import type { CatalogPage, CatalogRecord } from './backupPublicationRead';
import { publicationMessages } from './messages';
import { useBackupText } from './useBackupText';

type Reader = Pick<typeof systemBackupPublicationReadService, 'catalog' | 'record'>;
type Context = ReturnType<typeof createPublicationViewContext>;
type PageState = { context: Context; kind: 'idle' | 'loading' | 'error'; page?: CatalogPage } | { context: Context; kind: 'ready'; page: CatalogPage };
type RecordState = { context: Context; kind: 'idle' | 'loading' | 'error' } | { kind: 'ready'; context: Context; value: CatalogRecord };

export default function BackupLiveCatalog({ installation, reader = systemBackupPublicationReadService }: { installation: string; reader?: Reader }) {
  const { locale } = useBackupText(), text = publicationMessages(locale);
  const context = useMemo(() => createPublicationViewContext(reader, installation), [reader, installation]);
  const [state, setState] = useState<PageState>({ context, kind: 'idle' });
  const [record, setRecord] = useState<RecordState>({ context, kind: 'idle' });
  useLayoutEffect(() => context.commit(), [context]);
  const current = state.context === context ? state : { context, kind: 'idle' as const, page: undefined };
  const currentRecord = record.context === context ? record : { context, kind: 'idle' as const };
  const read = (more = false) => {
    if (!context.active()) return;
    const previous = more ? current.page : undefined;
    if (more && !previous?.next_cursor) return;
    const ticket = context.page.start(); context.record.cancel(); setRecord({ context, kind: 'idle' });
    const active = () => ticket.active() && context.active();
    setState({ context, kind: 'loading', page: previous });
    reader.catalog(installation, ticket.signal, previous?.next_cursor ?? undefined).then(page => {
      if (!active()) return;
      const items = [...(previous?.items ?? []), ...page.items];
      if (new Set(items.map(item => item.id)).size !== items.length || items.length > 5000) throw new Error('invalid_publication_page');
      setState({ context, kind: 'ready', page: { ...page, items } });
    }).catch(() => { if (active()) setState({ context, kind: 'error', page: previous }); });
  };
  const readRecord = (item: CatalogRecord) => {
    if (!context.active()) return;
    const ticket = context.record.start(); setRecord({ context, kind: 'loading' });
    const active = () => ticket.active() && context.active();
    reader.record(installation, item.id, ticket.signal).then(value => {
      if (!active()) return;
      if (value.record_sha256 !== item.record_sha256 || value.backup !== item.backup || value.manifestSHA256 !== item.manifestSHA256) throw new Error('publication_registration_changed');
      setRecord({ kind: 'ready', context, value });
    }).catch(() => { if (active()) setRecord({ context, kind: 'error' }); });
  };
  return <section className="rounded-xl border border-slate-200 bg-white p-5" aria-label={text.catalog}>
    <h2 className="font-semibold text-slate-900">{text.catalog}</h2>
    <p className="mt-2 text-sm text-slate-600">{text.catalogNote}</p>
    <button type="button" className="mt-3 rounded-lg border border-slate-200 px-3 py-2 text-sm disabled:opacity-50"
      disabled={current.kind === 'loading'} onClick={() => read()}>{current.kind === 'loading' ? text.loading : current.kind === 'idle' ? text.readCatalog : text.refresh}</button>
    {current.kind === 'error' && <p role="alert" className="mt-3 text-sm text-red-700">{text.failed}</p>}
    {current.kind === 'ready' && current.page.items.length === 0 && <p role="status" className="mt-3 text-sm text-slate-600">{text.empty}</p>}
    {current.page && <ul className="mt-3 space-y-3">{current.page.items.map(item => <li key={item.id} className="rounded border border-slate-200 p-3">
      <p className="break-all font-mono text-xs">{item.id}</p><p className="mt-1 break-all text-sm">{text.backup}: {item.backup}</p>
      <p className="mt-1 break-all font-mono text-xs">{text.hash}: {item.record_sha256}</p>
      <button type="button" className="mt-2 text-sm underline" onClick={() => readRecord(item)}>{text.readRecord}</button>
    </li>)}</ul>}
    {current.page?.next_cursor && <button type="button" className="mt-3 text-sm underline disabled:opacity-50" disabled={current.kind === 'loading'} onClick={() => read(true)}>{text.more}</button>}
    {currentRecord.kind === 'loading' && <p role="status" className="mt-3 text-sm">{text.loading}</p>}
    {currentRecord.kind === 'error' && <p role="alert" className="mt-3 text-sm text-red-700">{text.failed}</p>}
    {currentRecord.kind === 'ready' && <div className="mt-4 space-y-2">
      <h3 className="text-sm font-semibold">{text.record}</h3><p role="status" className="text-sm">{text.checked}</p><p className="text-sm text-slate-600">{text.trust}</p>
      <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-3 text-xs">{currentRecord.value.raw}</pre>
      <button type="button" className="text-sm underline" onClick={() => { context.record.cancel(); setRecord({ context, kind: 'idle' }); }}>{text.close}</button>
    </div>}
  </section>;
}


