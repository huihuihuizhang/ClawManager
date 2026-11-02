import { useLayoutEffect, useMemo, useState } from 'react';
import type { BackupDetailResource } from '../../../types/systemBackupContract';
import { systemBackupPublicationReadService } from '../../../services/systemBackupReadService';
import { createPublicationViewContext } from './backupPublicationRead';
import type { PublicationManifest } from './backupPublicationRead';
import { publicationMessages } from './messages';
import { useBackupText } from './useBackupText';

type Reader = Pick<typeof systemBackupPublicationReadService, 'manifest'>;
type Context = ReturnType<typeof createPublicationViewContext>;
type State = { context: Context; kind: 'idle' | 'loading' | 'error' } | { context: Context; kind: 'ready'; value: PublicationManifest };

export default function BackupLiveManifest({ detail, reader = systemBackupPublicationReadService }: { detail: BackupDetailResource; reader?: Reader }) {
  const { locale } = useBackupText();
  const text = publicationMessages(locale);
  const baseScope = [detail.task.origin_installation_id, detail.task.public_id, detail.task.row_version, detail.artifact_registration_hash, detail.checksums.manifest].join(':');
  const context = useMemo(() => createPublicationViewContext(reader, baseScope), [reader, baseScope]);
  const [state, setState] = useState<State>({ context, kind: 'idle' });
  useLayoutEffect(() => context.commit(), [context]);
  const current = state.context === context ? state : { context, kind: 'idle' as const };
  const available = detail.task.status === 'succeeded' && detail.artifact_state === 'committed'
    && detail.artifact_registration_id !== null && detail.artifact_registration_hash !== null && detail.checksums.manifest !== null;
  const read = () => {
    if (!context.active()) return;
    const ticket = context.page.start(); setState({ context, kind: 'loading' });
    const active = () => ticket.active() && context.active();
    reader.manifest(detail, ticket.signal).then(value => {
      if (active()) setState({ context, kind: 'ready', value });
    }).catch(() => { if (active()) setState({ context, kind: 'error' }); });
  };
  return <section className="mt-5 rounded-lg border border-slate-200 p-4" aria-label={text.manifest}>
    <h3 className="font-semibold text-slate-900">{text.manifest}</h3>
    <p className="mt-2 text-sm text-slate-600">{text.trust}</p>
    {!available ? <p role="status" className="mt-3 text-sm text-slate-600">{text.unavailable}</p> : <button type="button"
      className="mt-3 rounded-lg border border-slate-200 px-3 py-2 text-sm disabled:opacity-50" disabled={current.kind === 'loading'} onClick={read}>
      {current.kind === 'loading' ? text.loading : text.readManifest}</button>}
    {current.kind === 'error' && <p role="alert" className="mt-3 text-sm text-red-700">{text.failed}</p>}
    {current.kind === 'ready' && <div className="mt-3 space-y-2">
      <p role="status" className="text-sm text-slate-700">{text.checked}</p>
      <p className="break-all font-mono text-xs">{text.hash}: {current.value.sha256}</p>
      <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-3 text-xs">{current.value.raw}</pre>
      <button type="button" className="text-sm underline" onClick={() => { context.page.cancel(); setState({ context, kind: 'idle' }); }}>{text.close}</button>
    </div>}
  </section>;
}


