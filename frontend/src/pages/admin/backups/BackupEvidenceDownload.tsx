import { useEffect, useId, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { systemBackupDownload } from '../../../services/systemBackupDownloadService';
import { evidenceDownloadEnabled, evidenceIdPattern, EvidenceDownloadError } from './backupEvidenceDownload.ts';
import type { EvidenceDownloadFile } from './backupEvidenceDownload.ts';
import { useBackupText } from './useBackupText';

type Props = { installation: string | null; evidenceId?: string };
type State = { kind: 'idle' | 'busy' } | { kind: 'error'; error: EvidenceDownloadError }
  | { kind: 'ready'; file: EvidenceDownloadFile; url: string };

export default function BackupEvidenceDownload(props: Props) {
  if (!evidenceDownloadEnabled(import.meta.env.VITE_SYSTEM_BACKUP_EVIDENCE_DOWNLOAD)) return null;
  return <EvidenceDownloadForm key={`${props.installation ?? ''}:${props.evidenceId ?? ''}`} {...props} />;
}

export function EvidenceDownloadForm({ installation, evidenceId, download = systemBackupDownload, localTest = false }: Props & { download?: typeof systemBackupDownload; localTest?: boolean }) {
  const { b, number } = useBackupText();
  const id = useId();
  const [target, setTarget] = useState(evidenceId ?? '');
  const [mfa, setMfa] = useState(!localTest);
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [state, setState] = useState<State>({ kind: 'idle' });
  const active = useRef<AbortController | null>(null);
  const objectURL = useRef<string | null>(null);
  const login = useRef<string | null>(null);
  const release = () => {
    if (objectURL.current !== null) URL.revokeObjectURL(objectURL.current);
    objectURL.current = null;
  };
  useEffect(() => () => { active.current?.abort(); release(); }, []);
  const reset = () => { active.current?.abort(); active.current = null; release(); setState({ kind: 'idle' }); };
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    // Ref closes the same-tick double-click window before React rerenders.
    if (active.current !== null) return;
    release();
    const controller = new AbortController();
    active.current = controller;
    login.current = localStorage.getItem('access_token');
    setState({ kind: 'busy' });
    const request = { evidenceId: target.trim(), installation, credentials: mfa ? { password, code } : undefined };
    setPassword(''); setCode('');
    const timer = window.setTimeout(() => {
      controller.abort();
      if (active.current === controller) { active.current = null; setState({ kind: 'error', error: new EvidenceDownloadError('network') }); }
    }, 45_000);
    try {
      const file = await download(request, controller.signal);
      if (controller.signal.aborted || active.current !== controller) return;
      const url = URL.createObjectURL(file.blob);
      objectURL.current = url;
      setState({ kind: 'ready', file, url });
    } catch (error) {
      if (!controller.signal.aborted && active.current === controller) {
        setState({ kind: 'error', error: error instanceof EvidenceDownloadError ? error : new EvidenceDownloadError('network') });
      }
    } finally { window.clearTimeout(timer); if (active.current === controller) active.current = null; }
  };
  const busy = state.kind === 'busy';
  const button = 'inline-flex items-center justify-center rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 disabled:opacity-50';
  const field = 'mt-1 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 focus:border-rose-400 focus:outline-none focus:ring-1 focus:ring-rose-400 disabled:bg-slate-50';
  return <section className="rounded-xl border border-slate-200 bg-white p-5" aria-labelledby={`${id}-heading`}>
    <h3 id={`${id}-heading`} className="font-semibold text-slate-900">{b('evidenceDownloadTitle')}</h3>
    <p className="mt-2 text-sm leading-6 text-slate-500">{localTest ? '本机测试报告：仅含本轮合成测试数据，无需输入业务账户密码或验证码。' : b('evidenceDownloadNote')}</p>
    <form onSubmit={submit} className="mt-4 space-y-4" autoComplete="off">
      <div><label htmlFor={`${id}-target`} className="text-sm text-slate-700">{b('evidenceDownloadId')}</label>
        <input id={`${id}-target`} className={`${field} font-mono`} value={target} readOnly={evidenceId !== undefined} disabled={busy}
          required maxLength={40} spellCheck={false} autoCapitalize="none" onChange={event => { reset(); setTarget(event.target.value); }} /></div>
      {!localTest && <label className="flex items-center gap-2 text-sm text-slate-700"><input type="checkbox" checked={mfa} disabled={busy}
        onChange={event => { reset(); setMfa(event.target.checked); setPassword(''); setCode(''); }} />{b('evidenceDownloadMfa')}</label>}
      {mfa && <div className="grid gap-4 sm:grid-cols-2">
        <div><label htmlFor={`${id}-password`} className="text-sm text-slate-700">{b('evidenceDownloadPassword')}</label>
          <input id={`${id}-password`} className={field} type="password" value={password} required disabled={busy} autoComplete="off"
            onChange={event => setPassword(event.target.value)} /></div>
        <div><label htmlFor={`${id}-code`} className="text-sm text-slate-700">{b('evidenceDownloadCode')}</label>
          <input id={`${id}-code`} className={field} type="password" inputMode="numeric" pattern="[0-9]{6}" maxLength={6}
            value={code} required disabled={busy} autoComplete="off" onChange={event => setCode(event.target.value)} /></div>
      </div>}
      <div className="flex flex-wrap gap-2"><button className={`${button} !border-rose-600 !bg-rose-600 !text-white`} type="submit"
        disabled={busy || !evidenceIdPattern.test(target.trim()) || mfa && (!password || !/^\d{6}$/.test(code))}>{busy ? b('evidenceDownloadBusy') : b('evidenceDownloadAction')}</button>
        {busy && <button type="button" className={button} onClick={reset}>{b('evidenceDownloadCancel')}</button>}
        {state.kind === 'ready' && <button type="button" className={button} onClick={reset}>{b('evidenceDownloadClear')}</button>}</div>
    </form>
    {busy && <p role="status" aria-busy="true" className="mt-4 text-sm text-slate-500">{b('evidenceDownloadBusy')}</p>}
    {state.kind === 'error' && <p role="alert" className="mt-4 text-sm text-red-700">{b(`evidenceDownloadError_${state.error.code}`)}</p>}
    {state.kind === 'ready' && <div className="mt-4 space-y-3 rounded-lg border border-emerald-200 bg-emerald-50 p-4">
      <p role="status" className="text-sm text-emerald-900">{b('evidenceDownloadReady', { bytes: number(state.file.blob.size) })}</p>
      <a className={button} href={state.url} download={state.file.filename} onClick={event => {
        if (localStorage.getItem('access_token') !== login.current) {
          event.preventDefault(); reset(); setState({ kind: 'error', error: new EvidenceDownloadError('sessionChanged') });
        }
      }}>{b('evidenceDownloadSave')}</a>
      <dl className="space-y-2 text-xs text-slate-700"><div><dt>SHA-256</dt><dd className="break-all font-mono">{state.file.sha256}</dd></div>
        {state.file.operationId && <div><dt>{b('evidenceDownloadOperation')}</dt><dd className="break-all font-mono">{state.file.operationId}</dd></div>}</dl>
    </div>}
  </section>;
}
