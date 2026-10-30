import { useEffect, useRef, useState } from 'react';
import { readRecoveryActions, reconcileOriginalBackup } from '../../../services/systemBackupRecovery';
import type { RecoveryActions } from '../../../services/systemBackupRecovery';
import type { BackupDetailSelection } from './backupLiveDetail';
import { useBackupText } from './useBackupText';

export default function BackupReconcileOriginal({ selection }: { selection: BackupDetailSelection }) {
  const { b } = useBackupText();
  const [capability, setCapability] = useState<RecoveryActions | null>(null);
  const [state, setState] = useState<'idle' | 'sending' | 'uncertain' | 'accepted' | 'unavailable'>('idle');
  const [hasRequest, setHasRequest] = useState(false);
  const pending = useRef<AbortController | null>(null);
  const key = useRef<string | null>(null);
  useEffect(() => {
    key.current = null;
    setHasRequest(false);
    setCapability(null);
    setState('idle');
    try {
      const saved = sessionStorage.getItem(`backup-reconcile:${selection.origin_installation_id}:${selection.public_id}`);
      if (saved && /^[A-Za-z0-9._:-]{16,128}$/.test(saved)) {
        key.current = saved;
        setHasRequest(true);
      }
    } catch { /* no persisted request */ }
    const request = new AbortController();
    readRecoveryActions(selection, request.signal).then(a => { if (!request.signal.aborted) setCapability(a); })
      .catch(() => { if (!request.signal.aborted) setState('unavailable'); });
    return () => { request.abort(); pending.current?.abort(); };
  }, [selection.public_id, selection.origin_installation_id, selection.row_version, selection.kind]);
  const send = async (lookupOnly = false) => {
    if (pending.current) return;
    if (key.current === null) {
      const storage = `backup-reconcile:${selection.origin_installation_id}:${selection.public_id}`;
      try { key.current = sessionStorage.getItem(storage); } catch { /* tab storage unavailable */ }
      if (!key.current || !/^[A-Za-z0-9._:-]{16,128}$/.test(key.current)) key.current = crypto.randomUUID();
      try { sessionStorage.setItem(storage, key.current); } catch { /* retain exact in-memory identity */ }
    }
    setHasRequest(true);
    const request = new AbortController(); pending.current = request; setState('sending');
    try { await reconcileOriginalBackup(selection, key.current, request.signal, lookupOnly); if (!request.signal.aborted) setState('accepted'); }
    catch { if (!request.signal.aborted) setState('uncertain'); }
    finally { if (pending.current === request) pending.current = null; }
  };
  if (!capability && !hasRequest) return state === 'unavailable' ? <p role="status" className="mt-4 text-sm text-slate-500">{b('reconcileCapabilityUnavailable')}</p> : null;
  return <div className="mt-4 rounded border border-slate-200 p-4 text-sm">
    <p>{capability ? b(capability.can_reconcile ? 'reconcileOriginalNote' : 'reconcileUnsupported') : b('reconcileCapabilityUnavailable')}{capability && !capability.can_reconcile && <span className="ml-2 font-mono">{capability.reason}</span>}</p>
    {capability?.can_reconcile && <button type="button" disabled={state === 'sending' || state === 'accepted'} onClick={() => void send()} className="mt-3 rounded border bg-white px-3 py-2 disabled:opacity-50">{b(state === 'uncertain' ? 'reconcileSameRequest' : 'reconcileOriginal')}</button>}
    {hasRequest && <button type="button" disabled={state === 'sending'} onClick={() => void send(true)} className="ml-2 mt-3 rounded border bg-white px-3 py-2 disabled:opacity-50">{b('reconcileLookupOnly')}</button>}
    {(state === 'accepted' || state === 'uncertain') && <p role="status" className="mt-2 text-amber-800">{b(state === 'accepted' ? 'reconcileAccepted' : 'reconcileUncertain')}</p>}
  </div>;
}
