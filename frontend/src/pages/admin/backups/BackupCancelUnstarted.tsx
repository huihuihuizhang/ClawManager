import { useEffect, useRef, useState } from 'react';
import axios from 'axios';
import type { BackupDetailSelection } from './backupLiveDetail';
import { cancelUnstartedBackup } from '../../../services/systemBackupActions';
import { useBackupText } from './useBackupText';

export default function BackupCancelUnstarted({ selection, active = false, canceled }: { selection: BackupDetailSelection; active?: boolean; canceled: () => void }) {
  const { b } = useBackupText();
  const key = useRef<string | null>(null);
  const pending = useRef<AbortController | null>(null);
  const [status, setStatus] = useState<'idle' | 'sending' | 'uncertain' | 'denied' | 'active' | 'unavailable' | 'accepted' | 'done'>('idle');
  useEffect(() => () => pending.current?.abort(), []);
  const submit = async () => {
    if (pending.current || status === 'done') return;
    const storageKey = `backup-cancel:${selection.origin_installation_id}:${selection.public_id}`;
    if (key.current === null) {
      try { key.current = sessionStorage.getItem(storageKey); } catch { /* tab storage may be disabled */ }
      if (!key.current || !/^[a-zA-Z0-9._:-]{16,128}$/.test(key.current)) key.current = crypto.randomUUID();
      try { sessionStorage.setItem(storageKey, key.current); } catch { /* the in-memory key still protects retries */ }
    }
    const controller = new AbortController();
    pending.current = controller;
    setStatus('sending');
    try {
      const operation = await cancelUnstartedBackup(selection, key.current, controller.signal);
      if (!controller.signal.aborted) {
        if (operation.status === 'succeeded') { setStatus('done'); canceled(); }
        else setStatus('accepted');
      }
    } catch (error) {
      if (controller.signal.aborted) return;
      const code = axios.isAxiosError(error) ? error.response?.data?.code : undefined;
      setStatus(code === 'permission_denied' || code === 'authentication_required' ? 'denied'
        : code === 'conflict_active_job' ? 'active' : code === 'not_ready' ? 'unavailable' : 'uncertain');
    } finally { if (pending.current === controller) pending.current = null; }
  };
  return <div className="mt-5 rounded-lg border border-slate-200 bg-slate-50 p-4">
    <p className="text-xs leading-5 text-slate-600">{b(active ? 'cancelRunningNote' : 'cancelUnstartedNote')}</p>
    <button type="button" className="mt-3 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-100 disabled:opacity-50"
      disabled={status === 'sending' || status === 'done' || status === 'denied' || status === 'active'} onClick={() => void submit()}>
      {status === 'sending' ? b('loading') : status === 'done' ? b('cancelConfirmed') : status === 'uncertain' || status === 'unavailable' || status === 'accepted' ? b('cancelRetrySameRequest') : b('cancelTask')}
    </button>
    {status !== 'idle' && status !== 'sending' && status !== 'done' && <p className="mt-2 text-sm text-amber-800" role="status">
      {b(status === 'accepted' ? 'cancelAccepted' : status === 'denied' ? 'cancelDenied' : status === 'active' ? 'cancelAlreadyStarted' : status === 'unavailable' ? 'cancelUnavailable' : 'cancelUncertain')}
    </p>}
  </div>;
}
