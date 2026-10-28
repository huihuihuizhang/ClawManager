import { useEffect, useState } from 'react';
import { systemBackupReadService } from '../../../services/systemBackupReadService';
import { readBackupLiveEvents } from './backupLiveEvents';
import type { BackupDetailSelection } from './backupLiveDetail';
import { activeBackupRecoveryStates, hasProtectedRecovery } from './backupRecoveryState';
import { useBackupText } from './useBackupText';

export default function BackupRecoveryNotice({ selection, status, viewEvents }: {
  selection: BackupDetailSelection; status: string; viewEvents: () => void;
}) {
  const { b } = useBackupText();
  const [notice, setNotice] = useState<'none' | 'protected' | 'unavailable'>('none');
  const { kind, public_id, origin_installation_id, row_version } = selection;
  const active = kind === 'backups' && activeBackupRecoveryStates.has(status);
  useEffect(() => {
    if (!active) return;
    const controller = new AbortController();
    setNotice('none');
    readBackupLiveEvents(systemBackupReadService, { kind, public_id, origin_installation_id, row_version }, controller.signal)
      .then(page => { if (!controller.signal.aborted) setNotice(hasProtectedRecovery(status, public_id, page.items) ? 'protected' : 'none'); })
      .catch(() => { if (!controller.signal.aborted) setNotice('unavailable'); });
    return () => controller.abort();
  }, [active, kind, public_id, origin_installation_id, row_version, status]);
  if (!active || notice === 'none') return null;
  return <div role="status" className="mt-4 rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-950">
    <p className="font-medium">{b(notice === 'protected' ? 'recoveryProtectedTitle' : 'recoveryDiagnosticUnavailable')}</p>
    {notice === 'protected' && <p className="mt-1 leading-6">{b('recoveryProtectedNote')}</p>}
    <button type="button" className="mt-3 rounded-lg border border-amber-300 bg-white px-3 py-2 text-sm" onClick={viewEvents}>{b('viewEvents')}</button>
  </div>;
}
