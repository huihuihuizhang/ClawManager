import type { SystemBackupTask } from '../../../types/systemBackupContract';
import type { BackupTaskKind } from './backupApiRead';
import type { BackupDetailSelection } from './backupLiveDetail';
import { useBackupText } from './useBackupText';

export default function BackupTaskTable({ items, kind, selected, select }: {
  items: SystemBackupTask[]; kind: BackupTaskKind; selected: BackupDetailSelection | null;
  select: (selection: BackupDetailSelection) => void;
}) {
  const { b, label, number, date } = useBackupText();
  return <div className="mt-4 overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr className="border-b border-slate-200 text-slate-500">
    <th scope="col" className="py-2 pr-4 font-medium">ID</th><th scope="col" className="py-2 pr-4 font-medium">{b('executionStatus')}</th>
    <th scope="col" className="py-2 pr-4 font-medium">{b('configVersion')}</th><th scope="col" className="py-2 font-medium">{b('detailUpdatedAt')}</th>
  </tr></thead><tbody>{items.map(item => <tr key={item.public_id} className="border-b border-slate-100">
    <td className="py-2 pr-4 font-mono text-xs"><button type="button"
      className="break-all text-left text-rose-700 underline decoration-rose-200 underline-offset-4 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-rose-500"
      aria-label={`${b('detailOpen')} ${item.public_id}`} aria-expanded={selected?.kind === kind && selected.public_id === item.public_id}
      aria-controls={selected?.kind === kind && selected.public_id === item.public_id ? 'system-backup-live-detail' : undefined}
      onClick={() => select({ kind, public_id: item.public_id, origin_installation_id: item.origin_installation_id, row_version: item.row_version })}>{item.public_id}</button></td>
    <td className="py-2 pr-4">{label(item.status)}</td><td className="py-2 pr-4">v{number(item.config_version)}</td><td className="whitespace-nowrap py-2">{date(item.updated_at)}</td>
  </tr>)}</tbody></table></div>;
}
