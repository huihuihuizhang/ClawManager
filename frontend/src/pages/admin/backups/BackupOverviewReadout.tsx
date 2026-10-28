import type { OverviewResource } from '../../../types/systemBackupContract';
import { useBackupText } from './useBackupText';

export default function BackupOverviewReadout({ overview: o, navigate }: {
  overview: OverviewResource; navigate?: (tab: 'backups' | 'drills') => void;
}) {
  const { b, label, date, number } = useBackupText();
  const counts: [string, number][] = [
    [b('activeTasks'), o.active_task_count], [b('activeOperations'), o.active_operation_count],
    [b('unresolved'), o.finalization_unknown_count], [b('cleanupBacklog'), o.cleanup_backlog_count],
    [b('ownershipBacklog'), o.ownership_resolution_backlog_count],
  ];
  const dependencies: [string, string][] = [
    [b('controller'), o.controller_health], [b('database'), o.database_health],
    [b('artifactStore'), o.artifact_target_health], [b('evidenceStore'), o.evidence_store_health],
    [b('catalog'), o.catalog_health], [b('sourceWriters'), o.source_writer_state],
  ];
  const status: [string, string][] = [
    [b('matrix'), o.matrix], [b('featureStatus'), o.effective_enabled ? b('enabled') : b('disabled')],
    [b('recoveryReady'), o.backup_recovery_readiness ? b('ready') : b('notReady')],
    [b('baselineRecord'), o.baseline_present ? b('baselinePresent') : b('baselineAbsent')],
    [b('monitoring'), o.monitoring_armed ? b('enabled') : b('disabled')],
    [b('monitoringReason'), label(o.monitoring_armed_reason)], [b('liveObservedAt'), date(o.observed_at)],
  ];
  return <div className="space-y-5">
    <dl aria-label={b('overviewCounts')} className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">{counts.map(([name, value]) =>
      <div key={name} className="rounded-xl border border-slate-200 bg-white p-5"><dt className="text-xs text-slate-500">{name}</dt>
        <dd className="mt-3 text-3xl font-semibold tabular-nums text-slate-900">{number(value)}</dd></div>)}</dl>
    <section className="rounded-xl border border-slate-200 bg-white p-5">
      <h2 className="font-semibold text-slate-900">{b('overview')}</h2>
      <dl className="mt-4 grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-4">{status.map(([name, value]) =>
        <div key={name}><dt className="text-slate-500">{name}</dt><dd className="mt-1 break-words text-slate-900">{value}</dd></div>)}</dl>
    </section>
    <div className="grid gap-5 xl:grid-cols-2">
      <section className="rounded-xl border border-slate-200 bg-white p-5">
        <h2 className="font-semibold text-slate-900">{b('dependencies')}</h2><p className="mt-1 text-xs leading-5 text-slate-500">{b('dependenciesNote')}</p>
        <dl className="mt-4 space-y-4">{dependencies.map(([name, value]) => {
          const tone = value === 'healthy' || value === 'clean' ? 'bg-emerald-50 text-emerald-700'
            : value === 'degraded' || value === 'drift' || value === 'stale' ? 'bg-amber-50 text-amber-800' : 'bg-slate-100 text-slate-600';
          return <div key={name} className="flex items-center justify-between gap-3 text-sm"><dt className="text-slate-700">{name}</dt>
            <dd className={`rounded-md px-2 py-1 text-xs font-medium ${tone}`}>{label(value)}</dd></div>;
        })}</dl>
      </section>
      <section className="rounded-xl border border-slate-200 bg-white p-5">
        <h2 className="font-semibold text-slate-900">{b('attention')}</h2><p className="mt-1 text-xs leading-5 text-slate-500">{b('attentionNote')}</p>
        <div className="mt-4 space-y-4">{o.shortage_failure_domains.length === 0
          ? <p className="text-sm text-slate-500">{b('noShortageReported')}</p>
          : o.shortage_failure_domains.map((domain) => <div key={domain.target_failure_domain_id} className="rounded-lg border border-amber-200 bg-amber-50 p-4">
            <h3 className="text-sm font-medium text-amber-900">{b('shortage')}</h3><p className="mt-2 break-all text-xs text-amber-800">{domain.target_failure_domain_id}</p>
            <p className="mt-1 text-sm text-amber-800">{b('shortageCount', { available: number(domain.eligible_usable_recovery_points), minimum: number(domain.minimum_recovery_points) })}</p></div>)}
          {navigate && (o.finalization_unknown_count > 0 || o.cleanup_backlog_count > 0) && <div className="flex flex-wrap gap-2">
            {o.finalization_unknown_count > 0 && <button type="button" className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700" onClick={() => navigate('backups')}>{b('inspectUnresolved')}</button>}
            {o.cleanup_backlog_count > 0 && <button type="button" className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700" onClick={() => navigate('drills')}>{b('inspectCleanup')}</button>}
          </div>}
          <p className="text-xs leading-5 text-slate-500">{b('monitoringNote', { status: o.monitoring_armed ? b('enabled') : b('disabled') })}</p>
        </div>
      </section>
    </div>
  </div>;
}
