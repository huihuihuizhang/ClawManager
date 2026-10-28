import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Archive, ArrowRight, ClipboardCheck, Download, Flag, RotateCcw, Settings, Trash2, Database, FlaskConical, Info, Loader2, RefreshCw, Search, ShieldCheck, TriangleAlert } from 'lucide-react';
import AdminLayout from '../../../components/AdminLayout';
import type { BackupDetailResource } from '../../../types/systemBackupContract';
import { backupEntryPoints, filterBackups, formatBytes, previewScenarios, unavailableBackupSource } from './backupReadModel';
import type { BackupReadSource, BackupReadState, BackupSnapshot, PreviewScenario } from './backupReadModel';
import { previewBackupSource } from './backupPreview';
import BackupLiveWorkspace from './BackupLiveWorkspace';
import { liveBackupReadEnabled } from './backupLiveSource';
import { evidenceDownloadEnabled } from './backupEvidenceDownload.ts';
import { useBackupText } from './useBackupText';
import BackupOverviewReadout from './BackupOverviewReadout';

const tabs = [
  ['overview', 'overview'], ...backupEntryPoints.map((entry) => [entry.tab, entry.label] as const),
] as const;
type Tab = (typeof tabs)[number][0];
const good = new Set(['healthy', 'passed', 'committed', 'registered', 'clean', 'valid', 'eligible']);
const bad = new Set(['failed', 'corrupt', 'delete_failed', 'unavailable', 'unsupported']);
const warn = new Set(['degraded', 'warning', 'finalization_unknown', 'report_expired', 'partial_failed', 'drift', 'source_changed', 'dependency_unhealthy']);
const panelClass = 'rounded-xl border border-slate-200 bg-white';
const buttonClass = 'inline-flex items-center justify-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-rose-500';
const checksumLabels = { manifest: 'checksum_manifest', index: 'checksum_index', marker: 'checksum_marker', acceptance: 'checksum_acceptance', catalog: 'checksum_catalog' } as const;
const liveReadEnabled = liveBackupReadEnabled(import.meta.env.VITE_SYSTEM_BACKUP_LIVE_READ);

function Badge({ value, label }: { value: string; label?: string }) {
  const { label: statusLabel } = useBackupText();
  const color = good.has(value) ? 'bg-emerald-50 text-emerald-700 ring-emerald-200' : bad.has(value) ? 'bg-red-50 text-red-700 ring-red-200' : warn.has(value) ? 'bg-amber-50 text-amber-800 ring-amber-200' : 'bg-slate-100 text-slate-600 ring-slate-200';
  return <span className={`inline-flex max-w-full rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset ${color}`}>{label ?? statusLabel(value)}</span>;
}

function Panel({ title, note, children }: { title: string; note?: string; children: ReactNode }) {
  return <section className={panelClass}><div className="border-b border-slate-100 px-5 py-4"><h2 className="font-semibold text-slate-900">{title}</h2>{note && <p className="mt-1 text-xs leading-5 text-slate-500">{note}</p>}</div><div className="p-5">{children}</div></section>;
}

function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="flex flex-col items-center px-4 py-7 text-center"><Archive aria-hidden="true" className="mb-4 h-9 w-9 text-slate-300" /><h3 className="text-sm font-semibold text-slate-800">{title}</h3><div className="mt-2 max-w-lg text-sm leading-6 text-slate-500">{children}</div></div>;
}

function Fields({ values }: { values: [string, ReactNode][] }) {
  const { number } = useBackupText();
  return <dl className="grid gap-x-8 gap-y-4 sm:grid-cols-2 xl:grid-cols-3">{values.map(([name, value]) => <div key={name} className="min-w-0"><dt className="text-xs text-slate-500">{name}</dt><dd className="mt-1.5 break-words text-sm text-slate-800">{typeof value === 'number' ? number(value) : value}</dd></div>)}</dl>;
}

function DisabledAction({ children }: { children: ReactNode }) {
  const { b } = useBackupText();
  return <button type="button" disabled title={b('actionUnavailable')} className="inline-flex cursor-not-allowed items-center gap-2 rounded-lg border border-slate-200 bg-slate-100 px-3 py-2 text-sm text-slate-400">{children}</button>;
}


const entryIcons = { backups: Archive, drills: RotateCcw, preflight: ClipboardCheck, verification: ShieldCheck, catalog: Download, retention: Trash2, config: Settings, baseline: Flag };
function EntryGrid({ navigate }: { navigate: (tab: Tab) => void }) {
  const { b } = useBackupText();
  return <nav aria-label={b('entryNavigation')} className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{backupEntryPoints.map((entry) => {
    const Icon = entryIcons[entry.tab];
    return <button type="button" key={entry.tab} onClick={() => navigate(entry.tab)} className={`${panelClass} group flex items-start gap-3 p-4 text-left transition hover:border-rose-300 hover:shadow-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-rose-500`}>
      <span className="rounded-lg bg-slate-50 p-2 text-slate-500 group-hover:bg-rose-50 group-hover:text-rose-600"><Icon className="h-4 w-4" aria-hidden="true" /></span>
      <span className="min-w-0 flex-1"><span className="flex items-start justify-between gap-2 text-sm font-semibold text-slate-900"><span>{b(entry.label)}</span><ArrowRight className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" /></span><span className="mt-1 block text-xs leading-5 text-slate-500">{b(entry.description)}</span>{entry.tab === 'retention' && <span className="mt-1 block text-xs text-slate-400">{b('comingSoon')}</span>}</span>
    </button>;
  })}</nav>;
}

function Overview({ data, navigate }: { data: BackupSnapshot; navigate: (tab: Tab) => void }) {
  const { b, label: statusLabel, date, number } = useBackupText();
  const o = data.overview;
  return <div className="space-y-5">
    <section className="grid gap-4 rounded-xl bg-slate-900 p-5 text-white lg:grid-cols-[minmax(0,1fr)_auto]">
      <div><div className="mb-3 flex items-center gap-2 text-xs font-medium tracking-widest text-slate-300"><ShieldCheck className="h-4 w-4" aria-hidden="true" />{b('readiness')}</div><h2 className="text-xl font-semibold">{o.backup_recovery_readiness ? b('readyTitle') : b('notReadyTitle')}</h2><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">{o.backup_recovery_readiness ? b('readyNote') : b('notReadyNote')}</p><div className="mt-4 flex flex-wrap gap-2"><Badge value={o.matrix} /><Badge value={o.baseline_present ? 'passed' : 'unknown'} label={o.baseline_present ? b('baselinePresent') : b('baselineAbsent')} /><Badge value={data.promotionHealth} label={b('baselineHealthSummary', { status: statusLabel(data.promotionHealth) })} /></div></div>
      <div className="flex flex-col justify-center gap-3 border-slate-700 lg:border-l lg:pl-6"><span className="text-xs text-slate-400">{b('observedAt')}</span><span className="font-mono text-sm">{date(o.observed_at)}</span><span className="text-xs text-slate-400">{b('configSummary', { version: number(o.config_version), status: o.effective_enabled ? b('enabled') : b('disabled') })}</span></div>
    </section>
    <BackupOverviewReadout overview={o} navigate={navigate} />
    <EntryGrid navigate={navigate} />
  </div>;
}

function BackupDetail({ backup, data }: { backup: BackupDetailResource; data: BackupSnapshot }) {
  const { b, label: statusLabel, locale, list, date } = useBackupText();
  const [section, setSection] = useState<'summary' | 'events' | 'logs' | 'manifest'>('summary');
  const registration = data.catalog.find((item) => item.backupId === backup.task.public_id);
  const events = data.events.filter((event) => event.target_public_id === backup.task.public_id);
  const logs = data.logs.filter((log) => log.task_public_id === backup.task.public_id);
  return <Panel title={backup.task.public_id} note={b('detailNote')}>
    <div className="mb-5 flex flex-wrap gap-2" role="group" aria-label={b('detailNavigation')}>{([['summary', b('summary')], ['events', b('events')], ['logs', b('logs')], ['manifest', b('manifest')]] as const).map(([key, label]) => <button key={key} aria-pressed={section === key} className={`${buttonClass} ${section === key ? '!border-slate-900 !bg-slate-900 !text-white' : ''}`} onClick={() => setSection(key)}>{label}</button>)}</div>
    {section === 'summary' && <>
      <Fields values={[
        [b('executionStatus'), <Badge value={backup.task.status} />], [b('artifactState'), <Badge value={backup.artifact_state} />],
        [b('readableState'), <Badge value={backup.artifact_usable ? 'passed' : 'warning'} label={backup.artifact_usable ? b('readable') : b('unreadable')} />],
        [b('acceptanceReady'), <Badge value={backup.acceptance_ready ? 'passed' : 'unknown'} label={backup.acceptance_ready ? b('ready') : b('notReady')} />],
        [b('backupEligibility'), <Badge value={backup.acceptance_eligible ? 'eligible' : 'warning'} label={backup.acceptance_eligible ? b('status_eligible') : b('ineligible')} />],
        [b('registration'), <Badge value={registration?.registration ?? 'unknown'} />],
        [b('purpose'), <Badge value={backup.task_purpose} />], [b('consistency'), statusLabel(backup.consistency)], [b('size'), formatBytes(backup.bytes, locale)],
        [b('eligibilityReason'), list(backup.eligibility_reason_codes.map(statusLabel))],
        [b('unreadableReason'), backup.artifact_usable ? '—' : statusLabel(backup.artifact_unusable_reason)],
        [b('failureDomain'), backup.target_failure_domain_id],
      ]} />
      <div className="mt-5 flex flex-wrap gap-2 border-t border-slate-100 pt-4"><DisabledAction>{b('verifyArtifact')}</DisabledAction><DisabledAction>{b('createDrill')}</DisabledAction><DisabledAction>{b('createPreflight')}</DisabledAction><DisabledAction>{b('cancelTask')}</DisabledAction></div>
      <p className="mt-2 text-xs text-slate-500">{b('functionalNote')}</p>
    </>}
    {section === 'events' && (events.length ? <ol className="space-y-4">{events.map((event, index) => <li key={`${event.created_at}-${index}`} className="border-l-2 border-slate-200 pl-4"><div className="text-xs text-slate-500">{date(event.created_at)} · {statusLabel(event.level)}</div><p className="mt-1 text-sm text-slate-800">{event.message}</p></li>)}</ol> : <Empty title={b('noEvents')}>{b('noEventsNote')}</Empty>)}
    {section === 'logs' && (data.logsExpired ? <Empty title={b('scenario_logs_expired')}>{b('logsStopped')}<button className="ml-1 text-rose-700 underline" onClick={() => setSection('events')}>{b('viewEvents')}</button></Empty> : logs.length ? <div className="overflow-auto rounded-lg bg-slate-950 p-4 font-mono text-xs leading-7 text-slate-200" aria-label={b('redactedLogs')}>{logs.map((log) => <div key={`${log.attempt_number}-${log.phase}-${log.job_generation}-${log.chunk_sequence}-${log.line_index}`} className="whitespace-pre-wrap break-all">{date(log.timestamp)} [{log.phase}] {log.message}</div>)}</div> : <Empty title={b('noLogs')}>{b('noLogsNote')}</Empty>)}
    {section === 'manifest' && <div className="space-y-5"><p className="text-sm leading-6 text-slate-500">{b('manifestNote')}</p><Fields values={[
      [b('parts'), list(backup.requested_parts.map(statusLabel))], [b('matrix'), backup.matrix],
      [b('artifactRegistration'), backup.artifact_registration_id ?? b('unregistered')],
    ]} /><div className="space-y-3 rounded-lg bg-slate-50 p-4">{Object.entries(backup.checksums).map(([name, hash]) => <div key={name}><div className="text-xs font-medium text-slate-600">{b(checksumLabels[name as keyof typeof checksumLabels])} SHA-256</div><code className="mt-1 block break-all text-xs text-slate-500">{hash ?? b('notGenerated')}</code></div>)}</div></div>}
  </Panel>;
}

function Backups({ data }: { data: BackupSnapshot }) {
  const { b, label: statusLabel, locale } = useBackupText();
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('all');
  const [selected, setSelected] = useState<string | null>(null);
  const filtered = filterBackups(data.backups, query, status);
  const current = filtered.find((item) => item.task.public_id === selected) ?? filtered[0];
  return <div className="space-y-5"><Panel title={b('backups')} note={b('filterNote')}>
    <div className="mb-4 flex flex-wrap gap-3"><label className="flex min-w-0 flex-1 items-center gap-2 rounded-lg border border-slate-200 px-3 focus-within:border-rose-400 focus-within:ring-1 focus-within:ring-rose-400"><Search className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" /><input aria-label={b('search')} value={query} onChange={(event) => setQuery(event.target.value)} placeholder={b('search')} className="w-full min-w-0 bg-transparent py-2 text-sm outline-none" /></label><select aria-label={b('statusFilter')} value={status} onChange={(event) => setStatus(event.target.value)} className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm"><option value="all">{b('allStatuses')}</option>{Array.from(new Set(data.backups.map((item) => item.task.status))).map((value) => <option key={value} value={value}>{statusLabel(value) ?? value}</option>)}</select></div>
    {filtered.length ? <div className="overflow-x-auto"><table className="w-full whitespace-nowrap text-left text-sm"><thead className="border-b border-slate-200 text-xs text-slate-500"><tr>{[b('backupDeployment'), b('executionStatus'), b('artifact'), b('backupEligibility'), b('size'), b('details')].map((head) => <th key={head} scope="col" className="px-3 py-3 font-medium">{head}</th>)}</tr></thead><tbody className="divide-y divide-slate-100">{filtered.map((backup) => <tr key={backup.task.public_id} className={current?.task.public_id === backup.task.public_id ? 'bg-slate-50' : ''}><td className="px-3 py-4"><div className="font-mono text-xs text-slate-900">{backup.task.public_id}</div><div className="mt-1 text-xs text-slate-500">{backup.matrix} · {statusLabel(backup.task_purpose)}</div></td><td className="px-3 py-4"><Badge value={backup.task.status} /></td><td className="px-3 py-4"><Badge value={backup.artifact_state} /></td><td className="px-3 py-4"><Badge value={backup.acceptance_eligible ? 'eligible' : 'warning'} label={backup.acceptance_eligible ? b('status_eligible') : b('ineligible')} /></td><td className="px-3 py-4 text-slate-600">{formatBytes(backup.bytes, locale)}</td><td className="px-3 py-4"><button aria-label={b('viewBackup', { id: backup.task.public_id })} aria-pressed={current?.task.public_id === backup.task.public_id} className="rounded px-2 py-1 font-medium text-rose-700 hover:bg-rose-50" onClick={() => setSelected(backup.task.public_id)}>{b('view')}</button></td></tr>)}</tbody></table></div> : <Empty title={data.backups.length ? b('noMatches') : b('noBackups')}>{data.backups.length ? <button className={buttonClass} onClick={() => { setQuery(''); setStatus('all'); }}>{b('clearFilters')}</button> : b('noBackupsNote')}</Empty>}
  </Panel>{current && <BackupDetail key={current.task.public_id} backup={current} data={data} />}</div>;
}

function Catalog({ data }: { data: BackupSnapshot }) {
  const { b } = useBackupText();
  return <Panel title={b('catalog')} note={b('catalogNote')}><div className="mb-4 flex gap-2"><DisabledAction>{b('scanCatalog')}</DisabledAction><DisabledAction>{b('importRecord')}</DisabledAction></div>{data.catalog.length ? <div className="space-y-3">{data.catalog.map((entry) => <div key={entry.id} className="rounded-lg border border-slate-200 p-4"><div className="mb-4 break-all font-mono text-xs text-slate-700">{entry.id}</div><Fields values={[
    [b('sourceBackup'), entry.backupId], [b('registration'), <Badge value={entry.registration} />], [b('status_full'), <Badge value={entry.verification} />], [b('importStatus'), entry.imported ? b('imported') : b('notImported')],
  ]} /></div>)}</div> : <Empty title={b('noCatalog')}>{b('noCatalogNote')}</Empty>}</Panel>;
}

function Drills({ data }: { data: BackupSnapshot }) {
  const { b, label: statusLabel, number, list } = useBackupText();
  return <Panel title={b('drills')} note={b('drillsNote')}>{data.drills.length ? <div className="space-y-5">{data.drills.map((drill) => <article key={drill.task.public_id} className="rounded-lg border border-slate-200 p-4"><h3 className="mb-4 break-all font-mono text-sm">{drill.task.public_id}</h3><Fields values={[
    [b('sourceBackup'), drill.source.source_public_id], [b('executionStatus'), <Badge value={drill.task.status} />], [b('cleanupStatus'), <Badge value={drill.cleanup_status} />],
    [b('drillEligibility'), <Badge value={drill.acceptance_eligible ? 'eligible' : 'warning'} label={drill.acceptance_eligible ? b('status_eligible') : b('ineligible')} />],
    [b('cleanupPolicy'), statusLabel(drill.cleanup_policy)], [b('verifierChecks'), b('verifierCount', { passed: number(drill.verifier_summary.passed), failed: number(drill.verifier_summary.failed) })],
    [b('reason'), list(drill.eligibility_reason_codes.map(statusLabel))],
  ]} /><div className="mt-4"><DisabledAction>{b('cleanupDrill')}</DisabledAction></div></article>)}</div> : <Empty title={b('noDrills')}>{b('noDrillsNote')}</Empty>}</Panel>;
}

function Preflights({ data }: { data: BackupSnapshot }) {
  const { b, label: statusLabel, date } = useBackupText();
  return <Panel title={b('preflights')} note={b('preflightsNote')}>{data.preflights.length ? <div className="space-y-5">{data.preflights.map((preflight) => <article key={preflight.task.public_id} className="rounded-lg border border-slate-200 p-4"><h3 className="mb-4 break-all font-mono text-sm">{preflight.task.public_id}</h3><Fields values={[
    [b('sourceBackup'), preflight.source.source_public_id], [b('executionStatus'), <Badge value={preflight.task.status} />], [b('reportValidity'), <Badge value={preflight.report_validity_reason} />],
    [b('preflightMode'), statusLabel(preflight.preflight_mode)], [b('compatibility'), <Badge value={preflight.artifact_compatibility} />], [b('targetProfile'), statusLabel(preflight.target_profile)],
  ]} /><h4 className="mb-3 mt-6 text-sm font-medium">{b('differenceReport')}</h4><div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="bg-slate-50 text-xs text-slate-500"><tr>{[b('check'), b('source'), b('target'), b('result')].map((head) => <th key={head} scope="col" className="p-3 font-medium">{head}</th>)}</tr></thead><tbody>{(data.differences[preflight.task.public_id] ?? []).map((row) => <tr key={row.resource} className="border-t border-slate-100"><td className="p-3">{row.resource}</td><td className="p-3 text-slate-500">{/^\d{4}-\d{2}-\d{2}T/.test(row.source) ? date(row.source) : row.source}</td><td className="p-3 text-slate-500">{row.target}</td><td className="p-3"><Badge value={row.result} /></td></tr>)}</tbody></table></div><p className="mt-4 text-xs text-slate-500">{b('expiredReportNote')}</p></article>)}</div> : <Empty title={b('noPreflights')}>{b('noPreflightsNote')}</Empty>}</Panel>;
}

function Configuration({ data }: { data: BackupSnapshot }) {
  const { b, label: statusLabel, number } = useBackupText();
  return <div className="space-y-5"><Panel title={b('config')} note={b('configNote')}><Fields values={[
    [b('configVersion'), `v${data.config.version}`], [b('activation'), data.config.active ? b('activated') : b('notActivated')], [b('featureStatus'), data.config.effective_enabled ? b('enabled') : b('disabled')],
    [b('minimumPoints'), data.config.values.minimum_recovery_points], [b('alertProfile'), statusLabel(data.config.values.alert_profile)], [b('changeReason'), data.config.change_reason ?? '—'],
    [b('matrix'), data.overview.matrix], [b('monitoring'), data.overview.monitoring_armed ? b('enabled') : b('disabled')],
  ]} /><div className="mt-5"><DisabledAction>{b('editConfig')}</DisabledAction></div></Panel><Panel title={b('references')} note={b('referencesNote')}><Fields values={[
    [b('registries'), b('itemCount', { count: number(data.config.values.registries.length) })], [b('credentials'), b('itemCount', { count: number(data.config.values.references.length) })],
  ]} /><p className="mt-4 text-sm text-slate-500">{b('sampleReferencesNote')}</p></Panel></div>;
}

function Verifications({ data }: { data: BackupSnapshot }) {
  const { b, label: statusLabel, number } = useBackupText();
  return <Panel title={b('entry_verification')} note={b('verificationNote')}><div className="mb-4"><DisabledAction>{b('startVerification')}</DisabledAction></div>{data.verifications.length ? <div className="space-y-4">{data.verifications.map((verification) => <article key={verification.task.public_id} className="rounded-lg border border-slate-200 p-4"><h3 className="mb-4 break-all font-mono text-sm">{verification.task.public_id}</h3><Fields values={[
    [b('sourceBackup'), verification.source.source_public_id], [b('executionStatus'), <Badge value={verification.task.status} />],
    [b('verificationScope'), statusLabel(verification.verification_scope)], [b('verificationDecision'), statusLabel(verification.decision_reason)],
    [b('readabilityBefore'), verification.usable_before ? b('readable') : b('unreadable')], [b('readabilityAfter'), verification.usable_after ? b('readable') : b('unreadable')],
    [b('artifactState'), <Badge value={verification.artifact_state_after ?? 'unknown'} />],
    [b('verifierChecks'), b('verifierCount', { passed: number(verification.verifier_summary.passed), failed: number(verification.verifier_summary.failed) })],
  ]} /></article>)}</div> : <Empty title={b('noVerifications')}>{b('noVerificationsNote')}</Empty>}</Panel>;
}

function Baseline({ data }: { data: BackupSnapshot }) {
  const { b } = useBackupText();
  return <div className="space-y-5"><Panel title={b('entry_baseline')} note={b('baselineNote')}><Fields values={[
    [b('matrix'), data.overview.matrix], [b('baselineRecord'), data.overview.baseline_present ? b('established') : b('notEstablished')],
    [b('baselineHealth'), <Badge value={data.promotionHealth} />],
    [b('recoveryReady'), <Badge value={data.overview.backup_recovery_readiness ? 'passed' : 'warning'} label={data.overview.backup_recovery_readiness ? b('ready') : b('notReady')} />],
  ]} /><div className="mt-5"><DisabledAction>{b('createBaseline')}</DisabledAction></div></Panel><Panel title={b('candidates')} note={b('candidatesNote')}><Fields values={[
    [b('eligibleBackups'), data.backups.filter((backup) => backup.acceptance_eligible && backup.artifact_usable).length],
    [b('eligibleDrills'), data.drills.filter((drill) => drill.acceptance_eligible).length],
  ]} /><p className="mt-4 text-sm leading-6 text-slate-500">{b('baselineEligibilityNote')}</p></Panel></div>;
}

function ReadWorkspace({ source, onPreview }: { source: BackupReadSource; onPreview: () => void }) {
  const { b } = useBackupText();
  const [state, setState] = useState<BackupReadState>({ kind: 'loading' });
  const [revision, setRevision] = useState(0);
  const [params, setParams] = useSearchParams();
  const requestedTab = params.get('tab');
  const tab: Tab = tabs.find(([key]) => key === requestedTab)?.[0] ?? 'overview';
  const navigate = (next: Tab) => { const nextParams = new URLSearchParams(params); nextParams.set('tab', next); setParams(nextParams); };
  useEffect(() => {
    const controller = new AbortController();
    source.read(controller.signal).then((result) => { if (!controller.signal.aborted) setState(result); })
      .catch(() => { if (!controller.signal.aborted) setState({ kind: 'error', code: 'readError' }); });
    return () => controller.abort();
  }, [source, revision]);
  const refresh = () => { setState({ kind: 'loading' }); setRevision((value) => value + 1); };
  return <>
    <div className="mb-4 flex min-w-0 items-center justify-between gap-3 border-b border-slate-200 pb-3">
      {tab === 'overview' ? <h2 className="text-sm font-semibold text-slate-700">{b('overview')}</h2> : <>
        <select aria-label={b('navigation')} value={tab} onChange={(event) => navigate(event.target.value as Tab)} className="min-w-0 max-w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm lg:hidden">{tabs.map(([key, label]) => <option key={key} value={key}>{b(label)}</option>)}</select>
        <nav aria-label={b('navigation')} className="hidden min-w-0 flex-1 gap-1 overflow-x-auto lg:flex">{tabs.map(([key, label]) => <button key={key} aria-current={tab === key ? 'page' : undefined} onClick={() => navigate(key)} className={`shrink-0 whitespace-nowrap rounded-lg px-3 py-2 text-sm font-medium focus-visible:outline-rose-500 ${tab === key ? 'bg-rose-50 text-rose-700' : 'text-slate-500 hover:bg-slate-100 hover:text-slate-900'}`}>{b(label)}</button>)}</nav>
      </>}
      <button type="button" onClick={refresh} disabled={state.kind === 'unavailable' || state.kind === 'loading'} className={`${buttonClass} shrink-0 disabled:cursor-not-allowed disabled:opacity-40`}><RefreshCw className="h-4 w-4" aria-hidden="true" />{b('refresh')}</button>
    </div>
    {state.kind === 'unavailable' && <section className={`${panelClass} mb-4 flex flex-wrap items-center gap-4 px-5 py-4`}>
      <Database className="h-6 w-6 shrink-0 text-slate-400" aria-hidden="true" />
      <div className="min-w-0 flex-1 basis-64"><h2 className="text-sm font-semibold text-slate-900">{b('unavailableTitle')}</h2><p className="mt-1 text-sm leading-6 text-slate-500">{b('unavailableNote')}</p></div>
      <button type="button" className={buttonClass} onClick={onPreview}><FlaskConical className="h-4 w-4" aria-hidden="true" />{b('showPreview')}</button>
    </section>}
    {state.kind === 'loading' && <div className={`${panelClass} p-10`} aria-busy="true" role="status"><div className="flex items-center justify-center gap-2 text-sm text-slate-500"><Loader2 className="h-5 w-5 animate-spin" aria-hidden="true" />{b('loading')}</div><div className="mt-6 grid animate-pulse grid-cols-2 gap-4 md:grid-cols-4" aria-hidden="true">{[1, 2, 3, 4].map((key) => <div key={key} className="h-24 rounded-lg bg-slate-100" />)}</div></div>}
    {state.kind === 'error' && <div role="alert" className="rounded-xl border border-red-200 bg-red-50 p-6"><div className="flex items-center gap-2 font-medium text-red-800"><TriangleAlert className="h-5 w-5" aria-hidden="true" />{b('loadFailed')}</div><p className="my-3 text-sm text-red-700">{b(state.code)}</p><button className={buttonClass} onClick={refresh}>{b('retry')}</button></div>}
    {state.kind === 'unsupported' && <div className={panelClass}><Empty title={b('unsupportedTitle')}>{b('unsupportedNote')}</Empty></div>}
    {state.kind === 'ready' && <div className="space-y-5">
      {!state.data.overview.effective_enabled && <div role="status" className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm leading-6 text-amber-900">{b('disabledNote')}</div>}
      {tab === 'overview' && <Overview data={state.data} navigate={navigate} />}
      {tab === 'backups' && <Backups data={state.data} />}
      {tab === 'catalog' && <Catalog data={state.data} />}
      {tab === 'drills' && <Drills data={state.data} />}
      {tab === 'preflight' && <Preflights data={state.data} />}
      {tab === 'config' && <Configuration data={state.data} />}
      {tab === 'verification' && <Verifications data={state.data} />}
      {tab === 'baseline' && <Baseline data={state.data} />}
      {tab === 'retention' && <Panel title={b('retention')} note={b('retentionNote')}><Empty title={b('noCleanup')}>{b('noCleanupNote')}</Empty><div className="flex justify-center"><DisabledAction>{b('previewCleanup')}</DisabledAction></div></Panel>}
    </div>}
    {tab === 'overview' && state.kind !== 'ready' && <EntryGrid navigate={navigate} />}
  </>;
}

export default function SystemBackupsPage() {
  const { b } = useBackupText();
  const [preview, setPreview] = useState(false);
  const [scenario, setScenario] = useState<PreviewScenario>('ready');
  const source = useMemo(() => preview ? previewBackupSource(scenario, {
    changeReason: b('fixture_changeReason'), eventMessage: b('fixture_eventMessage'), logMessage: b('fixture_logMessage'),
    schema: b('fixture_schema'), schemaLabel: b('fixture_schemaLabel'), workspace: b('fixture_workspace'), capacity: b('fixture_capacity'),
    freshness: b('fixture_freshness'), expired: b('fixture_expired'),
  }) : unavailableBackupSource, [preview, scenario, b]);
  const changePreview = () => setPreview((current) => !current);
  const changeScenario = (value: PreviewScenario) => setScenario(value);
  return <AdminLayout title={b('title')}>
    <div className="mx-auto max-w-[1600px] space-y-5">
      <header className="flex flex-wrap items-start justify-between gap-4"><div><div className="mb-2 flex items-center gap-2 text-slate-900"><Database className="h-5 w-5" aria-hidden="true" /><h2 className="text-lg font-semibold">{b('heading')}</h2></div><p className="text-sm leading-6 text-slate-500">{b('intro')}</p></div><div className="flex flex-wrap gap-2"><button type="button" aria-pressed={preview} onClick={changePreview} className={buttonClass}><FlaskConical className="h-4 w-4" aria-hidden="true" />{preview ? b('exitPreview') : b('showPreview')}</button><DisabledAction><Archive className="h-4 w-4" aria-hidden="true" />{b('createBackup')}</DisabledAction></div></header>
      {preview ? <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3"><div className="flex items-start gap-2 text-sm text-amber-900"><Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" /><p><strong>{b('preview')}</strong>{' · '}{b('previewNotice')}</p></div><label className="flex items-center gap-2 text-xs text-amber-900">{b('previewState')}<select value={scenario} onChange={(event) => changeScenario(event.target.value as PreviewScenario)} className="rounded-md border border-amber-200 bg-white px-2 py-1.5 text-sm">{previewScenarios.map((value) => <option key={value} value={value}>{b(`scenario_${value}`)}</option>)}</select></label></div> : <div className="flex items-center gap-2 text-xs text-slate-500"><Info className="h-4 w-4" aria-hidden="true" />{liveReadEnabled && evidenceDownloadEnabled(import.meta.env.VITE_SYSTEM_BACKUP_EVIDENCE_DOWNLOAD) ? b('evidenceDownloadMode') : b('readOnly')}</div>}
      {preview
        ? <ReadWorkspace key={`${preview}-${scenario}`} source={source} onPreview={changePreview} />
        : liveReadEnabled
          ? <BackupLiveWorkspace fallback={<ReadWorkspace source={unavailableBackupSource} onPreview={changePreview} />} />
          : <ReadWorkspace source={unavailableBackupSource} onPreview={changePreview} />}
    </div>
  </AdminLayout>;
}
