import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import type { BackupTaskKind, BackupTaskResource } from './backupApiRead';
import { readBackupLiveDetail } from './backupLiveDetail';
import type { BackupDetailReader, BackupDetailSelection } from './backupLiveDetail';
import { systemBackupReadService } from '../../../services/systemBackupReadService';
import { useBackupText } from './useBackupText';
import { formatBytes } from './backupReadModel';
import BackupLiveActivity from './BackupLiveActivity.tsx';
import BackupEvidenceDownload from './BackupEvidenceDownload.tsx';
import BackupCancelUnstarted from './BackupCancelUnstarted';
import BackupRecoveryNotice from './BackupRecoveryNotice';

type DetailState = { kind: 'loading' } | { kind: 'error' }
  | { kind: 'ready'; detail: BackupTaskResource[BackupTaskKind] };

export default function BackupLiveDetail({ selection, close, reader = systemBackupReadService, localReport }: {
  selection: BackupDetailSelection; close: () => void; reader?: BackupDetailReader;
  localReport?: (evidence: { public_id: string; sha256: string }) => ReactNode;
}) {
  const { b, label, date, number, list, locale } = useBackupText();
  const [state, setState] = useState<DetailState>({ kind: 'loading' });
  const [revision, setRevision] = useState(0);
  const [section, setSection] = useState<'summary' | 'events' | 'logs'>('summary');
  const { kind, public_id, origin_installation_id, row_version } = selection;
  const downloadEvidence = state.kind === 'ready'
    ? state.detail.verifier_summary.report_evidence ?? (state.detail.schema_version === 'system-backup-artifact-verification-detail.v1'
      ? state.detail.health_report_evidence : null)
    : null;
  useEffect(() => {
    const controller = new AbortController();
    readBackupLiveDetail(reader, { kind, public_id, origin_installation_id, row_version }, controller.signal)
      .then((detail) => { if (!controller.signal.aborted) setState({ kind: 'ready', detail }); })
      .catch(() => { if (!controller.signal.aborted) setState({ kind: 'error' }); });
    return () => controller.abort();
  }, [kind, public_id, origin_installation_id, row_version, revision, reader]);

  const buttonClass = 'rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700';
  const fields: [string, ReactNode][] = [];
  if (state.kind === 'ready') {
    const detail = state.detail;
    fields.push(
      [b('executionStatus'), label(detail.task.status)],
      [b('configVersion'), `v${number(detail.task.config_version)}`],
      [b('detailUpdatedAt'), date(detail.task.updated_at)],
      [b('detailAttempt'), detail.execution.current_attempt_number === null ? '—' : number(detail.execution.current_attempt_number)],
      [b('detailPhase'), detail.execution.current_phase === null ? '—' : label(detail.execution.current_phase)],
      [b('detailProgressAt'), detail.execution.last_business_progress_at === null ? '—' : date(detail.execution.last_business_progress_at)],
      [b('verifierChecks'), label(detail.verifier_summary.aggregate_status)],
      [b('detailVerifierCounts'), b('detailVerifierCount', {
        passed: number(detail.verifier_summary.passed), warning: number(detail.verifier_summary.warning),
        failed: number(detail.verifier_summary.failed), skipped: number(detail.verifier_summary.skipped),
      })],
    );
    switch (detail.schema_version) {
      case 'system-backup-backup-detail.v1':
        fields.push(
          [b('artifactState'), label(detail.artifact_state)],
          [b('readableState'), detail.artifact_usable ? b('readable') : b('unreadable')],
          [b('unreadableReason'), label(detail.artifact_unusable_reason)],
          [b('acceptanceReady'), detail.acceptance_ready ? b('ready') : b('notReady')],
          [b('backupEligibility'), detail.acceptance_eligible ? b('status_eligible') : b('ineligible')],
          [b('eligibilityReason'), list(detail.eligibility_reason_codes.map(label))],
          [b('purpose'), label(detail.task_purpose)], [b('matrix'), detail.matrix],
          [b('size'), formatBytes(detail.bytes, locale)],
        );
        break;
      case 'system-backup-drill-detail.v1':
        fields.push(
          [b('detailSourceArtifact'), detail.source.source_public_id],
          [b('purpose'), label(detail.task_purpose)],
          [b('targetProfile'), label(detail.target_profile)],
          [b('cleanupPolicy'), label(detail.cleanup_policy)],
          [b('cleanupStatus'), label(detail.cleanup_status)],
          [b('detailCleanupFailure'), label(detail.cleanup_failure_code)],
          [b('drillEligibility'), detail.acceptance_eligible ? b('status_eligible') : b('ineligible')],
          [b('eligibilityReason'), list(detail.eligibility_reason_codes.map(label))],
        );
        break;
      case 'system-backup-preflight-detail.v1':
        fields.push(
          [b('detailSourceArtifact'), detail.source.source_public_id],
          [b('preflightMode'), label(detail.preflight_mode)],
          [b('compatibility'), label(detail.artifact_compatibility)],
          [b('reportValidity'), label(detail.report_validity_reason)],
        );
        break;
      case 'system-backup-artifact-verification-detail.v1':
        fields.push(
          [b('detailSourceArtifact'), detail.source.source_public_id],
          [b('verificationScope'), label(detail.verification_scope)],
          [b('verificationDecision'), label(detail.decision_reason)],
          [b('readabilityBefore'), detail.usable_before === null ? b('status_unknown') : detail.usable_before ? b('readable') : b('unreadable')],
          [b('readabilityAfter'), detail.usable_after === null ? b('status_unknown') : detail.usable_after ? b('readable') : b('unreadable')],
          [b('artifactState'), detail.artifact_state_after === null ? '—' : label(detail.artifact_state_after)],
          [b('unreadableReason'), label(detail.unusable_reason_after)],
        );
        break;
    }
  }
  return <section id="system-backup-live-detail" className="rounded-xl border border-slate-200 bg-white p-5" aria-label={b('summary')}>
    <div className="flex flex-wrap items-center justify-between gap-3">
      <h2 className="break-all font-mono text-sm font-semibold text-slate-900">{public_id}</h2>
      <div className="flex gap-2">
        <button type="button" className={buttonClass} disabled={state.kind === 'loading'} onClick={() => { setState({ kind: 'loading' }); setRevision((value) => value + 1); }}>{b('refresh')}</button>
        <button type="button" className={buttonClass} onClick={close}>{b('detailClose')}</button>
      </div>
    </div>
    <div className="mt-4 flex flex-wrap gap-2" role="group" aria-label={b('detailViews')}>{(localReport ? ['summary'] as const : ['summary', 'events', 'logs'] as const).map((view) =>
      <button type="button" key={view} className={buttonClass} aria-pressed={section === view}
        disabled={view === 'logs' && state.kind !== 'ready'} onClick={() => setSection(view)}>{b(view)}</button>)}</div>
    {(section === 'summary' || section === 'logs' && state.kind !== 'ready') && <>
      {state.kind === 'loading' && <p className="mt-4 text-sm text-slate-500" role="status" aria-busy="true">{b('loading')}</p>}
      {state.kind === 'error' && <p className="mt-4 text-sm text-red-700" role="alert">{b('readError')}</p>}
      {state.kind === 'ready' && !localReport && reader === systemBackupReadService && <BackupRecoveryNotice
        key={`${public_id}:${revision}:${state.detail.task.row_version}`}
        selection={{ ...selection, row_version: state.detail.task.row_version }} status={state.detail.task.status} viewEvents={() => setSection('events')} />}
      {state.kind === 'ready' && <dl className="mt-5 grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-3">{fields.map(([name, value]) =>
        <div key={name} className="min-w-0"><dt className="text-slate-500">{name}</dt><dd className="mt-1 break-words text-slate-900">{value}</dd></div>)}</dl>}
      {state.kind === 'ready' && !localReport && reader === systemBackupReadService && (kind === 'backups' || kind === 'preflights')
        && state.detail.task.can_cancel && ['pending', 'preparing', 'ready_for_capture', 'acquiring_gate', 'capturing', 'canceling', 'validating'].includes(state.detail.task.status)
        && <BackupCancelUnstarted key={public_id} selection={selection} active={state.detail.task.status !== 'pending'} canceled={() => { setState({ kind: 'loading' }); setRevision(v => v + 1); }} />}
      {downloadEvidence !== null && <div className="mt-5">{localReport ? localReport(downloadEvidence) : <BackupEvidenceDownload
        installation={origin_installation_id} evidenceId={downloadEvidence.public_id} />}</div>}
    </>}
    {(section === 'events' || section === 'logs' && state.kind === 'ready') &&
      <BackupLiveActivity key={`${revision}:${section}`} selection={selection} channel={section} viewEvents={() => setSection('events')} />}
  </section>;
}
