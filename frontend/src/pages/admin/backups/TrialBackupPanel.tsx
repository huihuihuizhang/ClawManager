import { useEffect, useState } from 'react';
import { useI18n } from '../../../contexts/I18nContext';
import api from '../../../services/api';
import TrialEnvironment, { type TrialEnvironmentStatus } from './TrialEnvironment';
import {
  createTrialHandoff, downloadTrialJson, isTrialBackupID, matchesTrialHandoff, readTrialHandoff, type TrialRestoreHandoff,
} from './trialRestoreHandoff';

const route = '/admin/system-backup/trial';
type Task = {
  id: string;
  backup_id?: string;
  status: 'running' | 'succeeded' | 'failed';
  stage: string;
  error?: string;
  readback_verified: boolean;
  ciphertext_sha256?: string;
  counts?: Record<string, number>;
  hermes_history?: { sessions: number; messages: number; transcript_sha256: string };
  workspace_files?: { entries: number; file_bytes: number; archive_sha256: string };
};
type Readiness = { missing: string[] | null; restore_missing: string[] | null; environment?: TrialEnvironmentStatus };
type RestorePreflight = Pick<Task, 'readback_verified' | 'ciphertext_sha256' | 'counts' | 'hermes_history' | 'workspace_files'> & {
  backup_id: string;
  missing?: string;
};

const mountReadinessCodes = new Set(['source_credential', 'restore_credential', 'restore_read_credential', 'encryption_key']);

function waitingForProjectedMaterials(ready?: Readiness) {
  const environment = ready?.environment;
  if (environment?.state !== 'prepared' || !environment.profile) return false;
  const missing = environment.profile.side === 'source' ? ready?.missing : ready?.restore_missing;
  return missing?.some((item) => mountReadinessCodes.has(item)) ?? false;
}

export default function TrialBackupPanel() {
  const { locale } = useI18n();
  const zh = locale.startsWith('zh');
  const [ready, setReady] = useState<Readiness>();
  const [task, setTask] = useState<Task>();
  const [backupID, setBackupID] = useState('');
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState(false);
  const [preflight, setPreflight] = useState<RestorePreflight>();
  const [checkingBackup, setCheckingBackup] = useState(false);
  const [preparing, setPreparing] = useState(false);
  const [revision, setRevision] = useState(0);
  const [handoff, setHandoff] = useState<TrialRestoreHandoff>();
  const [handoffError, setHandoffError] = useState<'invalid' | 'placement'>();
  const [readingHandoff, setReadingHandoff] = useState(false);
  const profile = ready?.environment?.profile;
  const mayAutofillBackup = !!ready && profile?.side !== 'target';
  const running = task?.status === 'running';
  const preparationRunning = ready?.environment?.state === 'running';
  const materialsPending = waitingForProjectedMaterials(ready);
  const actionPending = running || busy || checkingBackup || preparing || readingHandoff;
  const handoffPlacementDiffers = !!handoff && !!ready && (profile?.side !== 'target' || !matchesTrialHandoff(handoff, profile));
  const canCheck = !!ready && !ready.restore_missing?.length && !actionPending && !handoffPlacementDiffers && isTrialBackupID(backupID);
  const matchingPreflight = preflight?.backup_id === backupID ? preflight : undefined;
  const handoffDigestDiffers = !!handoff && matchingPreflight?.readback_verified === true &&
    matchingPreflight.ciphertext_sha256 !== handoff.ciphertext_sha256;
  const canRestore = canCheck && matchingPreflight?.readback_verified && !matchingPreflight.missing && !handoffDigestDiffers;
  const exportHandoff = profile?.side === 'source' && task?.status === 'succeeded' && task.readback_verified && task.id === task.backup_id
    ? createTrialHandoff(profile, task.backup_id, task.ciphertext_sha256) : undefined;

  useEffect(() => {
    const controller = new AbortController();
    api.get<Readiness>(route + '/readiness', { signal: controller.signal })
      .then(({ data }) => { if (!controller.signal.aborted) setReady(data); })
      .catch(() => { if (!controller.signal.aborted) setError(true); });
    return () => controller.abort();
  }, [revision]);

  useEffect(() => {
    if (!preparationRunning && !materialsPending) return;
    const controller = new AbortController();
    // A completed Job can precede kubelet's next projected Secret refresh.
    const materialDeadline = materialsPending ? Date.now() + 120_000 : undefined;
    let timer = window.setTimeout(poll, 2500);
    async function poll() {
      try {
        const { data } = await api.get<Readiness>(route + '/readiness', { signal: controller.signal });
        if (controller.signal.aborted) return;
        setReady(data);
        if (data.environment?.state !== 'running' && !waitingForProjectedMaterials(data)) return;
      } catch {
        if (controller.signal.aborted) return;
      }
      if (!materialDeadline || Date.now() < materialDeadline) timer = window.setTimeout(poll, 2500);
    }
    return () => { controller.abort(); window.clearTimeout(timer); };
  }, [preparationRunning, materialsPending]);

  useEffect(() => {
    const controller = new AbortController();
    let timer: number | undefined;
    async function poll() {
      try {
        const { data } = await api.get<{ task: Task | null }>(route + '/task', { signal: controller.signal });
        if (controller.signal.aborted) return;
        setTask(data.task ?? undefined);
        const completed = data.task?.status === 'succeeded' ? data.task.backup_id : undefined;
        if (completed && mayAutofillBackup) setBackupID((current) => current || completed);
      } catch {
        if (!controller.signal.aborted) setError(true);
      }
      if (!controller.signal.aborted) timer = window.setTimeout(poll, 2000);
    }
    void poll();
    return () => { controller.abort(); window.clearTimeout(timer); };
  }, [revision, mayAutofillBackup]);

  function refreshReadiness() {
    setReady(undefined);
    setPreflight(undefined);
    setRevision((value) => value + 1);
  }

  async function prepareEnvironment() {
    setPreparing(true);
    setError(false);
    try {
      const { data } = await api.post<TrialEnvironmentStatus>(route + '/environment/prepare');
      if (data.state === 'prepared') {
        refreshReadiness();
      } else {
        setReady((current) => current && { ...current, environment: data });
      }
    } catch {
      setError(true);
    } finally {
      setPreparing(false);
    }
  }

  async function checkBackup() {
    if (!canCheck) return;
    setCheckingBackup(true);
    setError(false);
    setPreflight(undefined);
    try {
      const { data } = await api.post<RestorePreflight>(route + '/backups/' + backupID + '/preflight');
      setPreflight(data);
    } catch {
      setError(true);
    } finally {
      setCheckingBackup(false);
    }
  }

  async function start(restore: boolean) {
    if (restore && !canRestore) return;
    setBusy(true);
    setError(false);
    try {
      const suffix = restore ? '/backups/' + backupID + '/restore' : '/backups';
      const digest = restore ? matchingPreflight?.ciphertext_sha256 : undefined;
      const { data } = await api.post<Task>(route + suffix, undefined,
        digest ? { params: { expected_ciphertext_sha256: digest } } : undefined);
      setTask(data);
      if (!restore) setBackupID('');
    } catch {
      setError(true);
    } finally {
      setBusy(false);
      refreshReadiness();
    }
  }

  function clearHandoff() {
    setHandoff(undefined);
    setHandoffError(undefined);
    setBackupID('');
    setPreflight(undefined);
  }

  async function importHandoff(file: File) {
    clearHandoff();
    setReadingHandoff(true);
    try {
      const selection = await readTrialHandoff(file);
      if (profile?.side !== 'target' || !matchesTrialHandoff(selection, profile)) {
        setHandoffError('placement');
        return;
      }
      setBackupID(selection.backup_id);
      setHandoff(selection);
    } catch {
      setHandoffError('invalid');
    } finally {
      setReadingHandoff(false);
    }
  }

  const labels: Record<string, string> = zh ? {
    prepare: '准备', capture: '采集', encrypt: '加密写入', readback: '独立读回',
    restore: '写入隔离库', verify: '恢复对账', done: '已完成',
    restore_hermes_history: '恢复 Hermes 对话', hermes_history: 'Hermes 对话无法校验或恢复',
    restore_workspace_files: '恢复工作区文件', workspace_files: '工作区文件无法校验或恢复',
    running: '运行中', succeeded: '成功', failed: '失败',
    source_credential: '试行源库凭据', source_isolation: '源库身份或只读授权',
    source_schema: '源库表结构', encryption_key: '试行加密密钥', storage_mounts: '专用存储挂载',
    storage_write_readback: '存储写入或独立读回', restore_isolation: '目标隔离与 MySQL 身份',
    restore_credential: '目标写入凭据', restore_read_credential: '目标只读凭据',
    restore_placement: '隔离目标的存储与命名空间', restore_database_name: '隔离库名称',
    restore_artifact_mount: '试行产物只读挂载',
    restore_artifact_configuration: '请检查导入目录和试行加密密钥',
    restore_artifact_missing: '找不到这份备份的密文或回执',
    restore_artifact_readback: '这份备份的完整性或解密校验失败',
    restore_artifact_changed: '导入密文已变化，请核对交接单后重新预检',
    restore_artifact_writable: '导入卷可写，请重新以只读方式挂载',
    trial_environment_source: '请在已登记的源环境创建备份',
    trial_environment_target: '请在已登记的隔离目标恢复',
    trial_environment_preparation: '试行环境准备尚未通过',
    restore_target_schema: '目标库缺少用户、配额或实例所需的表结构，请检查迁移',
    restore_target_database: '无法检查目标库的表结构',
    restore_database_mismatch: '写入和只读凭据指向不同的库', restore_accounts_shared: '写入和只读必须使用独立账号',
    restore_writer_database: '无法使用写入凭据连接目标库', restore_writer_isolation: '写入连接的目标库身份不匹配',
    restore_reader_database: '无法使用只读凭据连接或检查目标库', restore_reader_isolation: '只读连接身份或 SELECT 授权不符合要求',
  } : {
    hermes_history: 'The target Hermes workspace failed its check',
    workspace_files: 'The target workspace files failed their check',
    restore_artifact_configuration: 'Check the import directory and trial encryption key',
    restore_artifact_missing: 'The backup ciphertext or receipt is missing',
    restore_artifact_readback: 'The backup integrity or decryption check failed',
    restore_artifact_changed: 'The imported ciphertext changed. Check the handoff and run preflight again.',
    restore_artifact_writable: 'Mount the trial import volume as read-only',
    trial_environment_source: 'Create backups in the registered source environment',
    trial_environment_target: 'Restore only in the registered target environment',
    trial_environment_preparation: 'Trial environment preparation is pending',
    restore_target_schema: 'The target lacks the required user, quota, or instance schema. Check its migrations.',
    restore_target_database: 'Cannot inspect the target database schema',
    restore_database_mismatch: 'Writer and reader credentials must point to the same target database',
    restore_accounts_shared: 'Writer and reader must use separate accounts',
    restore_writer_database: 'Cannot connect to the target database with the writer credentials',
    restore_writer_isolation: 'The writer connection returned a different target identity',
    restore_reader_database: 'Cannot connect to or inspect the target database with the reader credentials',
    restore_reader_isolation: 'The reader identity or SELECT grants failed validation',
  };
  const label = (code: string) => labels[code] ?? code.replaceAll('_', ' ');
  const button = 'rounded-lg border border-slate-200 px-3 py-2 text-sm font-medium disabled:opacity-40';
  return <section className="space-y-3 rounded-xl border border-slate-200 bg-white p-5" aria-labelledby="trial-backup-title">
    <h2 id="trial-backup-title" className="font-semibold text-slate-900">{zh ? '备份（试行版）' : 'Backup (trial)'}</h2>
    <p className="text-sm text-slate-600">{zh
      ? '范围包括用户、配额、实例规格和启动所需配置。恢复到预先配置的隔离目标，实例初始为停止状态。'
      : 'Includes users, quotas, instance specifications and startup configuration. Instances are restored stopped to the configured isolated target.'}</p>
    {ready?.environment && <TrialEnvironment environment={ready.environment} disabled={running || busy || checkingBackup || readingHandoff}
      preparing={preparing} onPrepare={() => void prepareEnvironment()} />}
    <div className="flex flex-wrap items-center gap-2">
      <button type="button" className={button} disabled={!ready || !!ready.missing?.length || actionPending} onClick={() => void start(false)}>
        {zh ? '创建试行备份' : 'Create trial backup'}
      </button>
      <button type="button" className={button} disabled={checkingBackup || preparing || readingHandoff} onClick={() => { setError(false); refreshReadiness(); }}>
        {zh ? '检查试行就绪状态' : 'Check trial readiness'}
      </button>
    </div>
    {error && <p role="alert" className="text-sm text-red-700">{zh ? '试行请求失败，请检查就绪状态后重试。' : 'Trial request failed. Check readiness and try again.'}</p>}
    {!!ready?.missing?.length && <p className="text-sm text-amber-900">{zh ? '备份缺项 · ' : 'Backup requires · '}{ready.missing.map(label).join(' · ')}</p>}
    {ready && (ready.restore_missing?.length
      ? <p className="text-sm text-amber-900">{zh ? '恢复缺项 · ' : 'Restore requires · '}{ready.restore_missing.map(label).join(' · ')}</p>
      : <p className="text-sm text-emerald-700">{zh ? '目标库身份、基础表结构和导入卷已校验' : 'Target database identity, required tables, and import mount verified'}</p>)}
    {profile?.side === 'target' && <div className="space-y-1 text-sm text-slate-700">
      <div className="flex flex-wrap items-center gap-2">
        <label className="flex min-w-0 flex-wrap items-center gap-2">
          {zh ? '选择恢复交接单' : 'Select a restore handoff'}
          <input type="file" accept=".json,application/json" disabled={actionPending}
            className="max-w-full text-xs file:mr-2 file:rounded-md file:border-0 file:bg-slate-100 file:px-2 file:py-1"
            onChange={(event) => {
              const file = event.currentTarget.files?.[0];
              event.currentTarget.value = '';
              if (file) void importHandoff(file);
            }} />
        </label>
        {handoff && <button type="button" className={button} disabled={actionPending} onClick={clearHandoff}>
          {zh ? '清除交接单' : 'Clear handoff'}
        </button>}
      </div>
      <p>{zh ? '将密文和存储回执交付到目标导入卷后，再检查此备份。' : 'Place the ciphertext and storage receipt on the target import volume before checking the backup.'}</p>
    </div>}
    {(handoffError || handoffPlacementDiffers) && <p role="alert" className="text-sm text-red-700">
      {handoffError === 'invalid'
        ? (zh ? '无法读取交接单，请选择从源端下载的 JSON 文件。' : 'Cannot read the handoff. Select the JSON file downloaded from the source.')
        : (zh ? '交接单与当前登记的源或目标不匹配。' : 'The handoff does not match the registered source or target.')}
    </p>}
    <div className="flex flex-wrap items-end gap-2">
      <label className="flex min-w-0 flex-col gap-1 text-sm text-slate-700">
        {zh ? '试行备份 ID' : 'Trial backup ID'}
        <input value={backupID} maxLength={32} readOnly={!!handoff} disabled={checkingBackup || readingHandoff} onChange={(event) => {
          setBackupID(event.target.value.trim());
          setPreflight(undefined);
          setHandoffError(undefined);
        }}
          className="w-72 max-w-full rounded-lg border border-slate-200 px-3 py-2 font-mono" />
      </label>
      <button type="button" className={button} disabled={!canCheck} onClick={() => void checkBackup()}>
        {checkingBackup ? (zh ? '正在检查备份…' : 'Checking backup…') : (zh ? '检查此备份' : 'Check this backup')}
      </button>
      <button type="button" className={button} disabled={!canRestore}
        onClick={() => void start(true)}>{zh ? '恢复到隔离环境' : 'Restore to isolated target'}</button>
    </div>
    {matchingPreflight && <div aria-live="polite" className="space-y-1 text-sm text-slate-700">
      <p className={matchingPreflight.missing || handoffDigestDiffers ? 'text-amber-900' : 'text-emerald-700'}>{matchingPreflight.missing
        ? label(matchingPreflight.missing)
        : handoffDigestDiffers
          ? (zh ? '目标导入的密文摘要与交接单不一致。' : 'The imported ciphertext digest differs from the handoff.')
          : (zh ? '产物读回和恢复内容预检通过' : 'Artifact readback and restore content checks passed')}</p>
      {matchingPreflight.counts && <p>{zh
        ? `${matchingPreflight.counts.users ?? 0} 个用户 · ${matchingPreflight.counts.instances ?? 0} 个实例`
        : `${matchingPreflight.counts.users ?? 0} users · ${matchingPreflight.counts.instances ?? 0} instances`}</p>}
      {matchingPreflight.hermes_history && <p>{zh
        ? `${matchingPreflight.hermes_history.messages} 条 Hermes 消息`
        : `${matchingPreflight.hermes_history.messages} Hermes messages`}</p>}
      {matchingPreflight.workspace_files && <p>{zh
        ? `${matchingPreflight.workspace_files.entries} 项工作区内容`
        : `${matchingPreflight.workspace_files.entries} workspace entries`}</p>}
    </div>}
    {task && <div role="status" className="space-y-2 text-sm text-slate-700">
      <p>{zh ? '任务' : 'Task'} <code>{task.id}</code> · {label(task.status)} · {label(task.stage)}{task.error && ` · ${label(task.error)}`}</p>
      {task.backup_id && <p>{zh ? '试行产物' : 'Trial artifact'} <code>{task.backup_id}</code></p>}
      {exportHandoff && <button type="button" className={button}
        onClick={() => downloadTrialJson(`backup-trial-restore-${exportHandoff.backup_id}.json`, exportHandoff)}>
        {zh ? '下载恢复交接单' : 'Download restore handoff'}
      </button>}
      {task.readback_verified && <p className="text-emerald-700">{zh ? '独立读回校验通过' : 'Independent readback verified'}</p>}
      {task.hermes_history && <p>{zh
        ? `Hermes 对话 · ${task.hermes_history.sessions} 个会话 · ${task.hermes_history.messages} 条消息`
        : `Hermes history · ${task.hermes_history.sessions} sessions · ${task.hermes_history.messages} messages`}</p>}
      {task.workspace_files && <p>{zh
        ? `工作区文件 · ${task.workspace_files.entries} 项 · ${task.workspace_files.file_bytes.toLocaleString()} 字节`
        : `Workspace files · ${task.workspace_files.entries} entries · ${task.workspace_files.file_bytes.toLocaleString()} bytes`}</p>}
      {task.counts && <dl className="flex flex-wrap gap-x-5 gap-y-1">{Object.entries(task.counts).map(([table, count]) =>
        <div className="flex gap-2" key={table}><dt>{table}</dt><dd>{count}</dd></div>)}</dl>}
    </div>}
  </section>;
}

