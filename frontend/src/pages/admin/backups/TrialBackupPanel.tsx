import { useEffect, useState } from 'react';
import { useI18n } from '../../../contexts/I18nContext';
import api from '../../../services/api';

const route = '/admin/system-backup/trial';
type Task = {
  id: string;
  backup_id?: string;
  status: 'running' | 'succeeded' | 'failed';
  stage: string;
  error?: string;
  readback_verified: boolean;
  counts?: Record<string, number>;
  hermes_history?: { sessions: number; messages: number; transcript_sha256: string };
  workspace_files?: { entries: number; file_bytes: number; archive_sha256: string };
};
type Readiness = { missing: string[] | null; restore_missing: string[] | null };

export default function TrialBackupPanel() {
  const { locale } = useI18n();
  const zh = locale.startsWith('zh');
  const [ready, setReady] = useState<Readiness>();
  const [task, setTask] = useState<Task>();
  const [backupID, setBackupID] = useState('');
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const running = task?.status === 'running';

  useEffect(() => {
    const controller = new AbortController();
    api.get<Readiness>(route + '/readiness', { signal: controller.signal })
      .then(({ data }) => { if (!controller.signal.aborted) setReady(data); })
      .catch(() => { if (!controller.signal.aborted) setError(true); });
    return () => controller.abort();
  }, [revision]);

  useEffect(() => {
    const controller = new AbortController();
    let timer: number | undefined;
    async function poll() {
      try {
        const { data } = await api.get<{ task: Task | null }>(route + '/task', { signal: controller.signal });
        if (controller.signal.aborted) return;
        setTask(data.task ?? undefined);
        const completed = data.task?.status === 'succeeded' ? data.task.backup_id : undefined;
        if (completed) setBackupID((current) => current || completed);
      } catch {
        if (!controller.signal.aborted) setError(true);
      }
      if (!controller.signal.aborted) timer = window.setTimeout(poll, 2000);
    }
    void poll();
    return () => { controller.abort(); window.clearTimeout(timer); };
  }, [revision]);

  function refreshReadiness() {
    setReady(undefined);
    setRevision((value) => value + 1);
  }

  async function start(restore: boolean) {
    setBusy(true);
    setError(false);
    try {
      const suffix = restore ? '/backups/' + backupID + '/restore' : '/backups';
      const { data } = await api.post<Task>(route + suffix);
      setTask(data);
      if (!restore) setBackupID('');
    } catch {
      setError(true);
    } finally {
      setBusy(false);
      refreshReadiness();
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
    restore_artifact_writable: '导入卷可写，请重新以只读方式挂载',
    restore_target_schema: '目标库缺少用户、配额或实例所需的表结构，请检查迁移',
    restore_target_database: '无法检查目标库的表结构',
    restore_database_mismatch: '写入和只读凭据指向不同的库', restore_accounts_shared: '写入和只读必须使用独立账号',
    restore_writer_database: '无法使用写入凭据连接目标库', restore_writer_isolation: '写入连接的目标库身份不匹配',
    restore_reader_database: '无法使用只读凭据连接或检查目标库', restore_reader_isolation: '只读连接身份或 SELECT 授权不符合要求',
  } : {
    restore_artifact_writable: 'Mount the trial import volume as read-only',
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
    <div className="flex flex-wrap items-center gap-2">
      <button type="button" className={button} disabled={!ready || !!ready.missing?.length || running || busy} onClick={() => void start(false)}>
        {zh ? '创建试行备份' : 'Create trial backup'}
      </button>
      <button type="button" className={button} onClick={() => { setError(false); refreshReadiness(); }}>
        {zh ? '检查试行就绪状态' : 'Check trial readiness'}
      </button>
    </div>
    {error && <p role="alert" className="text-sm text-red-700">{zh ? '试行请求失败，请检查就绪状态后重试。' : 'Trial request failed. Check readiness and try again.'}</p>}
    {!!ready?.missing?.length && <p className="text-sm text-amber-900">{zh ? '备份缺项 · ' : 'Backup requires · '}{ready.missing.map(label).join(' · ')}</p>}
    {ready && (ready.restore_missing?.length
      ? <p className="text-sm text-amber-900">{zh ? '恢复缺项 · ' : 'Restore requires · '}{ready.restore_missing.map(label).join(' · ')}</p>
      : <p className="text-sm text-emerald-700">{zh ? '目标库身份、基础表结构和导入卷已校验' : 'Target database identity, required tables, and import mount verified'}</p>)}
    <div className="flex flex-wrap items-end gap-2">
      <label className="flex min-w-0 flex-col gap-1 text-sm text-slate-700">
        {zh ? '试行备份 ID' : 'Trial backup ID'}
        <input value={backupID} maxLength={32} onChange={(event) => setBackupID(event.target.value.trim())}
          className="w-72 max-w-full rounded-lg border border-slate-200 px-3 py-2 font-mono" />
      </label>
      <button type="button" className={button} disabled={!ready || !!ready.restore_missing?.length || running || busy || !/^[0-9a-f]{32}$/.test(backupID)}
        onClick={() => void start(true)}>{zh ? '恢复到隔离环境' : 'Restore to isolated target'}</button>
    </div>
    {task && <div role="status" className="space-y-2 text-sm text-slate-700">
      <p>{zh ? '任务' : 'Task'} <code>{task.id}</code> · {label(task.status)} · {label(task.stage)}{task.error && ` · ${label(task.error)}`}</p>
      {task.backup_id && <p>{zh ? '试行产物' : 'Trial artifact'} <code>{task.backup_id}</code></p>}
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
