import { useEffect, useRef, useState } from 'react';
import type { SystemBackupTask } from '../../../types/systemBackupContract';
import type { BackupDetailSelection } from './backupLiveDetail';
import BackupTaskTable from './BackupTaskTable';
import BackupLiveDetail from './BackupLiveDetail.tsx';
import { EvidenceDownloadForm } from './BackupEvidenceDownload.tsx';
import { labDownload, labInstallation, labReader, labRequest } from './verificationLab';
import type { LabCheck, LabScenario, LabState } from './verificationLab';

const button = 'rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm disabled:opacity-50';

export default function BackupVerificationLab() {
  const [state, setState] = useState<LabState | null>(null);
  const [tasks, setTasks] = useState<SystemBackupTask[]>([]);
  const [selection, setSelection] = useState<BackupDetailSelection | null>(null);
  const [checks, setChecks] = useState<LabCheck[]>([]);
  const [scenario, setScenario] = useState<LabScenario>('match');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  const action = useRef<AbortController | null>(null);
  const polling = useRef<AbortController | null>(null);
  const [detailEpoch, setDetailEpoch] = useState(0);

  useEffect(() => {
    const controller = new AbortController(); polling.current = controller;
    let timer: ReturnType<typeof setTimeout>;
    const refresh = async () => {
      try {
        const next = await labRequest<LabState>('/state', controller.signal);
        const page = await labReader.list('verifications', controller.signal);
        if (controller.signal.aborted) return;
        setState(next); setTasks(page.items); setError('');
        setSelection(current => {
          if (!current) return current;
          const row = page.items.find(item => item.public_id === current.public_id);
          return row ? { ...current, row_version: row.row_version } : null;
        });
      } catch {
        if (!controller.signal.aborted) setError('无法读取测试服务。请按操作手册启动服务后点击“刷新状态”。');
      }
      if (!controller.signal.aborted) timer = setTimeout(refresh, 750);
    };
    void refresh();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [revision]);

  const selectedID = selection?.public_id;
  const selectedVersion = selection?.row_version;
  useEffect(() => {
    if (!selectedID) return;
    const controller = new AbortController();
    labRequest<LabCheck[]>(`/tasks/${selectedID}/checks`, controller.signal).then(value => {
      if (!controller.signal.aborted) setChecks(value);
    }).catch(() => { if (!controller.signal.aborted) setError('检查项读取失败，请刷新状态重试。'); });
    return () => controller.abort();
  }, [selectedID, selectedVersion]);
  useEffect(() => () => { action.current?.abort(); }, []);

  const perform = async (kind: 'prepare' | 'execute' | 'reset') => {
    if (action.current) return;
    const controller = new AbortController(); action.current = controller;
    polling.current?.abort(); setBusy(true); setError('');
    setChecks([]); setSelection(null); setDetailEpoch(value => value + 1);
    try {
      if (kind === 'prepare') await labRequest('/prepare', controller.signal, { scenario });
      if (kind === 'execute') {
        // Executing consumes this prepared input exactly once.
        const detail = await labRequest<{ task: SystemBackupTask }>('/execute', controller.signal, { id: state?.prepared?.id });
        if (!controller.signal.aborted) {
          setState(current => current && { ...current, prepared: null, running: true });
          setSelection({ kind: 'verifications', public_id: detail.task.public_id, row_version: detail.task.row_version, origin_installation_id: labInstallation });
        }
      }
      if (kind === 'reset') { await labRequest('/reset', controller.signal, {}); setState(null); setTasks([]); }
    } catch (failure) {
      if (!controller.signal.aborted) setError(failure instanceof Error ? failure.message : '测试请求失败，请刷新状态。');
    } finally {
      if (!controller.signal.aborted) { action.current = null; setBusy(false); setRevision(value => value + 1); }
    }
  };
  return <main className="mx-auto max-w-6xl space-y-5 p-5 text-slate-900">
    <header><h1 className="text-2xl font-semibold">D · A 校验独立测试入口</h1>
      <p className="mt-3 rounded-lg border border-amber-300 bg-amber-50 p-4 text-sm leading-6">合成输入 · 实际调用 A 的 VerifyBackupSnapshot · 本机内存隔离。注册审批和捕获证明为测试夹具；结果仅验证快照检查逻辑，不代表现场数据库、备份可用性或恢复验收。</p></header>
    <section className="space-y-4 rounded-xl border border-slate-200 bg-white p-5" aria-label="固定操作流程">
      <h2 className="font-semibold">启动 → 准备数据 → 执行 → 查看并下载报告 → 重置</h2>
      <ol className="list-inside list-decimal space-y-2 text-sm leading-6">
        <li>按 docs/system-backup-d-verification-lab.md 启动；服务状态：{state ? '已连接' : '等待连接'}。</li>
        <li>选择测试场景，点击“准备数据”。每次执行前重新准备。</li>
        <li>点击“执行校验”，列表自动刷新，点击任务 ID 查看详情、检查项和报告。</li>
        <li>点击“重置演示”，清空本次进程的输入、任务与报告，再重复以上步骤。</li>
      </ol>
      <label className="flex flex-wrap items-center gap-3 text-sm">测试场景<select aria-label="测试场景" className={button} value={scenario} disabled={busy || state?.running}
        onChange={event => setScenario(event.target.value as LabScenario)}>
        <option value="match">数据一致（通过）</option><option value="mismatch">行数不一致（检查失败）</option><option value="missing-proof">缺少捕获证明（拒绝校验）</option>
      </select></label>
      <div className="flex flex-wrap gap-3"><button className={button} disabled={!state || busy || state.running} onClick={() => void perform('prepare')}>准备数据</button>
        <button className={`${button} !bg-rose-600 !text-white`} disabled={!state?.prepared || busy || state.running || state.run_count >= 20}
          onClick={() => void perform('execute')}>执行校验</button>
        <button className={button} disabled={busy} onClick={() => void perform('reset')}>重置演示</button>
        <button className={button} disabled={busy} onClick={() => setRevision(value => value + 1)}>刷新状态</button></div>
      <p role="status" aria-live="polite" className="text-sm">{busy ? '正在提交操作…' : state?.running ? '校验运行中…' : state?.prepared ? `数据已准备：${state.prepared.scenario}，可执行校验。` : '等待准备数据。'} {state && `已执行 ${state.run_count}/20 次。`}</p>
    </section>
    {error && <p role="alert" className="rounded-lg bg-red-50 p-4 text-red-800">{error}</p>}
    <section className="rounded-xl border border-slate-200 bg-white p-5"><h2 className="font-semibold">校验任务列表</h2>
      {tasks.length ? <BackupTaskTable items={tasks} kind="verifications" selected={selection} select={next => { setChecks([]); setSelection(next); }} /> : <p className="mt-3 text-sm text-slate-500">尚无校验任务，请准备数据并执行。</p>}</section>
    {selection && <BackupLiveDetail key={`${detailEpoch}:${selection.public_id}:${selection.row_version}`} selection={selection} close={() => { setSelection(null); setChecks([]); }} reader={labReader}
      localReport={ref => <EvidenceDownloadForm installation={labInstallation} evidenceId={ref.public_id} download={labDownload(ref.sha256)} localTest />} />}
    {selection && <section className="rounded-xl border border-slate-200 bg-white p-5"><h2 className="font-semibold">A 返回的检查项</h2>
      {checks.length ? <div className="mt-3 overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr>{['检查 ID','状态','预期','实际'].map(title => <th key={title} className="p-2">{title}</th>)}</tr></thead>
        <tbody>{checks.map(check => <tr key={check.id} className="border-t"><td className="break-all p-2 font-mono text-xs">{check.id}</td><td className="p-2">{check.status}</td><td className="break-all p-2">{JSON.stringify(check.expected)}</td><td className="break-all p-2">{JSON.stringify(check.actual)}</td></tr>)}</tbody></table></div>
        : <p className="mt-3 text-sm text-slate-500">运行中或 A 未返回检查项；缺少证明时直接拒绝，可下载报告查看失败类别。</p>}</section>}
  </main>;
}
