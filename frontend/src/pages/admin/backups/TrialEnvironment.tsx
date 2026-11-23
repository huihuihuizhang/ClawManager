import { useI18n } from '../../../contexts/I18nContext';

type Placement = {
  cluster: string;
  namespace: string;
  image: string;
  service_account: string;
  artifact_claim: string;
  artifact_storage_class?: string;
  workspace_claim?: string;
  workspace_storage_class?: string;
  instance_storage_class?: string;
  key_secret: string;
  source_read_secret?: string;
  restore_write_secret?: string;
  restore_read_secret?: string;
  runtime_secret?: string;
};

export type TrialEnvironmentStatus = {
  state: 'unregistered' | 'invalid' | 'registered' | 'waiting' | 'running' | 'prepared' | 'failed' | 'unavailable';
  profile?: {
    revision: string;
    side: 'source' | 'target';
    source: Placement;
    target: Placement;
    prepare_job?: { name: string; uid: string };
  };
};

type Props = {
  environment: TrialEnvironmentStatus;
  disabled: boolean;
  preparing: boolean;
  onPrepare: () => void;
};

export default function TrialEnvironment({ environment, disabled, preparing, onPrepare }: Props) {
  const { locale } = useI18n();
  const zh = locale.startsWith('zh');
  const { profile, state } = environment;
  const statuses: Record<TrialEnvironmentStatus['state'], string> = zh ? {
    unregistered: '平台尚未登记试行配置',
    invalid: '登记的试行配置无效，请联系平台管理员核对',
    registered: '已登记配置，尚未绑定准备任务',
    waiting: '准备任务可启动',
    running: '正在准备试行环境',
    prepared: '准备任务已完成',
    failed: '准备任务失败，请联系平台管理员处理后重新登记',
    unavailable: '无法读取或启动已登记的准备任务',
  } : {
    unregistered: 'The platform has not registered trial configuration',
    invalid: 'The registered trial configuration is invalid. Contact the platform administrator.',
    registered: 'Configuration is registered. No preparation job is assigned.',
    waiting: 'Ready to run the preparation job',
    running: 'Preparing the trial environment',
    prepared: 'Preparation job completed',
    failed: 'The preparation job failed. Ask the platform administrator to resolve it and register a replacement.',
    unavailable: 'Cannot read or start the registered preparation job',
  };
  const fieldLabels: Record<keyof Placement, string> = zh ? {
    cluster: '集群', namespace: '命名空间', image: '镜像', service_account: '服务账号',
    artifact_claim: '产物 PVC', artifact_storage_class: '产物存储类', workspace_claim: '工作区 PVC',
    workspace_storage_class: '工作区存储类', instance_storage_class: '实例存储类',
    key_secret: '加密密钥 Secret', source_read_secret: '源只读 Secret', restore_write_secret: '恢复写入 Secret',
    restore_read_secret: '独立复核 Secret', runtime_secret: '运行账号 Secret',
  } : {
    cluster: 'Cluster', namespace: 'Namespace', image: 'Image', service_account: 'Service account',
    artifact_claim: 'Artifact PVC', artifact_storage_class: 'Artifact storage class', workspace_claim: 'Workspace PVC',
    workspace_storage_class: 'Workspace storage class', instance_storage_class: 'Instance storage class',
    key_secret: 'Encryption key Secret', source_read_secret: 'Source reader Secret', restore_write_secret: 'Restore writer Secret',
    restore_read_secret: 'Independent verifier Secret', runtime_secret: 'Runtime account Secret',
  };

  function download() {
    if (!profile) return;
    const file = new Blob([JSON.stringify(profile, null, 2) + '\n'], { type: 'application/json' });
    const url = URL.createObjectURL(file);
    const link = document.createElement('a');
    link.href = url;
    link.download = `backup-trial-${profile.side}-${profile.revision}.json`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  return <div className="space-y-2 rounded-lg border border-slate-200 p-3" aria-labelledby="trial-environment-title">
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <h3 id="trial-environment-title" className="text-sm font-medium text-slate-900">{zh ? '试行环境配置' : 'Trial environment configuration'}</h3>
      {profile && <span className="text-sm text-slate-600">{zh ? '版本 ' : 'Revision '}{profile.revision}</span>}
    </div>
    <p role="status" className={state === 'failed' || state === 'invalid' || state === 'unavailable' ? 'text-sm text-amber-900' : 'text-sm text-slate-700'}>
      {preparing ? (zh ? '正在启动准备任务…' : 'Starting preparation…') : statuses[state]}
    </p>
    {profile && <>
      <div className="flex flex-wrap gap-2">
        {profile.prepare_job && <button type="button" className="rounded-lg border border-slate-200 px-3 py-2 text-sm font-medium disabled:opacity-40"
          disabled={disabled || preparing || state !== 'waiting'} onClick={onPrepare}>
          {zh ? '准备试行环境' : 'Prepare trial environment'}
        </button>}
        <button type="button" className="rounded-lg border border-slate-200 px-3 py-2 text-sm font-medium" onClick={download}>
          {zh ? '下载配置摘要' : 'Download configuration summary'}
        </button>
      </div>
      <details>
        <summary className="cursor-pointer text-sm text-slate-800">{zh ? '查看源和目标配置' : 'View source and target configuration'}</summary>
        <div className="mt-2 grid gap-3 lg:grid-cols-2">
          {(['source', 'target'] as const).map((side) => <div key={side} className="min-w-0">
            <h4 className="text-sm font-medium text-slate-800">{side === 'source' ? (zh ? '备份源' : 'Backup source') : (zh ? '隔离目标' : 'Isolated target')}
              {profile.side === side && (zh ? '（当前）' : ' (current)')}</h4>
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 py-1 text-sm text-slate-700">
              {(Object.keys(fieldLabels) as (keyof Placement)[]).filter((key) => profile[side][key]).map((key) =>
                <div className="contents" key={key}><dt>{fieldLabels[key]}</dt><dd className="break-all font-mono">{profile[side][key]}</dd></div>)}
            </dl>
          </div>)}
        </div>
      </details>
    </>}
  </div>;
}
