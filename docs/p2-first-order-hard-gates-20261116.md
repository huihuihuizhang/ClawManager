# 现场首单硬性条件与处理顺序（2026-11-16）

目标保持为：原安装完整接管、配置启用后，从正式页面创建一单；同一任务完成完整采集、恢复、上传、独立读回和登记。以下把已确认的拒绝条件集中列出；“待现场验证”不表示已通过，也不表示已经证明存在代码缺口。

权威现场回执和精确文件 pin 见 `p2-minimal-loop-handoff-20261115.json` 的 `current_site_state_20261116_1148`。旧历史段落不覆盖该字段。

| 顺序 | 硬性条件及拒绝点 | 当前证据 | 对应处理 / 完成标志 |
| --- | --- | --- | --- |
| 1 | 所有实际参与进程必须有停写与恢复证明；无目录节点不能拿空 host cut 代替进程证明 | 本地原生进程、完整及部分恢复检查通过；controller、两节点 owner、独立 whole reader 已部署 | 现场 C1 与正式任务必须读到真实停止、替代进程及最终恢复回执；进程证明仍禁止进入文件归档入口 |
| 2 | 运行程序、持久恢复目录及实际服务配置必须匹配交付 | 镜像 `0fad0e52…`、实际四 ELF 与两节点 reader/owner 已读回；原恢复目录保留 | 不重做已完成交付。主机 Longhorn 参数尚未加载，见第 10 项 |
| 3 | 非空且有效的 nonce 原生来源、原 Secret 只读挂载及最终 Pod 绑定 | 原生 nonce issue 已成功；两容器只读挂载、真实 UID/字节和新 Pod 已验收，最终 request 尚未生成，故原生 bind 未执行 | 交付 `system-backup-original-nonce-material`，用原 enrollment 首次 issue；按原作者输出的 volume/mount 安装，再读回两容器 UID、可读性及摘要；最终 request 生成后执行原生 bind。未知 issue 只 resume 同 intent |
| 4 | 所有会改变 Pod 的基础挂载必须先就绪，不能继续给即将替换的 Pod 签短期材料 | metadata 与 nonce 均已加载；当前 Pod `7de91180…`，其原生 relay 已签发并通过严格 TLS 1.3、服务名及 SQL 读回 | 安装 nonce 前按原进程身份停止只读 relay；rollout 后用真实新 Pod 重建 relay，并更新 controller 相关来源。后续 enabled 切换仍走既有独立接管流程 |
| 5 | 原管理员、enrollment、runtime issuer 与导出 key 必须同源，不能重复创建或搬出六种 signer | 原 issuer query 已通过；Core 的 `execution-keys` 已有原签名 export 与两把 key | 复用原 export，后续 Forward 由原生 owner 重新验证；不重新 export、不输出 key 内容 |
| 6 | Vault 签发必须保留 CA、服务名、集群、JWT 信任及三用途独立约束 | 宿主机到 Vault Service TLS 超时；固定真实 master broker 的 CRI/Pod/网络命名空间后严格 TLS 1.3 成功 | 采用已验证的执行网络位置，保留文件 custody 和全部原生认证；不修改网络策略，不把 issuer 私钥复制到业务 Pod。短期材料在依赖就绪后签发 |
| 7 | 原生来源事实必须覆盖全部实例、卷、资源和批准的六个 Secret；前后复核必须一致 | 当前 8 实例作者与 facts 成功，三卷材料已生成；MinIO 区域变更后的明确后继、三卷材料及完整 facts 已成功，来源到北京时间 17:25:15 有效 | 基础 Pod 身份改变后必须走明确后继；不冒用旧 Pod/facts，不重签已有效的 API token。批准的六 Secret 范围不扩张 |
| 8 | disabled config 必须有全部 9 registry 和 20 reference；空引用、歧义引用均拒绝 | 本轮八类实际 registry DATA 已集中核对并固定 pin：parts/source_writers/redis_sources/secret_allowlist/failure_domains/RBAC/strong-auth/provider-proof；后三项保留候选性质，不代表已验证用户 MFA；disaster_identity_mapping 及二十类引用尚未齐全 | 从原生产者输出组装：registry 为 parts、redis_sources、failure_domains、disaster_identity_mapping、source_writers、rbac_bindings、secret_allowlist、strong_auth_issuers、provider_proof_issuers；reference 为 artifact 三操作/upload issuer/CA，evidence store/三操作/CA/KEK，backup KEK，三用途 signing，catalog 三操作，nonce，status relay |
| 9 | request、Forward、publication、source V2 与 capture consumer 必须绑定同一 config/Core/最终 controller；DATA 文件本身不是授权 | 本轮尚无 request、signing material、publication 或 capture consumer | 复用 `issue-signing-material`、`author-disabled-config`、`prepare-initial-request`、原 initial Forward/publication/provider 与 `issue-v2`；每次保留 intent、原生回执和实际输出 pin；未知结果先 query，不重 issue |
| 10 | 原主机 Longhorn 作者要求有效签名 V2 source 和独立 capture consumer；准备好的 hold JSON 不是安装证明 | `longhorn-hold-materials.json` 原生生成成功，SHA `2bd69edb…`；节点服务仍未加载参数 | 第 9 项通过后生成真实 host bundles，whole/shared 指向已交付新 ELF；经原安装脚本加载，读回 unit 参数、文件摘要、实际 PID 和 TLS。不得手写“已安装”或直接跳过 tenant 校验 |
| 11 | writer selection 必须经原 source-config 作者接入 host definition 和 keeper image | 当前后继 selection 仍缺两字段 | 用现有 `original_longhorn_host_definition` / `original_longhorn_keeper_image` 输入重新 author；保留实际租户 namespace UID、Pod→RS→Deployment、SSAR 与全量 census 校验 |
| 12 | C1 需要真实 S3、专用 evidence、六操作、status relay、catalog/KEK/CA/nonce 生产物；短期材料不能提前消耗或伪造 | 所需五个补充工具、镜像内既有 MinIO 三工具和固定 mc 均已核对；现场 MinIO 区域为空的真实拒绝已通过单字段配置修正，新 Pod 原生探测 exit0；尚无本轮 C1 成功生产物 | 先完成长期 DATA 与工具准备，再集中执行原作者。S3 最长 10 分钟、C1 evidence 最长 480 秒等原限制保留；失效不改时间字段，不把旧凭据当新授权 |
| 13 | 原安装接管必须实际覆盖三卷及全部 writer，发生中途失败时先释放存储再恢复业务 | 尚未进行本轮现场停写/冻结 | 原 C1/first-adoption 同进程执行完整采集与异常恢复；保留真实 durable journal。RWO/RWX 全部范围、旧进程退出、恢复顺序及最终运行均须现场证明 |
| 14 | disabled 初始化与原安装历史/分类/映射必须真实登记，不能直接写 SQL 或把部分证明当接管完成 | relay 实际读回 config_rows=0、owner_head_rows=0；初始化尚未执行 | 通过原 first-adoption/disabled initialization 入口取得已提交、源恢复的查询回执；只读核对实际 config/head/登记记录 |
| 15 | 首次启用走现有 config mutation 的强认证、完整 owner 复核及实际运行状态检查 | `ConfigMutationAuthority.StrongAuth` 为真实必需调用；当前未登记 TOTP、登记服务未完整部署 | 只补本次已有登记服务的配置与入口；需要时由用户在本地页面登记/确认。密码、种子、验证码不发聊天；不制造 MFA 证明。create 当前不单独强制 MFA，不能据此跳过 enable 的检查 |
| 16 | enabled Forward/publication/provider 与正常 controller 接管不能沿用只读 relay 的身份或证明 | 当前 controller disabled，只读 relay 的 `task_mutations_enabled=false` | 复用既有 enabled 独立授权、原生 relay handover 和实际 runtime 检查；验收当前进程确已接单，不仅查看配置 enabled 字段 |
| 17 | 正式页面、当前管理员会话、入口权限、可用容量和生产 runtime 均须实际通过 | 尚未从页面创建本轮正式任务；页面入口及当前会话尚待验证 | 仅在真实拒绝出现时按本次首单处理；不扩建通用认证。容量使用实际 staging/DB/目标存储观测，不用空报告或声明值 |
| 18 | 同一正式任务必须采集→业务恢复→上传→独立读回→catalog 登记成功；采集证明不能冒充读回证明 | 尚未执行 | 留存同一 task-id、产物身份/摘要、独立物理读取和登记回执，核对业务恢复。成功前不得标记闭环完成 |
| 19 | 范围审计和临时资源清理要受真实任务及恢复证据约束 | 团队只读 Pod 仍保留；本轮没有新增测试产物 | 真实 task-id、source-disabled/恢复证据满足后使用既有 retirement 脚本；保留审计回执，清理 D 盘构建缓存及本次临时资源，不在 C 盘生成构建临时产物 |

第 3 项挂载已完成，原生 bind 仍待真实 request；第 4 项新 Pod relay 已通过 TLS/SQL 读回，补充工具和新 Pod 完整来源事实均已验收；MinIO 区域实际配置已加载并通过原生探测，变更后的来源事实也已重读。眼前处理完整引用与配置生产物。第 8—19 项仍含未完成或未现场验证的环节，不称前一项为“唯一剩余阻塞”。新开发仅接受能指出本次首单具体拒绝点、不能复用的原因及结束检查的修改。

MinIO 的区域配置使用原生 `MINIO_SITE_REGION`，对应 [固定 September 版本常量](https://github.com/minio/minio/blob/RELEASE.2025-09-07T16-13-09Z/internal/config/constants.go)；同版 [admin info 作者](https://github.com/minio/minio/blob/RELEASE.2025-09-07T16-13-09Z/cmd/admin-handlers.go) 从 `globalSite.Region()` 返回区域。本次以现场实际响应、CAS 配置加载和原生探测回执为验收依据，没有放宽区域校验。

2026-11-16 运行授权前置重现旧 RSA PEM 差异：同一公钥 DER SHA `849773cc…`，原 API 导出 451 字节（含尾换行），Vault 返回 450 字节。旧对话 `01a1cee2…` 的提交 `16ea941d` 已在安装依赖入口实现 RSA 身份比较；本次复用同一实现至运行权限、C1 evidence 与最初 signing JWT 检查。三包针对性回归已通过；新补丁尚未部署，不据此宣称授权或备份成功。不同密钥、重复密钥、issuer、算法、默认角色变化仍拒绝，JWKS 与非 RS256 分支保持原检查。

2026-11-16 15:15 接续：最新现场以 handoff 的 `latest_current_site_state_20261116_1515` 为准。23cbf0b0 / 镜像 f7d0cf75 已实际加载，8 ELF、原 nonce 两容器可读、metadata 挂载、当前 Pod relay TLS/SQL、新来源、三卷材料及完整 facts 已通过；来源窗口延至 18:02。3-1 已完成：5 项 Vault 策略/角色实际读回，metadata-only 凭据已签发。2-1/2-2/2-3 与 3-2/3-3/3-4 仍待完成。用户授权新聊天 01a1e334-b03a-7b41-94d1-4d840e2edadf 并行准备现有强认证登记服务/页面入口，主线继续配置与存储接线；新聊天禁止竞争 SSH 队列、增加 Deployment 或 rollout 当前来源。没有正式页面任务。

2026-11-16 15:49 签名材料实际首调用 exit1（14.27s），三用途 JWT 已写、五项策略实际存在，但最终 signed material 未写。复核同一 JWT 的实际 Vault batch 登录成功，TTL10、固定用途及 Pod/SA/namespace 全匹配，`identity_policies` 空时被 Vault 省略；三处原始探测和签名 observer 的必填字段检查因此拒绝。补丁只允许该空可选字段，保留强类型解码、非空身份策略拒绝及原有 token/用途/签名检查；两处签名读取器同时复用旧 RSA 身份比较来接收已证明的 PEM 尾换行差异。两包定向回归已通过，最终源码复跑和发布尚未完成，不把代码修复当现场授权成功。

2026-11-16 16:53：ca68 全8包已现场核验，镜像8191f41b已构建（尚未替换当前disabled f7d Pod）；新签名原生成功。C1 S3 首次调用在MC预读拒绝、未进入IAM或桶写：其子进程省略PATH/MC_CONFIG_DIR导致getent找不到，还传入固定mc不支持的--certs-dir。已在同一现场、同一原root和CA下，用现有native-install的环境及参数实际跑通mc版本、用户和策略三项只读检查；只修正并更新独立C1S3工具。失败输出保留，配置/请求尚未生成，不称2-1或3-2完成。
