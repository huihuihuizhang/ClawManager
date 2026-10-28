# 用户与实例备份控制器

本目录提供控制器安装模板，以及使用合成数据的本机 Docker 备份实验脚本。控制器模板尚未应用到 K8s；本机实验会新建独立 MySQL，不连接参考服务器或执行真实业务迁移。
入口为 `backend/cmd/backup-controller`，功能任务仅支持 `backup`、`preflight`、`drill`；目标必须是独立的 `cm_drill_*` 库和 `cm-drill-*` 命名空间，恢复后实例保持停止。

## 本机 OpenClaw Lite/Pro 备份实验

在仓库根目录的 PowerShell 执行：

```powershell
& ./examples/backup-controller/run-local-lab.ps1
```

前提是本机 Docker Desktop Linux 引擎已运行、Go 1.26.1 及项目依赖已缓存，且脚本固定的三个本地镜像 ID 存在。脚本始终指定 `desktop-linux` 并核验本机命名管道，所有容器使用 `--pull never`，不使用 kubeconfig、远程 Docker、镜像仓库或已有数据库。镜像不存在时退出，不能将失败当成测试通过。当前缓存 Lite/Pro 的 OpenClaw 都报告 `2026.7.1-2 (0790d9f)`；Lite 镜像标签含 `2026.9.30`，不能用标签日期代替实际程序版本。

脚本创建唯一的 `cm-backup-lab-run-*` 容器、内部网络及 MySQL 卷；无宿主端口发布。临时材料存放在 Git 忽略的 `.codex-temp/backup-lab/run-*`。自动生成专用账号、bcrypt 哈希、数据库 TLS、加密和签名密钥，不需要生产凭据。每次运行使用全新目录和卷，已有产物不会覆盖。容器在结束或失败时停止，文件、命名卷和内部网络保留供排查，不自动删除。

执行路径：

1. 创建 admin、普通用户和两类 Linux OpenClaw 实例的合成数据；五张 InnoDB 表包含配额、停止状态及禁用的任务配置。
2. 使用真实 Lite/Pro 镜像执行 baseline，在无网络容器中启动 Gateway、检查健康并停止；每类加入合成 Skill、会话、任务及模型凭据文件。此处直接执行 OpenClaw CLI，未经过镜像 `/init` 或 Runtime Agent API。
3. 冻结专用 MySQL 为 `super_read_only`，用仅 SELECT、必须 TLS 的账号调用生产 `worker.RunDatabase`；只读挂载实例目录并调用 `worker.Run`，生成压缩加密分片，再由 `artifact.Directory.Publish` 签名发布。
4. 比对采集前后数据库和源文件 HMAC，停止 MySQL；另一无网络容器仅挂载发布包、验证材料和新输出目录，解密核对全部行、两种登录密码哈希和归档文件。篡改测试只改独立副本，必须拒绝认证，原备份包只读保留。

`environment.json` 记录镜像、实际版本、Gateway 健康检查和停止结果；`result.json` 记录数据量、数据库/文件一致性和篡改拒绝结果；`artifacts/` 是签名加密包；`verification/` 为隔离解包结果（含故意损坏的负例副本）。凭据、源码 SQL 和解包结果均是本次合成数据，但也不要作为可复用生产配置提交。`-SkipOpenClawStart` 可省略 Gateway 启停，此时环境报告明确标为未验证，不能用来验收启停。

这是调用真实采集/加密/发布模块的数据链路集成，**不是控制器 HTTP/UI → K8s Job → 快照 → 源状态恢复的完整验收**。五张最小合成表不代表完整 ClawManager schema 已验收；会话/Skill/任务文件核对不等于恢复后 Agent 业务行为验证；没有执行目标业务库导入、目标 admin 替换或模型渠道调用。Windows bind mount 也不能用于证明 Linux UID/GID、POSIX 权限或 CSI/NFS 行为。

### 继续完整流程所需资料与环境

| 项目 | 所需信息或实现 | 当前可自行准备的部分 |
| --- | --- | --- |
| 专用 K8s | 专用测试集群的位置/访问方式，或新建测试集群的部署位置；支持 NetworkPolicy 的 CNI、Linux 节点及 CRI 接口 | 独立 namespace、控制库、RBAC、Worker/控制器镜像和测试证书可按现有模板生成；不复用未知旧 context |
| Runtime Agent | 对应 Lite/Pro 的 Runtime Agent 源码或镜像版本，备份 capabilities、generation fence、进程树停止、幂等重建接口支持情况 | 已有客户端和严格校验；当前实际运行的是 OpenClaw Gateway，不能代替 Runtime Agent 证明 |
| Writer 停止证明 | 所有应用/外部 writer 的范围与归属、门禁和远端副作用停止服务的实现/协议 | 已有 `WriterProofURL` 客户端；不能用固定返回成功的 mock 放行控制器 |
| 存储矩阵 | 测试 StorageClass、CSI snapshot class；HostPath 节点/路径；NFS 测试 export 与外部写入排除方式 | staging/evidence 跨 namespace 同后端 RWX 卷、独立 artifact 卷按实际身份绑定 |
| 应用与配置版本 | 待验收 ClawManager 分支/版本（默认可用当前仓库）、Lite/Pro 最终镜像及配置 schema、全部持久目录/Secret 引用 | 当前仓库的表结构和本次 baseline 可作为起点；无需提供真实用户数据或生产密码 |
| 可选业务验证 | 若验证恢复后模型/渠道可用，提供仅测试用途的服务与账号 | 当前使用假凭据验证字节保留和加密，不发外部请求 |

以上同时包含环境、资料和仍需实现的外部服务；不是填几个地址就能完成的纯配置工作。完整 K8s 联调前必须逐项具备真实能力。WorkBuddy、Windows 和其他四域不在本轮 Lite/Pro 数据链路实验范围内。

## 本机 WorkBuddy Lite 复杂目录实验

在仓库根目录执行 `& ./examples/backup-controller/run-workbuddy-lab.ps1`。固定使用本地缓存镜像 `sha256:e2eff0ff74b146b126cc88f05f0ee7f863c40041de2849d6c304bd40fe0ce496`（标签 `2026.10.14-startup-r2`，内部 WorkBuddy **5.3.14**、Electron 37.10.3）与前述 MySQL 镜像，不拉取镜像。脚本创建专用 Linux source/restore/mysql 命名卷；临时材料仍在 `.codex-temp/backup-lab/`，无网络的应用/验证容器不挂载宿主用户 HOME，不使用 privileged、Docker socket 或宿主 PID namespace。Wine 布局探针额外使用最多 2 GiB 的临时内存文件系统及 3 GiB 容器内存上限，退出后自动释放。

以下是首轮（Wine 专用适配前）的基线结果。脚本中的通用格式负例仍必须拒绝 Wine；专用适配的完整往返使用下节新脚本。**测试退出 0 不代表完整 WorkBuddy 迁移可用**：

| 测试 | 2026-10-26 结果 |
| --- | --- |
| 两个原生 daemon/web bridge | UID/GID 12001、12002，各自 HOME；健康检查通过、正常退出 0。直接运行镜像内 bridge，不经 Runtime Agent/bwrap/tun |
| 用户及实例数据 | 专用 MySQL 5 张表、9 行、2 用户、2 个 WorkBuddy Lite 实例；TLS 只读采集、签名加密与离线认证通过 |
| 复杂目录 | 1,081 个文件/链接：原生隐藏目录、配置和数据库，加合成中文路径、空文件、只读/可执行文件、相对链接、两组各 500 个小文件、任务/Skill/假凭据文件；逐项内容核对通过 |
| Linux 权限 | source/restore 都用 Linux 命名卷；UID/GID、权限位、目录及链接目标逐项一致，源和恢复目录的跨 UID 读取均被拒绝 |
| SQLite | 4 个原生数据库（各实例 workbuddy.db、edge-sync-mapping-v2.db）quick_check 通过；两个专用合成数据库保留非空 WAL，恢复读取 600 条已提交记录 |
| Wine 文档组件持久目录 | **真实初始化后归档被拒绝，完整备份受阻**：dosdevices/c: 和 z: 带冒号，z: 为指向 `/` 的绝对链接，触发现有安全策略 |

结果目录 `workbuddy-20261026-014646-4350bf08`，backup ID `lab-737c38475bda7ad6`；`environment.json` 为镜像及启动记录，`result.json` 为数据链路结果，`workbuddy-result.json` 为 Linux 元数据/SQLite 检查，`workbuddy-wine-result.json` 明确记录 `full_workbuddy_backup_ready=false`。Wine 探针使用独立新建 prefix，确认进程退出后调用同一生产 workspace.Archive；没有将不支持的条目静默排除。Wine 是此 Linux WorkBuddy 文档 SDK 的内部依赖，这项发现不代表扩展到了 Windows Agent 测试。

本次五张 MySQL 表为合成数据，不包含猜测的 `workbuddy_linux_identities`；WorkBuddy 身份表迁移依旧未通过。300 条/实例的会话、任务和模型/渠道假凭据在 `.backup-lab-fixtures/` 内，只验证字节保留，不伪称供应商原生会话、OAuth/MCP 或任务语义已验收。原生 SQLite 为真实 daemon 自动初始化的数据库，没有向未知厂商表猜字段插数据。文档健康信息中 `docsPreviewReady=false`，未验证文档编辑、登录、外部连接器和恢复后业务启动。

下一步开发/资料：

- Wine/Linux 特殊目录的专用适配已在下节补齐；首轮负例报告保留为历史证据，不覆盖新结果。
- 取得对应源分支的 WorkBuddy 身份表结构及 storage identity/UID/GID 生命周期合同，完成真实身份适配。当前文件级保留 UID/GID 不等于平台身份迁移。
- 提供目标镜像的配置/凭据/会话/任务格式与仅测试用途的业务样本后，验证原生功能；Runtime Agent 和 K8s/存储依赖继续按上一节接入，不请求生产账号或真实用户数据。

## WorkBuddy Lite Wine 专用适配与往返测试

生产 Worker 已接入 `WorkspaceLayout: "workbuddy-lite-wine.v1"`。在对应 `RuntimePolicies` 发布策略中显式配置这个字段，同时保留该版本精确的 `Image` digest、`Runtime` 和完整 `Files` 规则。该布局只接受 WorkBuddy/Linux/Lite，Pro、Windows、其他 Agent、未知布局及可变镜像标签拒绝；没有配置时继续使用原通用格式。空字段不改变旧策略 JSON/摘要，新字段通过既有发布策略哈希进入冻结任务和签名合同，恢复端必须使用一致策略。

本版本要求归档根是**单个实例的 HOME**，固定识别 `.local/share/workbuddy-editor-sdk-wine`，不能把共享池根或仅 `.workbuddy` 子目录当成整个实例。无 prefix 的新实例仍可备份；已有 prefix 要求真实目录、`drive_c`、`dosdevices` 和三个注册表文件完整。归档包含整个 HOME，不排除 Wine 的 DLL、注册表、文档或缓存。

- 唯一盘符例外为 `dosdevices/c:` → `../drive_c` 和 `dosdevices/z:` → `/`，原样记录链接而不遍历。额外盘符、不同链接目标、盘符下的伪造成员、替换祖先目录和其他绝对链接均拒绝。
- 只对这个布局保存 `user.DOSATTRIB`，用专用 PAX 记录传输原始属性字节（非空、最多 4096 字节）。目录和普通文件可以带该属性，符号链接不接受。未知扩展属性、ACL、capability、未知 PAX key 仍拒绝，不静默丢弃；目标文件系统不支持时恢复失败并保留隔离状态。
- 恢复先完整认证密文，再向空隔离根写文件和受限元数据；Z 映射最后建立，随后只修正已核验的真实父目录时间戳。没有沿 Z 映射执行文件写入；后续受 `os.Root` 限制的读写不能越出归档根。Z 的运行时含义是**之后运行 Wine 的容器根**，不是主机挂载授权。实例保持停止，不将隔离目录直接作为公开文件服务。

运行完整 Linux 数据卷实验：

```powershell
& ./examples/backup-controller/run-workbuddy-wine-lab.ps1
```

该脚本固定缓存 WorkBuddy 5.3.14 镜像及其 manifest digest，创建独立 source/target Linux 命名卷。原生 WorkBuddy daemon 在同一 HOME 初始化配置/SQLite 后停止；Wine 建立真实 prefix 和测试注册表键、中文文件及无宏 DOCX。生产 `worker.Run` 流式压缩加密全部内容，实验回执/策略用 Ed25519 签名；另一个无网络且不挂载源卷的容器恢复。内容、链接、UID/GID、mode、非链接 mtime 和 xattr 逐项核对。SQLite 验证从只读恢复卷复制 DB/WAL/SHM 到临时目录，再以 query_only 执行 quick_check：有效 WAL 备份可能需要 SQLite 重建 SHM，不能要求只读卷上的原件完成此操作。最后只在恢复的测试 prefix 启动 Wine CLI，读取源注册表键、C 盘文档和 Z 盘映射，然后结束 Wine 进程；不会启动恢复后的用户 Agent。

采集/恢复容器仅保留与现有 Worker 相同的 CHOWN/FOWNER/DAC_OVERRIDE capabilities，无 privileged、宿主目录或 Docker socket。实验布局策略的 JSON 规则只针对合成 marker，**不能把它当成真实 WorkBuddy 凭据、任务和配置的完整发布策略**。此处的签名实验回执是 Worker 集成测试材料，不是六域 catalog/acceptance 灾备点。

结果见运行目录中的 `environment.json`、`workbuddy-wine-result.json`、`wine-metadata-result.json`、`wine-runtime-result.json`，密文在 `wine-staging/`。服务器身份表迁移、完整 Runtime Agent 生命周期、文档 SDK 原生编辑功能和 Linux/K8s 存储验收仍分别为未验证；基础 Wine 读文件/注册表通过不能替代这些验收。

2026-10-26 最新共存实验为 `wine-20261026-022546-20c35e5f`（backup ID `lab-070a29f097f29614`）：1,987 个目录/文件/链接条目，原始文件内容 1,270,263,771 字节，密文 451,860,314 字节。全部内容、权限、时间戳、DOS 属性、2 个原生 SQLite 数据库、恢复后的 Wine 读注册表/文档检查通过。采集/恢复已成功后，为支持 SQLite SHM 重建修正校验脚本，在保留的隔离恢复卷上继续执行校验和 Wine 读取，未重放真实迁移。源、目标均为新建 Linux 命名卷，测试结束没有运行 Agent 或 Wine 进程。

## Agent 与环境验收覆盖

范围注册表目前声明 7 类、12 种 Linux 类型/模式组合。每个实际发布版本至少要做对应镜像的数据往返、停止/恢复源状态和隔离恢复检查；目录/格式或运行时不同的组合不能由另一类 Agent 代替。通用加密、SQL、路径安全可以共用回归，存储与权限能力要按底层驱动另行覆盖。

| 类型/模式 | 当前实际镜像测试情况 |
| --- | --- |
| OpenClaw Lite / Pro | 2026.7.1-2：原生初始化和网关健康、完整 HOME 加密往返、混合 SQL 演练通过 |
| WorkBuddy Lite | 5.3.14：daemon、SQLite、UID 权限及文件往返通过；Wine 共存往返见上文；已观察身份版本的 SQL 恢复通过，见下文 UID 专用适配 |
| WorkBuddy Pro | 5.3.14：Xvfb 中实际桌面初始化、正常退出后文件往返、14 个原生 SQLite 检查通过；没有套用 Lite Wine 策略；身份表仍阻断 SQL 恢复 |
| Hermes Lite / Pro | 分别 v0.21.0 / v0.16.0：原生配置/SessionDB、网关、加密往返及恢复后原生会话读回通过 |
| OpenCode Lite / Pro | 1.18.13：同一 digest，分别使用 Lite/Pro 启动器；本地 HTTP 创建会话、完整往返及恢复后查询同一会话通过 |
| DeepSeek Harness Lite / Pro | 0.1.0-rc.6：专用依赖链接布局、网关、文件往返及恢复后启动通过；测试启动器需要显式 Node 参数，镜像默认启动脚本尚需修正 |
| Codex Pro、Claude Code Pro | 用户明确要求本轮不测试；不计入通过数量 |

Windows Agent 不在本轮支持范围。本机宿主是 Windows，但本实验实例数据、备份恢复、xattr 和 Wine 在 Docker Desktop 的 Linux 内核与 Linux 命名卷中运行。它能验证 POSIX 内容和权限，**不能代替隔离 Linux/K8s 服务器验收**：服务器内核/容器运行时、Runtime Agent、节点证明、NetworkPolicy、CSI/快照、NFS/HostPath、UID/GID 及 ACL/xattr 支持必须实测。此次已发现本机 tmpfs 不支持所需 user xattr，扩展属性测试改在支持它的 Linux 命名卷中执行；不同存储必须分别确认能力。参考服务器仍保持只读，真实验收需另有独立测试环境。

### 运行实际镜像矩阵与多用户演练

在仓库根目录用 PowerShell 7 执行：

```powershell
./examples/backup-controller/run-agent-matrix-lab.ps1
# 只重跑指定失败组合；仍创建全新目录与卷，不复用已有源 HOME：
./examples/backup-controller/run-agent-matrix-lab.ps1 -Cases 'deepseek-harness-lite','deepseek-harness-pro'

# 可传入多个上述报告目录，按传入顺序选取各组合最新的 passed 记录：
./examples/backup-controller/run-mixed-agent-lab.ps1 -MatrixRoots @(
  'D:/path/to/ClawManager/.codex-temp/backup-lab/matrix-<run-id>'
)
```

矩阵脚本只访问本机 `desktop-linux`、使用脚本内固定的缓存 image ID 和 `--pull never`，逐个新建源/目标 Linux 卷。每个初始化容器 `--network none`，退出并确认写进程消失后，源卷只读采集；恢复容器只得到密文、签名元数据和临时测试密钥。文件核验先只读完成，再按类型进行独立的原生会话读回/网关启动检查。全部测试进程最终退出，不发布主机端口。每个版本和 repo digest 保存在 `case.json`/报告，脚本副本和 runner SHA256 从后期运行开始固定记录。历史失败目录保留，不覆盖成成功。

本轮最终 10 组合证据汇总位于 `.codex-temp/backup-lab/mixed-20261026-030941-3509ab6f/agent-matrix-summary.json`：8,261 个文件/目录/链接条目、23 个原生 SQLite 数据库，以及 3,000 条合成 WAL 消息。原生会话语义只对 Hermes 和 OpenCode 做了应用接口读回；其他类型的历史、Skill、任务和假凭据补充用例明确位于 `.backup-lab-fixtures`，不宣称它们覆盖所有厂商内部格式。WorkBuddy Pro 通过的是桌面初始化和数据检查，不是登录后业务、文档编辑或恢复后桌面交互验收。DeepSeek 的恢复后网关检查是在保留的目标卷上单独补跑，没有重写原始文件核验结果。

混合演练 `mixed-20261026-030941-3509ab6f` / `lab-40e20db883ff8dc6` 使用 admin、两个活动用户、一个禁用用户及 **OpenClaw/Hermes/OpenCode/DeepSeek Lite/Pro 共 8 实例**。它执行真正 `CaptureSource`、Database/Workspace Worker、签名加密发布、`RestoreDrill` 和独立 `VerifyDrill`；源库关闭后才启动另一新卷上的目标 MySQL，目标只有合成 bootstrap admin。SQL 恢复后锁定并撤销写账号权限，SELECT-only 账号验证所有规范化行；只读 Linux 验证器检查 3,371 个文件/链接的 HMAC、7 个原生 SQLite、2,400 条 WAL 消息和 8 个实例的跨 UID 读取拒绝。源 admin 密码哈希替换目标、禁用用户状态、19 位小数配额、用户归属关系均保留；任务定义保留但停用，实例/desired state 停止，旧平台 access/bootstrap token 与 Pod 句柄清除。模型/渠道的**合成文件凭据**验证加密后字节保留，并未调用真实服务。

WorkBuddy 没有被悄悄从全量导入中丢弃：上述 SQL 演练一开始就明确限定非 WorkBuddy 8 实例，另用包含 WorkBuddy 的负例确认缺身份 schema 时在写入前拒绝、bootstrap admin 原样保留；非空目标重复恢复也拒绝。WorkBuddy 两种模式的文件往返通过；后续新增的 Linux Lite 身份恢复实验见下文，Pro 身份仍未放行。

### 本轮修复和剩余资料

- **备份代码修复**：新增 `deepseek-harness-node-modules.v1`，只对 DeepSeek/Linux 和固定 digest 策略显式启用。允许 `.dsh/profiles/node_modules` 下 npm 包名到镜像内固定目录的精确链接映射，以及镜像实际存在的 3 个特殊映射；不跟随链接、不读取外部依赖内容，不允许任意绝对路径。通用布局仍拒绝；错目标、目录替换、路径穿越及链接下伪造文件的 Linux 测试通过。
- **测试启动修复**：OpenClaw 探测携带同一假令牌；Hermes Lite 配置本地 Origin/代理边界；DeepSeek 使用关闭端口的假模型路由和 `--no-open`。缓存 rc.6 启动器缺少 `node --expose-internals`，且该参数不能放进 `NODE_OPTIONS`；测试直接显式传参，生产镜像启动脚本须由其发布源补齐，不能将此报告当作默认启动器验收。
- **停止边界**：WorkBuddy Pro 通过仅容器 loopback 可达的 Electron main inspector 调用 `app.quit()`；Lite 的脱离进程组 sidecar 由私有 PID namespace 内、仅同测试 UID 的 SIGTERM 收尾，并确认无存活写进程。它们是测试停止方式，不能替代 Runtime Agent/cgroup 的生产停机证明。
- **WorkBuddy 身份资料更新（2026-10-26）**：已取得真实 DDL、GID=UID 启动校验和 schema=1 marker，现已完成对应 Linux Lite 版本的专用导入和隔离测试。无需重复提供 DDL；仍需源分支分配器/删除/旧版兼容代码或合同，以核验实际平台后续创建/删除行为。无需真实用户行或密码。

### WorkBuddy Lite UID 专用适配与隔离恢复

`Config.WorkBuddy` 使用 [workbuddy-uid-contract.v1.json](workbuddy-uid-contract.v1.json) 的完整内容（由 `domain.WorkBuddyUIDSchema()` 生成）。版本为 `workbuddy-linux-uid.v1`，固定身份表与 allocator 的元数据摘要，包括 `linux_uid` 唯一索引。不能改摘要绕过未知结构；不要填写并不存在的 GID/storage identity 列。

这个版本只接收已核对的 Linux Lite、GID=UID、空 `workbuddy_storage_identity`。全部历史身份占用和 created_at 原样保留，即使实例或旧用户已删除；live 实例的用户归属必须正确。next_uid 要大于全部已保留 UID，保留原高水位及间隙；65534 仅保留为耗尽边界。目标仅允许空表或初始 `(id=1,next_uid=10000)`，且其他表仍满足空白平台条件。替换初始种子与 admin/用户/实例恢复在同一事务完成，不允许在有业务数据的目标重放。

实例卷必须以包含 `.workbuddy-identity.json` 和 `home/` 的**单实例根**登记，不能登记共享池根或只登记 HOME。发布策略可用 `WorkspaceLayout: "workbuddy-lite-instance-wine.v1"`，该版本在 `home/` 内保留固定 Wine 盘符及 DOS 属性；旧 `workbuddy-lite-wine.v1` 只适合 HOME 根，不能混用。配置字段路径相应以 `home/` 开头。控制器冻结 SQL 身份并在发布时与认证数据库分片比较；恢复从认证分片推导身份，Worker 核验 marker 与实际 HOME UID/GID，一致性失败保持隔离。目标不会自动启动 Agent。

复现已完成的本机实验（只接受当前工作区内已通过的合成矩阵报告）：

```powershell
& ./examples/backup-controller/run-mixed-agent-lab.ps1 `
  -Suite workbuddy-identity `
  -MatrixRoots @("$PWD/.codex-temp/backup-lab/matrix-20261026-030309-e7cf97bc")
```

新机器需先使用 `run-agent-matrix-lab.ps1` 生成自己的 WorkBuddy Lite 合成 baseline，并将 `MatrixRoots` 换成该报告目录。脚本固定本机 Docker Desktop Linux 和缓存镜像、禁止拉取镜像；新建内部网络、MySQL 数据卷和文件卷，无宿主端口映射。旧 baseline 只读克隆，所有身份、账号及消息为合成值。源库冻结并停止后才创建目标库；恢复账号锁定/撤权后，独立 SELECT-only 账号核对全部行。结果保留，不删除已有卷或修改参考服务器。

成功记录：`workbuddy-identity-20261026-063224-df31201d`，backup ID `lab-0f0eeb84a600370f`。4 用户、2 实例、4 身份记录（含2条历史占用）、next_uid=23000；90 个文件/链接、182 条元数据、4 个原生 SQLite、600 条合成 WAL 消息核对通过。admin 替换、分配器回退拒绝、证据失败回滚、历史 UID 冲突、目标重复导入拒绝和跨用户文件隔离通过。报告见该目录的 `mixed-restore-result.json`、`mixed-verify-result.json`、`mixed-linux-result.json`。本轮 Wine 为实例根组合测试 fixture；此前完整真实 Wine prefix 实验另见上文。

通过的是固定身份版本的数据恢复，仍不代表完整 K8s 控制器/暂停快照流程、全业务配置语义或生产迁移验收。完整范围及剩余资料见[开发记录第 24 节](../../docs/users-instances-backup-development-plan.zh-CN.md#24-workbuddy-lite-身份历史占用与-uid-分配器恢复2026-10-26)。其他结构、非空 storage identity 和 WorkBuddy Pro 身份仍需对应合同与独立测试。
- **请补资料 2**：独立 Linux/K8s 测试环境的受限访问方式，ClawManager/Runtime Agent 发布 digest，拟验收的 StorageClass/VolumeSnapshotClass、CSI 驱动、NFS/HostPath 路径与 UID/GID、root-squash、ACL/xattr 能力。参考服务器 `172.16.0.158` 继续只读。
- **请补资料 3**：各发布版本完整持久化挂载清单、原生会话/Skill/定时任务/渠道配置布局、Secret/ref 和密钥服务对接约定，以及可在隔离环境创建的最小业务样本。当前 HOME 和假标记策略不能证明所有外部挂载或真实密钥迁移；不要提供生产凭据。
- **请补资料 4**：DeepSeek 修正后的启动镜像，或镜像构建源码位置；若目标 Hermes 版本与本轮 Lite v0.21.0 / Pro v0.16.0 不同，需明确对应发布 digest 再做该版本验收。

以上均未连接参考服务器、使用真实业务数据或执行真实迁移；K8s 控制器、快照、Runtime Agent 生命周期、完整生产发布策略的验收标记仍为 false。

## 离线构建与配置检查

在 backend 目录用已有 Go 工具链编译 `./cmd/backup-controller`、`./cmd/backup-worker`、`./cmd/backup-node-proof`。Linux 静态产物的构建形式为 `CGO_ENABLED=0 GOOS=linux go build -trimpath -o bin/backup-controller ./cmd/backup-controller`。对应 Dockerfile 使用本地二进制，不下载依赖。

`backup-controller --config /config/controller.json --check-config` 只检查 JSON 结构、路径和 profile 选择，不连接数据库/K8s，不读取全部依赖或报告环境已就绪。不加该参数才启动服务，且仅允许 Linux。

`controller.example.json` 的地址全部是文档示例，不能直接部署。填入实际隔离环境地址、证书、存储 UID 和镜像 digest。配置中可以含敏感重启参数，按 `controller.yaml` 使用 Secret 挂载，不使用普通 ConfigMap。命令行、日志及管理 DTO 不包含凭据。

## 配置与安装依赖

- `ControlDatabase` 的文件格式复用 `control.DatabaseConfig`：`database` 为 `worker.DatabaseSpec`，`credential_file` 是独立绝对路径。控制库名必须以 `cm_backup_control_` 开头。账号文件包含 `username` 和 base64 编码的 `password`。源只读/源账号管理/目标账号管理分别使用独立文件。MySQL 必须启用校验服务身份的 TLS。
- 手工在独立控制库安装 `control/schema.sql`。已安装旧版 schema 的环境使用 `upgrade-restart-result.sql` 增加恢复回执列，不能对新 schema 重复执行。程序不执行建表或升级。源端与控制库必须在同一个 MySQL server UUID 上，才能在同一事务中更新 generation、恢复 dispatch 和实例 binding。控制库账号需获源库 `instances`、`instance_runtime_bindings` 的相关读取/更新权限，以及 `runtime_pods` 读取权限；业务表必须为 InnoDB。
- 临时账号管理连接需要按实现授予 SELECT、账户创建/锁定/删除、会话检查/终止及精确表权限的授权能力。恢复临时账号只写隔离目标库。账号删除与既有会话清理都成功后才允许源恢复。不要把账号管理凭据发给 Worker。
- `KeysFile` 结构为 `VaultVersion`、`Vault`、`Wrapping`、`Signers`、`Verify`。后四者是版本/ID 到 base64 原始密钥的映射：Vault/Wrapping 各 32 字节，Ed25519 私钥 64 字节，公钥 32 字节。示例不提供可复用密钥。保留旧任务引用的解密密钥、签名验证公钥和历史 profile。
- Relay 证书必须匹配 `ControlURL` 的 IP SAN，Worker 证书由独立 issuer 签发为 clientAuth。`ControlURL` 和数据库地址使用明确 IP/端口，以生成精确 Worker 出站规则。CNI 对 Service DNAT 与 NetworkPolicy 的处理仍须在隔离集群实测。
- 节点证明使用本目录 `node-proof.pod.yaml`，`NodeEndpoints` 的节点名和服务器 SPIFFE 必须逐一对应。控制器使用自己的 clientAuth 身份访问它。仅有 Pod/Job 消失不能替代节点上原容器进程已退出的证明。
- 各源命名空间和隔离命名空间预建无 API 权限的 `backup-worker` ServiceAccount，关闭 token 自动挂载。控制器使用 `controller.yaml` 的 RBAC；它需要枚举全局 Pod/PV 和源工作负载，不能只看到部分实例。
- 控制器运行在 `cm-backup`，不能运行在隔离目标命名空间。通过 Downward API 注入 `POD_NAME/POD_NAMESPACE/POD_UID`。控制器会核对自身 `controller` 容器的实际卷挂载。
- 控制器与所有 Worker 的 staging 必须通过 RWX PVC 指向同一 NFS export/path 或 CSI driver/volumeHandle；evidence 使用另一共享卷。跨命名空间 PVC 名相同不代表数据相同，配置要填各自真实 UID。根目录必须预先存在且可写，不能设置 subPath。artifact 根独立持久化。Worker 密文输出 root 所有、0400，控制器因此也用 UID 0，但不授予 privileged、宿主目录或额外 capabilities。
- 目标隔离策略见 `quarantine.yaml`，`backup-quarantine` 必须永久保留并由支持 NetworkPolicy 的 CNI 执行。目标只允许本任务账本对应的 Worker Job；禁止应用 Pod/Deployment/ReplicaSet/StatefulSet/DaemonSet/CronJob。目标库需提前安装兼容的业务 schema，只有 bootstrap admin，恢复策略会用源 admin 密码和资料替换。

## 具体实例映射

`Instances` 必须完整覆盖源 SQL 清单，不能只列准备迁移的部分。每项含 `ID`、`Namespace`、`PodName`、`WorkloadKind`（`Gateway`/`Pod`/`Deployment`/`Stopped`）、`VolumeName`、`Workspace`。Deployment 另填 `WorkloadName`；停止实例填 `StoppedVolume`（Kubernetes Volume 结构）、`SubPath` 和需要的 `Node`。路径从实际 volumeMount/subPath 解析；未覆盖的其他持久卷、外部共享 writer 和 HPA 会拒绝执行。

CSI 可填写 `SnapshotClass`，要求 class 的 deletionPolicy 为 Delete，并冻结 class UID/driver 与 PVC/PV 身份。在所有源 writer 暂停后才创建快照、等待 Ready，核对 SnapshotContent 的原卷 handle 和快照 UID，再创建克隆 PVC 并导出密文。HostPath/NFS/PVC 可直接归档。延迟绑定卷先创建没有数据授权的等待 Job，待真实绑定固定后才发放密钥和数据库凭据。

Lite 另填 `Endpoint` 和完整 `Restart`（复用 `RuntimeAgentCreateGatewayRequest`，包括用户 UID/GID、端口、agent_type、workspace、资源与环境参数）。重启资料进入加密计划。运行时 generation 由控制器在事务中预留，调用失败后不重新分配 generation；原 runtime Pod 与 used_slots 必须仍匹配。恢复成功后更新 binding，不重复释放/占用槽位。Pro 同样回写实际恢复后的 Pod 绑定。

每个实例必须用 `Policy` 引用 `RuntimePolicies` 中的发布版本。策略包含 `Version`、固定 sha256 digest 的 `Image`、`Runtime`（type/mode/backend/variant/os）以及 `Files`。每个文件声明 Path/Format/Required/Fields，Fields 的 Path 是 JSON pointer 分段数组，Action 为 preserve/stub/disable/disable-string。采集前读取源文件验证字段覆盖但不修改源文件，整个 workspace 仍完整加密归档；恢复时按同一策略处理文件。旧 `Instances[].Files` 只允许为空或与发布策略完全相同，避免静默忽略冲突规则。`Configs` 提供数据库 JSON 列的完整字段规则。当前测试使用合成配置，实际 Agent 镜像版本的规则仍需根据对应版本资料配置和验证。

`Mode` 为空同时提供备份与隔离恢复；`backup` 只提供备份；`target` 只提供恢复/preflight，可省略源账号文件且不会打开源数据库。target 的 `Instances` 使用备份包里的实例 ID，并引用与源包签名摘要一致的版本策略；只读取签名密文包，不向源平台查询。仍保留 Source 的原数据库身份字段用于阻止误用目标。

## 业务资产与跨域适配

`Assets` 显式列出源端业务 Secret、ConfigMap 和 Skill 对象。Secret 必须为 Opaque，登记 Namespace/Name/UID/ResourceVersion/Role/Keys，Role 仅支持 model/channel/enterprise-auth/runtime-config，Keys 必须覆盖完整 Data。不得登记数据库管理账号、Worker 身份、签名密钥等基础设施凭据。ConfigMap 登记相同资源身份，并为每个 Data/BinaryData key 填写 Rules（Format/Fields）。源 Agent Pod 的 env、envFrom 和卷引用必须都在清单中；新增 key、资源替换或版本变化会拒绝采集。

Skill 对象填 Key/VersionID/SHA256/Size。Profile 的 `Objects` 填 HTTPS Endpoint、Bucket、Region、CA、Credentials，Credentials 文件为 AccessKey/SecretKey/SessionToken。使用最小只读对象账号；读取指定版本，并核对数据库中的 archive_hash/size_bytes 和实际字节。所有业务资产直接进入加密 staging，不写明文临时文件；当前总原始内容上限 32 MiB，不能用此内存实现承诺任意大小的对象库。

隔离恢复创建独立 assets PVC，恢复 Skill 对象及 `objects-index.json`，Secret 输出不可用的演练值，ConfigMap 按规则禁用触发和替换凭据；独立只读 verifier Job 重新解密源包并逐字节核对目标。该输出是便携的隔离恢复文件，不会创建可用的业务 Kubernetes Secret，也不会回填目标 MinIO 服务；源凭据原文仍在密文包中。生产凭据重新绑定和启动属于后续实际迁移流程，当前入口不支持。

`llm_models`、chat_sessions/chat_messages、Skill 元数据和绑定已进入与用户/实例相同的只读一致性事务，恢复时模型停用、调用引用清空、会话内容保留、Skill 安装状态归零。Team 定义、事件、工作流和模板也进入密文归档；其非空表需 owner 提供 `Dependencies[table]` 的 SchemaSHA256 和逐列 Columns 动作（preserve/null/stub/fixed:值），未适配的表拒绝恢复。摘要来自 `domain.SchemaDigest` 的 Table 元数据，不是手写 SQL 文本摘要。JSON 执行内容仍需 Configs，不能用逐列 preserve 绕过；引用完整性在写入前核验。未知 user/instance/runtime/WorkBuddy/Team/Skill/chat 表默认阻断，避免默默丢数据。Team Redis 和共享工作区不是本资产对象清单的自动覆盖范围。

`WorkBuddy` 保留原严格接口：Version、SHA256、Instance、StorageIdentity、UID、GID，适用于分支明确提供独立 storage/GID 列的合同。该旧模式不重放 allocator。新 `Layout: "workbuddy-linux-uid.v1"` 使用上述固定合同及 `AllocatorSHA256`，专门处理已观察的 Linux Lite 结构；二者不能混用。未知结构继续拒绝，不能推测列名、重新分配 UID 或用“旧版本”跳过。

## 应用副本和遗留写入许可

每个应用进程在业务数据库初始化前登记 namespace/Pod UID/node UID/CRI container ID/image ID，获取写入许可时绑定该进程。应用需注入 `POD_NAMESPACE/POD_NAME/POD_UID/BACKUP_APP_CONTAINER`，见 `application-identity.patch.yaml`，并具有读取自身 Pod 和 Node 的权限。老控制库显式执行 `control/upgrade-app-processes.sql`；新 schema 已含字段/表，不重复执行升级。程序不自动执行 SQL。

`Applications` 列出全部应用 Deployment 的 Namespace/Name/UID/Container/Image。discovery 核对实际副本数、Deployment→ReplicaSet→Pod 所有者链和已登记进程身份；当前限单容器应用，不支持额外 init/sidecar/ephemeral container。采集期间滚动更新或容器重启会使覆盖证明失效。注册和写入许可与维护门禁同事务互锁，门禁关闭后不能启动新写入者。

`WriterProofURL` 配合 `WriterCA/WriterToken` 接受 HTTPS JSON 证明。请求字段见 `profile.WriterProofRequest`：Version=writer-coverage.v1，随机 Nonce、Task、Mode、Database、ServerUUID、InventorySHA256、RequiredUntil；resolve/resolve-legacy 另附 Process 和 Permits。响应必须回显 Version/Nonce、返回整个请求的 `kube.ContentHash` 作为 RequestSHA256，并具有 Complete/GateEnforced=true 和覆盖 RequiredUntil 的 ValidUntil。resolve 还要求 RemoteEffectsStopped=true；resolve-legacy 另要求 LegacyIdentityConfirmed=true。摘要算法为 Go encoding/json 序列化上述结构后 SHA256，互操作方必须保持字段顺序/省略规则，不能自行以另一种 JSON 规范化算法替代。

该服务必须真实证明所有应用/外部数据库、对象库及远端副作用写入者已受门禁约束；仓库提供客户端和严格校验，不提供无条件成功的证明服务。没有真实证明时不能执行。NFS 仍额外要求存储方排除外部挂载写入。

许可 resolver 仅处理原进程身份：先核对原 Node UID、取得正面的 CRI 停止证明，再证明远端 SQL/请求/子 Job 等副作用结束；重新检查任务租约后，在一个事务内撤销进程、写审计、删除其精确许可。提交响应丢失后只读回查。旧版未绑定进程的 token 可通过 `LegacyPermits[token]` 提供原进程线索，但必须由外部服务独立确认 token 归属，配置本身不算证明。未知 token、缺失 CRI 记录、Pod 404、TTL 到期或部分证明都不能触发删除。

## 产物兼容边界

签名包使用 `users-instances-contribution.v2` 合同：数据库策略摘要、逐实例运行时策略摘要、ai_gateway/skill_hub/teams/resources 依赖声明以及 assets 部件。旧 v1 仅保留读取兼容，目标必须精确匹配当前合同。`artifact.Directory.Scan` 提供独立于源平台的有界分页目录，每个条目重新校验提交标记、签名及全部密文；未提交对象不展示，已提交对象损坏会报错。

这仍是 `users-instances-functional.v1alpha1` 的领域贡献包。另有 `recovery` 包提供六域 `system-backup.v1` 签名、注册/删除事件、retention 和 finalizer 核心；目录任务与六域功能发布 owner 接口已接入控制器。领域贡献声明本身不代表其他领域数据已完整恢复，也不能自动升级为 acceptance。

## 独立目录与 owner 模块

[catalog.example.json](catalog.example.json) 是独立目录控制器结构模板。使用绝对配置路径执行 `backup-controller --config <绝对路径> --check-config` 仅检查结构，不读凭据文件或打开连接。所有 `.invalid` 地址、占位 SHA、ID 和挂载路径都必须按隔离测试环境提供真实值；模板不能直接运行。

独立模式只有 Catalogs，没有 Profiles；仍需单独控制数据库和 Vault 密钥（KeysFile 中 VaultVersion/Vault），无需源数据库、K8s、node-proof 或 Worker relay。目录 profile 可与普通 profile 共存，但 ID 必须唯一。扫描模式为 inventory_manifest/provider_snapshot；known_record_only 仅提供已知记录导入。Artifacts 清空可配置纯扫描 profile。

Trust 文件是 recovery.Trust 数组，包含 ID/Version/Purpose/Public/Compromised；Public 是 base64 Ed25519 公钥。Trust、Codec、WrappingKeys 文件 hash 按**原文件字节**计算。WrappingKeys 为 key-version 到 base64 32 字节 KEK 的对象，Reference 必须等于 Bootstrap.kek。Codec 格式必须明确，内置仅支持 cmstg01-adapter.v1；内容见生成 schema 的 CodecDescriptor。Bootstrap 和精确 Locator 与注册记录完全匹配后才会装载预配置 reader；服务地址不从备份内容读取。

Gateway 端点是 owner 提供的 mTLS `/recovery/v1` 服务，不是直接填写 S3 endpoint。只读目录配置禁止 AllowAppend；原生能力、协议表和失败行为见 [recovery/README.md](../../backend/internal/systembackup/recovery/README.md)。扫描完成后可在任务“结果”中分页浏览目录、查看记录详情、填入导入校验表单并下载脱敏报告；历史结果不授权实际恢复。

同事的模块通过 `host.RunWithAdapters` 注册 `SixDomain`、`SharedWorkspace`、`CatalogCodecs` 工厂。分别由 profile.Config.SixDomainModule、SharedWorkspaceModule 和 codec Format 选择；模块引用固定 ID/version/SHA，配置变化产生新 revision。默认二进制没有猜测的 owner 模块，缺失时保持未就绪。共享卷 owner 须先提供真正恢复完的隔离卷回执；宿主核验资源身份，不替代卷内容恢复服务。

完整六域功能发布新增控制表 system_backup_recovery_publications；已有控制库使用 upgrade-catalog.sql 中的幂等 CREATE TABLE，初装 schema.sql 已包含。仅提供 SQL 源码，本轮没有执行安装或部署。

## 离线诊断与资料模板

```text
backup-controller --config <绝对配置路径> --diagnose
backup-controller --materials-template
```

diagnose 只读取给定配置文件，拒绝重复 key/未知字段，输出固定错误码、配置项位置、实例策略覆盖数量和所需资料类别。不会读取配置引用的数据库账号、证书、私钥、codec 或 KEK 文件，也不会连接任何服务。材料模板无需 config 参数，提供 Agent 版本/文件、WorkBuddy 表、Redis 拓扑、卷布局、存储原生能力、owner 合同及隔离环境清单；不要求生产数据或明文密钥。

structure_valid=true 只表示配置结构通过；runtime_verified 固定为 false。字段规则是否覆盖真正的镜像、实际副本/卷/存储能力和目标隔离仍需后续验证。无效配置返回非零退出码并在标准输出保留脱敏诊断；诊断不会回显地址、路径值、未知字段值或凭据。`--diagnose`、`--check-config`、`--materials-template` 互斥。

## 恢复账本和清理适配接入

Redis owner 将 `control.RedisJournal{Store: driver.Store, Task: task}` 传给 RedisRestorer；读取密文和实际 Redis 命令仍使用各自独立身份。所有清单在第一项写入前冻结；未知写不得直接手动改为 prepared，须通过 Reconcile 的正面比较和 writer 停止证明。

远端六域恢复 owner 先登记认证过的 artifact，再用 `control.ProtectedCollector` 包装读取它的每个恢复 collector，并显式配置 TTL 和 LeaseStopVerifier。清理 owner 使用相同 RecoveryGuards 的 FreezePrune/ClaimPrune/ExecutePrune，提供真实 PruneProvider；不注册 provider 就不能删除。任务成功/失败/取消终态都会阻止遗留未决 Redis 写、未释放消费者和已认领的清理任务。

已有隔离控制库需要显式安装 `control/upgrade-recovery-operations.sql`；初装 schema 已同步。这些脚本本轮未执行，未启动真实清理或迁移。

## Runtime Agent 与 NFS 能力接口

Runtime Agent 实现在本仓库外。控制器已实现 TLS 认证能力探测与 Lite 调用接线，但部署的 Runtime Agent 镜像需要提供 `POST /v1/backup/capabilities`。使用 `X-ClawManager-Control-Token`，请求 JSON 为 `Version: gateway-backup.v1`、`PodUID`、随机 `Nonce`；响应原样回显这三项，同时 `GenerationFence`、`ProcessTreeStop`、`IdempotentCreate`、`UIDIsolation` 为 true。字段表示实际保证：按 generation 隔离、停止整个 Gateway 进程树、幂等创建、租户 UID 隔离。404、旧 Pod 身份或不完整响应均在暂停前拒绝。

NFS 无法单凭 Kubernetes Pod 枚举排除外部机器写入。配置 `ExclusiveNFSProofURL` 及 StorageCA/StorageToken，接存储方受认证的只读证明端点。请求 `Version: nfs-writer-fence.v1`、`VolumeSHA256`、`Nonce`、`RequiredUntil`；响应回显前三项，并提供 `ExternalWritersFenced: true`、覆盖 RequiredUntil 的 `ValidUntil`。RequiredUntil 为当前时刻后两小时，覆盖最大任务时限。该接口应证明存储端已经排除外部写入，不是无条件返回成功的占位服务；没有该证明时 NFS 不可执行。该环境依赖属于此前第 4 项的外部 writer 覆盖工作。

## 清理与验证范围

中断/取消先撤销数据授权与临时 SQL 账号，再清理精确 UID 的 Job，获得进程终止证据后恢复源 writer。只在从未观察进程、从未发出密钥、授权已撤销且 Job 已持久化删除时，允许没有节点进程身份的 Worker 清理完成。已发过密钥的任务不走这一例外。

随后清理临时身份 Secret、请求 ConfigMap、Worker NetworkPolicy、源快照和克隆 PVC。目标恢复 PVC、已写入的隔离数据库、加密证据与产物保留供核对，禁止自动清空目标或启动 Agent；重新演练需要新的空目标配置。

本批测试是 SQL 驱动替身、Kubernetes fake、localhost TLS 和本机临时目录；模板未部署。真实 Linux/MySQL/K8s/CSI/HostPath/NFS 的隔离验收仍是独立工作，不等于已经完成真实迁移。

## 六域验收配置与 provider 服务端

backup profile 可增加 `AcceptancePolicy: {"id":"...","version":"...","sha256":"..."}`，要求已有 SixDomainModule。owner 必须实现 `profile.SixDomainAcceptanceOwner`，通过 ProbeAcceptance 检查策略、三个独立 signer、原生存储能力与独立验证器依赖；VerifyAcceptance 只读验证冻结 SixDomainPlan 的完整实际证据。缺少真实证据不能返回成功。普通 owner 不会自动取得 acceptance 准入。

API 创建 acceptance 任务需传 `kind: "backup"`、`purpose: "acceptance"`、固定 profile，以及 profiles 响应中的 `acceptance_policy`。策略不匹配或 profile 过期时拒绝；页面默认仍为功能备份，配置显式提供策略后才显示验收选项。完整计划及授权被冻结到已有加密控制记录；发布阶段核验授权、签名用途/密钥、全部前序确认及 cleanup 证据。验收不合格只保存负面验收记录，不注册；结果页面单独显示资格和注册状态。

provider 服务端示例为 [provider-gateway.example.json](provider-gateway.example.json)。仅做结构检查可运行：

```text
backup-provider-gateway --config /absolute/path/provider-gateway.json --check-config
```

该命令只读示例本身，不读引用的凭据/证书/后端配置、不连接 SQL 或对象存储。示例所有 hash/证书指纹均为占位，不能直接部署。正常运行需要在自有 Go 入口调用 `host.RunProviderGateway(ctx, config, factories)` 注册 NativeGatewayBackend；默认命令未注册厂商实现，会在任何凭据读取、连接或监听前拒绝启动。

网关逐叶证书 SHA-256 授权六个固定操作，服务端验证 mTLS；Identity/Location 固定，不能由请求指定其他根目录。BackendConfig 按文件实际字节 hash 固定，BackendModule 固定版本/hash，factory 必须核验所支持的模块版本并复制其需长期保留的配置字节。原生适配器还须检查所有固定 snapshot 字段及游标绑定；不能把请求里的声明当作 provider 证明。只读网关设置 AllowAppend=false、ControlDatabase 留空，并移除 conditional_create 权限。

开启 append 时在独立 cm_backup_control_ 数据库手工安装 `backend/internal/systembackup/control/upgrade-provider-gateway.sql`，网关全部副本共享该账本；程序只检查表存在，不安装。账本必须保留原未决写，不能用清表来重试。Create 必须真正具备存储端原生 key/hash/length/deadline 绑定，普通 S3 PUT 及客户端时钟检查不满足要求。请求重复或提交响应不明时仅 Observe，网关不提供删除或迁移接口。

尚需提供：存储端原生授权/强 absent/固定 inventory 的协议和隔离测试端点、backend 精确身份及权限策略、六域真实 verifier/目标故障域/KEK 恢复证据与版本化策略。无需提供生产明文密钥。详细开发契约见 [recovery/README.md](../../backend/internal/systembackup/recovery/README.md)。本轮没有启动真实服务或安装 SQL。
