# 页面完整备份优先：审核记录（2026-11-02）

本轮基线 `backup@171ad17c`。用户要求新建 A、D、公共 C 三个对话，由本对话统一审核并提交远程 `backup`；第一优先级是页面点击完成同一任务的正确备份。

## 本轮通过的切片

- D：真实页面单次点击采证入口，保留原幂等键，核对原 task/installation、详情头和递增版本；公开成品就绪仍返回待独立证据，不宣称完整验收。首提交 `0e082158` 已推送并核对远程 SHA。
- A：Permit Stage/Recheck 固定标签分段计时，默认关闭，不缓存授权或延长原窗口。native context 接线作为可检查的独立 patch 随附；未应用时不得声称 native 日志已有分段。PowerShell 验证器对 native SKIP 或缺计时输出拒绝通过。
- 公共 C：实际上传入口复用原封存名推导，额外核对 task/attempt/config、Job UID/代数、invocation/binding 和候选内容。不含未消费的清理 helper，不宣称本地删除、acceptance/catalog 或成功终态已完成。

## 审核者独立验证

仓库根目录运行 `node e2e/backup-live-contract.test.mjs`：4/4 通过、0 skipped、退出 0。`node --check` 两个模块通过；点击入口 `--help` 退出 0，缺配置反例退出 1、receipt=null，未连接现场。默认 `node --test` 在沙箱因 spawn EPERM 未执行用例，已改用同进程执行。

`backend` 目录，Go 1.26.1、GOTOOLCHAIN=local、GOPROXY=off、GOSUMDB=off、GOMAXPROCS=2：

```text
go test -mod=readonly -p 2 ./internal/systembackupkekadapter ./internal/systembackupexecution -run 'TestProviderPermitTiming|TestPublicationLocal|TestPublicationNativeCleanup' -count=1 -timeout=180s
```

退出 0：kekadapter 2.292s，execution 6.025s。覆盖新增计时拒绝/并发快照及封存绑定篡改负例、原文件清理和 native cleanup 邻近回归；这是本机组件验证，不是真实 SQL、Runtime 或完整页面验收。owner 初次并行冷编译遇 C 盘不足；审核者统一使用 D 盘独占临时目录，测试后 finally 校验绝对目标并删除全部本轮缓存和临时产物，退出 0。A/C 各自先前的构建目录也已清理。

## 尚未关闭的关键路径

1. 原 30 秒授权窗口内完整数据库采集未有新 native 成功证据；诊断接口不是性能修复。
2. 生产 PublishReadiness/PublicCapability 仍 workspace/false，页面六域 acceptance 会受阻；不能先置 true。
3. 原本地封存清理 SQL 日记及完整 evidence、acceptance/catalog 正式签名和读回、唯一成功结算仍需接线。
4. 同任务非空 Teams/Skills 最终产物和全部源 writer 物理恢复尚无本轮实证。

用户确认最终前端 origin 为 `https://10.130.14.23:32643`，目标是 zhanghui08 环境、远测 shell 为 Bash。默认密钥认证被拒绝后，用户明确改为自己连接、自己测试，审核者提供命令；停止继续尝试 SSH。未建立远程会话、未上传或部署。已提供只读 namespace/deployment/pod 版本和工具/磁盘盘点命令，待用户回传。Bash 页面命令见 D 交接；隔离 SQL 组件命令见 C 交接，均须满足前提，不能将 SKIP 或公开投影误作完整备份成功。

用户随后回传：context 为 `kubernetes-admin@kubernetes`；namespace 为 `clawmanager-zhanghui08-system`，UID `337cfe30-2c17-4b8e-b32a-760778b8098e`；App 为 `backup-test-zh-fix18`，实际 digest `c16f07c25c6dc8362aa09b7a1e81f5d1204f2812ae542bbcb21a3946975c6c9d`。未找到备份 controller；用户明确新增内容从未部署，其他 namespace 也没有。主机找到 Bash/git/Python3/kubectl，未找到 Node/npm/Go，可用磁盘约 1.8TB。这是用户执行回传，非审核者独立现场测量。下一步先完成生产收尾和同版本 App/controller/Worker 部署材料，不能在旧镜像上验收当前源码。

D 的 Bash 交接已改为独占工具目录，仅要求真实 repo 和登录态两个路径，不触碰已有 node_modules；现场证书沿浏览器实际信任链。审核者对三个 Bash 代码块执行 `bash --noprofile --norc -n` 通过，未执行安装、登录或点击，语法检查临时目录已删除。

用户已有 `docs/deployment_cn.md` 修改及 `.worktrees/` 保留，不纳入本轮提交。

## 第二轮审核中的接点

A 已核对现有 `PublicationSignersForTask → PublicationSigningKey → PreparePublicationRecord → Stage → SignCommitted`，无需新建签名框架。精确 payload/当前授权/唯一发送边界见 `system-backup-a-publication-signing-consumer-20261102.md`；legacy recovery DTO 与公共 v12 不兼容，不能替代。该文档仅静态核对，不代表正式接受/目录已经发布。

D 已核对根 Dockerfile 的 `app` target 同时包含 App 和 v2 controller、`backup-worker` 独立输出；App 默认启动不会自动运行 v2 controller。`system-backup-d-release-package-20261102.md` 目前只准备同源 OCI 候选构建与真实安装材料接点，不是完整可启用清单。审核者对两段 Bash 执行 `bash -n` 通过，并原样提取其清理函数，用失败的假 Docker 命令验证：builder 删除失败仍删除本轮 context；原构建退出 7 保持 7；构建成功但清理失败返回 1。测试未连接 Docker 或远端，临时目录已清理。

C 新增的实际 SQL 本地清理 producer 正在审核和准备独占 SAN/TLS MySQL 回归，尚未批准提交。原 native context 分段计时接线也已在工作区应用，待本轮统一编译验证；不能复用首轮的回归结果证明新代码。

第二轮实际回归已执行：现有公共签名向量通过（security 2.209s）；C 原文件清理/native 清理组件及新代码编译通过。首次 SQL 用例缺少 buildinfo commit，在建库前拒绝；补入真实基线 commit 与 dirty 文件 SHA 后，独占 MySQL 8.4.13/TLS1.3 下完整174迁移和原任务实际执行，226.86s 用例失败于数据库原30秒key/context/source截止时间，128次key-check累计28.306s，没有进入发布/本地SQL清理。SQL读回4位writer均有恢复回执、两道门禁idle、任务failed且无claim、external_actions=0；不认定现场全部物理恢复。精确边界和源码pins见 `evidence/supervisor-original-window-review-20261102-r1.json`。A据此继续当前读优化；C正向SQL闭环仍未验收，不批准推送删除实现。

D 的 `system-backup-d-controller-candidate.py` 已独立检查并运行8项测试通过，包含显式/缺省Downward API v1兼容、错误挂载和私有字节变更拒绝、输出不覆盖及不回显材料内容；对应文档两段Bash语法通过。它只消费私有已审核模板和材料pins，输出零副本/forward关闭的离线候选，report明确授权/在线资源/完整验收均未验证，不执行apply或创建权限。该工具不替代仍缺的正式安装材料和现场激活验收。

## 当前授权读与原窗口复核

审核者从 `951f4c51` 导出独立源码快照，仅叠加 A 冻结四文件，复用本轮 D 盘缓存。`go test -mod=readonly -p 2 ./internal/systembackupkekadapter -count=1 -v -timeout=180s` 退出0，包耗时9.027s。新增 `TestHeldProviderPermitRowsCurrentMySQL` 在本轮独占、独立UUID pin的MySQL 8.4.13/TLS1.3上实际运行，14子例全部通过（0.58s）：原序读取与后续同事务批量当前读取对证据篡改、缺失、mapping撤销/合法续期行为一致；事务结束后不能复用。独立SQL读回确认该测试自建随机schema已删除。原始日志SHA256为 `a4348a943fe61c8e31e82ba99d7c86117ee1ceedc44d3139518c1aa69fe469ba`。此结果不证明原30秒采集链已成功；A/B/C组合仍须实际复测。

C 新增 late-seal/absence 检查已在另一个冻结快照独立回归，`TestPublicationCompleteCleanupRejectsIncompleteHandles|TestPublicationLocal.*|TestPublicationNativeCleanup.*` 全部通过，包耗时6.490s。Windows用例在持有外来cipher的真实独占字节锁时，执行本轮自有文件删除和最终absence检查并保留外来文件，证明absence扫描不读取外来cipher；不把Windows上无效的chmod当作读访问拒绝证明。此处仍是组件证据，不能代替尚未通过的C实际SQL清理正向链。

D 的独占Kubernetes MySQL诊断入口已独立静态审查，默认使用现场真实私库固定digest；长连接PF/Ready不继承普通25秒HTTP请求超时，仍保留自身有界等待。审核者运行10项本地mock全部通过，Bash入口及A三个关联Bash脚本语法检查通过。mock覆盖原测试失败码保留、精确owner/UID变化拒绝删除、原子UID删除前置条件、清理错误继续擦除本轮本地秘密及长短请求超时分离。该工具仅为新随机namespace中的独占fixture，未连接集群，未证明镜像内OpenSSL可用或真实SAN/TLS/页面成功。
