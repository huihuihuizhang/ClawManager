# 本次安装的离线候选与现场接续

现场脱敏快照已经收齐。本轮仅离线开发和联检，未连接远测，未签发真实材料、安装 Node、改动集群、启用接单或执行整单备份。候选不含密码、JWT、私钥、kubeconfig 或测试夹具。

最后一轮完整性检查和逐阶段命令见 [本次接续命令与依赖](system-backup-p2-continuation-commands-20261111.md)。旧大 operator 的最后发布方法仍依赖其原真实 C1/MinIO history/enable/handover 上下文，不能直接在本现场复制或从脱敏包补造；当前候选不是“一键整单已就绪”。

## 固定输入与代码范围

快照：`D:/dsh-work/p2-offline-inventory-20261111/p2-offline-inventory.redacted.tar.gz`，原始字节 SHA256：`dfaf71f6b78b0dc852578c57a052a7bbc5329d442db219062be48b131a52fcb1`。25 份 JSON，采集错误为 `[]`。远侧完整私有 API 输入继续保留在 `/root/sbk/p2-offline-inventory.a05hq8f_/private`；快照内的 pin 仅是原始文件定位，不是授权。

目标为 `clawmanager-sbk-validation-system` 和选定的租户 `clawmanager-sbk-validation-user-1`。控制器 `sbk-d4f51b83b57e-controller` UID 固定为 `e4e27f27-8f02-40ab-8c62-09f2ffa3fafa`。运行范围保留 SQL 全部 8 个实例，运行捕获选择 1、2、3、7、8，明确延期 4、5、6；不删除错误/停止实例，也不把数据库历史当作空库。

复用已有 Longhorn 作者和正式恢复实现，不新增 Task/hold/签名协议。补两个现场可复现缺口：

* App 的两个就绪 Pod 必须全部核对 workspace 挂载；共享 PVC 的采集节点使用实际 staging/controller 节点，RWO 必须同节点。
* 原生共享运行时接受显式空参与者集合 `[]`，缺失/null 仍拒绝。空集合必须伴随原生共享 Agent、Node 客户端与实际节点/部署配置；SQL 全量 EOF 比较及任务实际物理停写不变。不插入虚构参与者。

## 接续工具

`assemble-p2-installation-candidate.py` 提供四个离线 DATA 操作：

* `freeze`：校验精确快照，输出本次安装的连接引用、私有输入索引、执行顺序和未通过的现场事项。
* `assemble`：消费既有 complete-inputs 作者的 `original-initial-source-author-inputs.v1` DATA 与真实 SQL/MinIO/Redis/API/目的密钥/续签回执，装配原生初始作者定义。五条连接固定为 `control_sql,source_api,source_objects,source_redis,source_sql`。SQL 账号从原生 `operation.Accounts` 读取 `User@Host`，不从 DSN 猜 Host。所有 pin 按原始字节核验。
* `longhorn-handoff`：消费原生 `prepare-mount-materials` 回执，将新的 Deployment/Core、MaterialsTemplate、SourceSelection、LonghornHoldMaterials 作为同一后继集；核对旧 Core 除 `longhorn_hold` 外完全一致，后续选择不依赖目录时间。Node 定义接收同一 hold pin 和新 PKI。
* `controller-waiting-patch`：只生成带 UID/resourceVersion/原 spec 测试的 JSON Patch；替换等待中的可执行路径为 `/run/system-backup/bin/system-backup-v2-controller`，添加实际二进制摘要校验，保留原等待及 env 摘要校验。不发送 Patch，不写 ready，不修改启用环境。

`continue-p2-native-candidate.py` 默认只打印可审核命令；显式 `--execute-native` 才在 Linux 调用既有五类原生入口：observer PKI、initial-source 作者、mount 作者、source facts、host-materials。所有 owner 参数均来自真实私有 pin；只向 argv 传路径和摘要。发送前持久化 intent；结果未知保留输出并停止，不再次发送。某一步的绑定不受后来补齐其他步骤影响。native stdout 保留原始换行，绝不重序列化签名回执。`--check-node-tls` 单独检查真实 TLS1.3、客户端证书与服务端 SPIFFE URI，不声称已完成 native FD/freeze。

`prepare-p2-vault-owner.py` 默认只做离线命令审核。它只接受本次已登记 plan、已审阅持久化安装器以及真实不可变 Vault 镜像输入；禁止用 tag 代替 image digest。显式执行时复用原安装器的安装/接续/解封/冒烟/持久化检查，在实际命名空间发现 Vault 时必须接回原私有 owner 状态，不新建第二套。root/unseal 数据仍留在原 owner 私有目录。

`prepare-p2-configuration-data.py` 是完整 ConfigurationData 的独立入口：从保留的原生产物建立输入索引，复用原 Core/捕获模板逻辑生成 DATA，再交给五连接装配与实际 Go 初始作者；不调用旧 provider/Redis prepare/apply，不把旧入口的“生成后即发送”当作纯 DATA 导出。它拒绝脱敏 API 记录；原始 API 记录仍只是采集时数据，由后续原生作者现场重验。缺省功能测试 profile 保留已有 same-cluster-copy 风险声明，不做隔离还原/DR 认证。

`prepare-p2-metadata-read-access.py` 只生成独立 Longhorn 只读绑定、两个实际源 actor SA 的声明和 Namespace/SA UID 执行前 guards。没有 apply、exec、通配或写入权限；现有绑定保留。详细输入来源、成功标准和未知发送处理见上述命令清单。

## 运行时输入边界

脱敏快照没有凭据值、真实续签材料或 Vault 状态，不能直接生成可投产的配置。`ConfigurationData` 现在由独立准备入口消费真实具名产物产生，不能用本地测试夹具代替。本地装配不自行认证运行时 issuer envelope；原生 owner 仍负责签名和完整身份核验。未来现场上传后须令目录 0700、Python/私有 JSON 文件 0600、原生 ELF 0700，再校验包内原始 SHA。

装配输入版本 `p2-installation-assembly-inputs.v1`，必需 pin：`ConfigurationData,MinIO,Redis,SourceAPI,SQLOperation,ControlDSN,SourceDSN,DatabaseCA,RuntimeIssuers,SourceIssuerPublic,ObserverReceipt`。MinIO/Redis/API/RuntimeIssuers 的已通过引用已冻结在 `offline-candidate.json`。重新签发 token、PKI 或重新观察配置时必须保留旧文件，显式选择后继 pin；不得覆盖已冻结输入。

原生命令包版本 `p2-native-candidate-operations.v1`：`Owner` 包含 `Plan,IssuerPublic,Enrollment,Kubeconfig,InstallerDSN,DatabaseCA,AdminPassword`，均为 `{File,SHA256}`；`Tools` 按二进制名提供真实 ELF pin；`Steps` 按具体阶段提供定义 pin 和最终输出目录。

| 阶段 | Steps 必需字段 | 原生命令 |
|---|---|---|
| observer-issue | ObserverDefinition, OutputDirectory | system-backup-original-observer-pki |
| base-host-materials | BaseHostDefinition, OutputDirectory | system-backup-observer-deployment-materials --mode host-materials |
| initial-source | InitialDefinition, OutputDirectory | system-backup-first-install-materials author-initial-source-inputs |
| mount | SourceSelection, MountLayouts, OutputDirectory | system-backup-source-registries prepare-mount-materials |
| facts | SourceSelection, Handoff | system-backup-source-registries produce-facts |
| host-materials | HostDefinition, Handoff, OutputDirectory | system-backup-observer-deployment-materials --mode host-materials |

MountLayouts 必须选择真实实例目录，`AuthorLonghornHold=true`，Longhorn provider/snapshot/clone class 由既有原生作者读取验证。host-materials 必须在原生 source facts/V2 签发后补入实际 `LonghornSourceRegistry`（Registry、CaptureConsumer、CaptureConsumerPin）；不能仅凭本地 handoff 生成 Node 包。该引用只允许补入，不允许同时换掉后继 Core/PKI/hold。

## 恢复连接后的顺序与停止条件

1. 读回原安装身份、当前源范围、controller/worker/source SA UID、PVC/PV/Node；复核 API TokenReview 和期限。Longhorn provider 的原只读角色目前只有 CRD 读取，应给既有 sources SA 增加精确 namespace 内 pods/services 的独立只读绑定，不扩大到 exec、写入或通配权限，不覆盖旧绑定。
2. 确认真正已安装、未 sealed、TLS 与二进制版本匹配的 Vault。快照只证明 registry 存在 `clawmanager-backup-vault:2.2.1-2194d86d`，未证明有可用 Vault 或真实 owner 状态。按原安装器输入协议核验不可变镜像；原私有状态不明时停止，不能重新初始化。
3. 原 observer 已于 `2026-11-11T07:55:02Z` 到期。对同一安装/控制器 SA/Node 生成新 create-only 定义、输出目录，使用原生 owner 真正续签；沿用 P1 真实 CRI/二进制定义，先生成无 hold 的 base-host-materials、安装新证书并检查 mTLS，再运行需要原生读取的 mount 作者。不重跑已经通过的整套引导。
4. 真实配置 DATA 装配和原生 initial-source 作者通过后，调用既有 mount 作者；立即将可选的回执 Deployment 作为新 Core，更新后继 template/selection。旧 Core 不得进入 source facts、Forward、mapping、签名或 controller 材料。
5. 在同一后继上生产 source facts/V2 与 capture consumer。将实际 signed registry 引用、新 PKI、新 Longhorn hold 交给原生 host-materials；使用其精确 NodeBundles 与原 install.sh 安装，然后验证全部 Node mTLS。不能把握手通过当成任务实际 FD/freeze 成功。
6. 通过既有 enrolled/config native owner 形成真实 disabled 配置、15 份 composition 输入、9 类 registry/20 类引用和 controller 环境，不借用旧 cold-adoption 成功记录。真实 KEK/catalog/nonce/signing 来源缺失即停止。当前脚本不会为这些缺项生成替代记录。
7. 将本次实际 v2-controller ELF 原始字节放到现有 inputs PVC 的 `bin/system-backup-v2-controller`，先核验原始 SHA/执行权限/owner，再对同一控制器发送审核后的等待入口 Patch。禁止使用 legacy `system-backup-controller` stub。核对实际 Pod UID、二进制 SHA、挂载和启动入口；此阶段保持 disabled、不发布 env.ready。
8. 只有上述实际原生作者/配置消费均通过后，才能按既有流程发布完整环境与 ready 摘要、核验 controller 加载、启用既有 admission，并执行整单停写→备份→恢复→读回验收。任何未知发送保留原 Task/attempt/intent/恢复义务，先恢复源，不新建操作绕过失败。

任何 pin、UID、范围、节点/挂载、有效期或 signed registry 不符均停止。测试 fixture、快照、命令审核结果、本地 `BackupReady=false` DATA 都不能用于替代真实原生签发或整单验收。

## 本地验证

新增 9 项 Python 联检覆盖真实脱敏快照中的双 App、原等待 shell、五连接、SQL User@Host、过期 PKI、原始 CRLF 字节、Longhorn 后继和未知发送接续、实际 Go CLI 参数声明以及 Vault tag 拒绝。定向 Go 测试覆盖空集合/缺失集合区别、原生物理依赖不可省略和既有运行范围/RBAC/恢复边界。此前已经通过的 Longhorn 作者和正式恢复测试不重复大范围运行。

最后一轮另有 5 项具名产物到完整定义、精确权限、脱敏运行输入拒绝、缺省 profile、只读 OCI 元数据入口的联检；包含原租户命名空间读取、现场 Pro tagged spec 的实际已加载 digest 和错误仓库拒绝。原业务 release 的 3 项拒绝回归也纳入本轮相关检查。Go 源码未再改动，沿用上一候选的 5 个已构建 ELF，不重复构建。

测试/构建临时文件仅位于 D 盘，交付包保留，临时目录在交付校验后删除。验证证据见同目录 evidence JSON。Linux 可执行文件及源码按 Git 原始 blob 导出，不能用会改变 CRLF 的工作区复制或 archive 替代封装。
