# 原 MinIO owner 的权限源安装候选（2026-11-03）

本批是待 root 独立审核、测试的源码和操作说明。今晚没有现场操作、测试、构建、SQL/Git 修改。当前没有证据确认现场五个角色账号和 observer 已存在，也没有现场 release/image/TLS 兼容结论。不能以此声明普通发布已就绪或 C 已闭环。

## 必须先明确的六个账号来源

账号必须来自原安装 owner 独立提供并 pin 的私密材料，不来自任务请求、backup 产物、当前响应计算出的信任 pin，或 controller 自行创建的凭据。

|用途|原始材料字段|真实读取/核对|
|---|---|---|
|artifact_read|target 的 `read_credential_file/sha256`，`read_identity_hash/ref_version`|原 credential AccessKey 哈希；命名 user/policy；该凭据自己的 accountinfo + help GET|
|artifact_write|target 的 `write_credential_file/sha256`，`write_identity_hash/ref_version`|同上，独立账号|
|artifact_delete|target 的 `delete_credential_file/sha256`，`delete_identity_hash/ref_version`|同上，独立账号；仅 staging|
|catalog_read|独立 catalog 的 `read_credential_file/sha256`，`catalog_read_identity_hash/ref_version`|同上，独立账号|
|catalog_append|独立 catalog 的 `append_credential_file/sha256`，`catalog_append_identity_hash/ref_version`|同上，独立账号|
|observer|definition 的 `ObserverCredentialFile/SHA256`、`ObserverAccountSHA256`|真实 ServerInfo、六个 user/policy、两 bucket 配置；自己的 accountinfo + help GET|

六个 AccessKey 哈希必须两两不同；没有 session token；各自 credential 文件为原 owner 的绝对、干净、非链接路径，Linux 0600，JSON 字段为 `access_key,secret_key,session_token,not_before,until`。`session_token` 为空，时间为真实 RFC3339 窗口。密钥只留在私密文件；不贴到 chat、日志、仓库、命令行参数。不存在、disabled、派生凭据、LDAP、group、多个 policy、额外/未知权限均拒绝。`current/latest` 不是固定 RefVersion。

## 阶段一：只读清点与最小策略准备

08:30 后由 zhanghui08 在原 owner 主机执行。沿用原 context `kubernetes-admin@kubernetes` 和 namespace `clawmanager-zhanghui08-system`，namespace UID 必须仍为 `337cfe30-2c17-4b8e-b32a-760778b8098e`。先运行 root 的现有 R8 只读命令，取得真实 MinIO namespace/deployment/replicaset/pod/service/serviceaccount/node UID、container/imageID、TLS CA/SPKI、deploymentID、版本/commit。这里只支持单实例、HTTPS、原发行 `2025-04-22T22:12:26Z` / commit `0d7408fc9969caf07de6a8c3a84f9fbb10a6739e`；其他版本/分支原地拒绝，不能更改 image/restart 来凑 profile。

沿用原 MinIO 管理员已存在的私密 mc config/alias 和权限。`MC`、`MC_CONFIG`、`ORIGINAL_ALIAS` 必须是实际绝对路径/原 alias；独立核对二进制 SHA、release `RELEASE.2025-04-16T18-13-26Z`、alias URL、原 CA。不要添加 alias、禁用 TLS 或提升 controller/observer 权限。先按六个准确 AccessKey/PolicyName 做 `admin user info` / `admin policy info` 命名 GET（不需要枚举全部用户）。返回写入 owner 私密目录，错误响应不是“不存在”的证据；必须确认该版本明确的原生不存在错误。

```bash
"$MC" --airgap --config-dir "$MC_CONFIG" admin user info "$ORIGINAL_ALIAS" "$EXACT_ACCESS_KEY"
"$MC" --airgap --config-dir "$MC_CONFIG" admin policy info "$ORIGINAL_ALIAS" "$EXACT_POLICY_NAME"
```

若任一旧账号/策略较宽、映射不符或缺失，不能覆盖或追加权限。先列出缺失项，再由原 MinIO 管理员在原 endpoint 创建新 owner 命名、带随机唯一后缀的专用账号和新策略（例如 `zhanghui08-backup-<purpose>-<随机后缀>`）。使用该管理员原本已有的 user/policy 创建与映射权限；缺权限即停，不扩权。`mc admin user add` 和 `policy create` 底层并不保证 create-only，因此所有名字必须先确认不存在，并由 owner 独占该命名批次；有冲突即换新批次，不重用名字、不盲目重试。

新账号可以先在 owner 私密环境生成/保存凭据，填入**新的**目标材料草案；先不要改已有运行配置或原 ref。通过原配置 owner 的现有安装流程注册新的固定 credential ref、IdentityHash/RefVersion，并产出新的独立 target/catalog 材料。这里的 producer 不自行注册这些 ref、不替换活动 config。现有路径/身份必须满足原 publication target/catalog 验证器。若没有该原 owner 流程输入，不能伪造 ref 或填任意 SHA 来继续。

策略由新增离线 CLI `system-backup-minio-permission-owner policies` 从已 pin 的 definition、target/catalog 和六个私密 credential 文件生成（不连接 MinIO/SQL/Kubernetes）。输出为六个 `{Purpose,PolicyName,NormalizedPolicySHA256,Policy}`；将 `Policy` 保存为私密策略文件，将 SHA 由 owner 独立选入最终 definition，再重新 canonicalize/pin 最终 definition。规划草案中的 policy SHA 仅是声明，`policies` 不验证它与响应相同；`observe/produce` 必须实际匹配。不能把规划输出当现场成功记录。

```bash
"$OWNER_CLI" policies --definition-file "$DEFINITION" --definition-sha256 "$DEFINITION_SHA" > "$PRIVATE_POLICY_PLAN"
```

生成策略只有：artifact read 为 formal+staging 的 GetObject/GetObjectVersion；artifact write 为相同前缀 PutObject；artifact delete 为 staging 的 DeleteObject + DeleteObjectVersion；catalog read 为 catalog 前缀 GetObject/GetObjectVersion；catalog append 为该前缀 PutObject；observer 为 admin:GetUser/GetPolicy/ServerInfo（admin API 的 Resource 为 `*`）以及两个准确 bucket ARN 的 GetBucketPolicy/GetBucketVersioning。无 ConfigUpdate、List、group、额外 policy、Deny、Condition、policy variable、未列出的 action/resource。两个 bucket 必须不同；现有 catalog root 在 installation 前缀内，同 bucket 会被 artifact root 权限覆盖，v2 明确拒绝，不能据此更改旧 bucket。

新增删除权限是单独 v2 选择，不修改冻结 v1。候选版本 DeleteObjectHandler 首先检查 DeleteObjectAction，即便请求带 versionId；v1 只有 DeleteObjectVersion 不足。应用层仍必须使用现有 staging、permit 和准确 versionId 删除校验；此处不授予 formal/catalog 删除权限。

需要创建时，原管理员逐个执行，秘密通过交互提示输入；不在参数或 chat 中填写 secret。创建输出也留在私密终端。随后执行准确 policy create/attach；每次只操作本批新名字。任何错误停止，保留已创建资源清单供 owner 检查。

```bash
"$MC" --airgap --config-dir "$MC_CONFIG" admin user add "$ORIGINAL_ALIAS"
"$MC" --airgap --config-dir "$MC_CONFIG" admin policy create "$ORIGINAL_ALIAS" "$NEW_POLICY_NAME" "$EXACT_POLICY_FILE"
"$MC" --airgap --config-dir "$MC_CONFIG" admin policy attach "$ORIGINAL_ALIAS" "$NEW_POLICY_NAME" --user "$NEW_ACCESS_KEY"
```

本阶段可能的写操作必须单独列单：最多六个新 MinIO 账号、六个新命名策略和六个准确映射；新的私密 credential/target/catalog 材料及原 owner ref 注册；不能覆盖旧账号/策略、改 bucket policy/versioning、改旧 config、重启、升级 image 或为 observer 增加 ConfigUpdate。已有六个账号完全符合原映射时无需上述新建。

## 阶段二：真实原 enrolled operator 签发及安装

新增 CLI 不提供 enroll/generate-issuer、Passed、临时 root/伪造源注入入口。使用原 enrollment plan、公钥独立 SHA、enrollment pin、原 owner kubeconfig、原 installer TLS DSN/CA、本地 admin 密码私密文件。公钥须与原 enrollment 一致；签名私钥是原 owner 已有 raw Ed25519 64-byte 私密文件，不能是 controller 私钥、不能重新生成。保持在原 owner 主机，绝不能作为 startup 文件内容或挂载给 controller。

最终 definition 是 RFC8785/JCS canonical JSON，完整字段合同如下（PascalCase；未知/缺失/重复字段拒绝）：

- `Version = original-minio-permission-definition.v2`；`ConfigFile/ConfigSHA256` 为原完整 config 字节；`TargetFile/TargetSHA256` 为原 owner 新选择的完整 target 材料字节。
- `GrantName/HeadName` 为本批两个新且不同的 DNS ConfigMap 名称；不能指向已有对象。
- `Grant.Version = minio-permission-grant.v1`；`Installation/Namespace/NamespaceUID` 精确匹配原 enrollment target；`ConfigSHA256` 同原 config；`Profile = minio-2025-04-22-builtin-flat.v2`；`Epoch = 1`；`NotBefore/Until` 为 owner 实际选择、当前有效、最长 24h 且不越过现有 owner 账本窗口的时间。
- `Grant.Provider` 含 `Endpoint,Region,CAFile,CASHA256,SPKISHA256,DeploymentID`；`Deployment,ReplicaSet,Pod,Service,ServiceAccount` 各为 `{Name,UID}`；以及 `Container,ImageID,Node,NodeUID`。全部来自原安装当前 API/TLS/source，不由示例值替代。
- `Grant.Principals` 恰五项，Purpose 为上表五用途；每项包含 `IdentityHash,RefVersion,AccountSHA256,PolicyName,PolicySHA256`。前两项来自对应原固定 config/material ref；AccountSHA256 是实际 AccessKey 字节 SHA；PolicySHA256 为 **v2 规范化原策略** SHA。
- `ObserverCredentialFile/ObserverCredentialSHA256,ObserverAccountSHA256,ObserverPolicyName,ObserverPolicySHA256` 指向独立最小只读 observer。无 Engine 字段，无 disabled-plugin/Ready/Passed 声明。

v2 策略摘要：保留全部 JSON 字段；拒绝重复/尾随/未知字段；Action、Resource 作为集合排序，Statement 按 canonical 字节排序，之后完整验证闭合 action/resource profile 并 SHA256。这个规则处理官方 map 序列化顺序，绝不丢掉额外权限或 Conditions。命名 policy 和实际 own-accountinfo 都必须匹配同一个原 pin。

owner 私密 Linux shell 中准备公共参数数组（全部变量来自原已经选择并 pin 的路径；不是在此调用中计算新公钥信任）：

```bash
COMMON=(--definition-file "$DEFINITION" --definition-sha256 "$DEFINITION_SHA"
 --plan-file "$ORIGINAL_PLAN" --plan-sha256 "$ORIGINAL_PLAN_SHA"
 --issuer-public-file "$ORIGINAL_PUBLIC" --issuer-public-sha256 "$ORIGINAL_PUBLIC_SHA"
 --kubeconfig-file "$ORIGINAL_KUBECONFIG" --kubeconfig-sha256 "$ORIGINAL_KUBECONFIG_SHA"
 --dsn-file "$ORIGINAL_INSTALLER_DSN" --database-ca-file "$ORIGINAL_DATABASE_CA"
 --local-admin-password-file "$ORIGINAL_LOCAL_ADMIN_PASSWORD"
 --enrollment-pin-file "$ORIGINAL_ENROLLMENT_PIN" --enrollment-pin-sha256 "$ORIGINAL_ENROLLMENT_PIN_SHA")
"$OWNER_CLI" observe "${COMMON[@]}" > "$PRIVATE_OBSERVATION"
```

`observe` 真实认证 SQL local admin + kube subject/enrollment/当前原 owner head，然后做两个完整 named-source pass，夹住两次六账号 own-policy + 同 owner 谓词 help 拒绝；检查真实 release/commit、bucket 无 policy 且 versioning Enabled、完整 UID/EndpointSlice 和运行容器 stamp、时间及原文件。只返回当前来源摘要，不返回就绪许可。失败不能通过手写签名 JSON、修改夹具或给 observer 更大权限解决。此 initial-install observe 要求两个新名字仍不存在。

明确 review 后执行实际新建：先创建一个全新且 0700 的输出目录，不能放在 controller 工作目录；`produce` 会再做上述真实认证/观测后签发，并用 Kubernetes Create 新建两个 ConfigMap。不会 Apply/Update 已有资源。grant immutable，head 可由原 owner 的后续签名撤销流程维护。该 CLI 当前只支持首次 epoch=1 安装，不自动轮换/恢复/撤销；旧头存在时拒绝。

```bash
"$OWNER_CLI" produce "${COMMON[@]}" --issuer-private-file "$ORIGINAL_OWNER_PRIVATE" \
 --output-directory "$NEW_PRIVATE_OUTPUT_DIRECTORY" > "$PRIVATE_INSTALL_RECEIPT"
```

退出码 0 才表示 producer 完成其来源安装；1 拒绝，2 参数/预检问题，3 输出失败，4 为部分/未知 commit（含网络断线或后验变化）。4 时不得直接重跑或删资源：私密检查本批两个准确名称的 UID/record/signature/epoch，确认 grant/head 是否存在；禁止用新名字规避未解决的部分安装。producer 不自动清理 owner 资源。即使 exit 0，也不是 publication/acceptance/succeeded 结论。

## 交给 D 的生成字段及启动选择合同

`produce` 只生成 `NEW_PRIVATE_OUTPUT_DIRECTORY/minio-permission.source.json`。它是 canonical JSON，Linux 0600，仅含：`Version = minio-publication-effective-permission-source.v2`；`Installation,Namespace,NamespaceUID`；`Issuer`（原 enrolled 公钥的 base64 JSON bytes）；`MinimumEpoch=1`；`Grant/Head={Name,UID}`（真实 Create 后再次 GET 的 UID）；`GrantSHA256`；以及上述五个 Observer locator/pin/name 字段。没有私钥、密码、secret、Engine、Passed。

单独收据为 `Version=original-minio-permission-source-installed.v2`，`File,SHA256,DefinitionSHA256,GrantSHA256,HeadSHA256,GrantUID,HeadUID,Epoch`。D 必须从原 owner 的独立收据/审核输入接收 File+SHA，而非从任务载荷或 startup 文件自己计算后自信任。分发 observer credential 的真实私密字节及原 CA 到既定原绝对路径，重新核对原 SHA，不重新生成凭据。startup 文件可由原 owner 分发给 controller，但签名私钥永不分发。

新显式消费 API 是 `NewMinIOEffectivePublicationPermissionV2Reader(MinIOPublicationPermissionInput{File,SHA256})` 和 `DeploymentService.CheckPublicationDependenciesWithMinIOEffectiveV2(ctx,input)`。它重新读取独立启动 pin、签名 grant/current head、epoch/UID、现时 SQL/config/KEK/signing、真实 MinIO/Kubernetes 来源，不以 producer 收据代替现时检查。撤销、换 UID、窗口过期、额外权限和任一漂移均拒绝。C5/main-loop/D installer 冻结字节未接线；D 要做单独源码审核选择，不能仅换 schema 文本宣称上线。

## 独立审核与官方依据

root 负责所有测试、Linux 编译、SQL、远程、Git 及测试产物清理。候选测试根见 source manifest；局部 TLS/fake-Kubernetes/SQL-model 测试不证明真实 MinIO、原 MySQL 或现场兼容。真实非空六域全量、不可变正式发布、独立完整回读、签名 catalog、同任务 succeeded、非 DR 标签仍必须单独验收。

- [候选服务端 DeleteObjectHandler](https://raw.githubusercontent.com/minio/minio/0d7408fc9969caf07de6a8c3a84f9fbb10a6739e/cmd/object-handlers.go)：版本删除仍先检查 DeleteObjectAction。
- [AccountInfoHandler](https://raw.githubusercontent.com/minio/minio/0d7408fc9969caf07de6a8c3a84f9fbb10a6739e/cmd/admin-handlers-users.go)、[owner 谓词](https://raw.githubusercontent.com/minio/minio/0d7408fc9969caf07de6a8c3a84f9fbb10a6739e/cmd/signature-v4-utils.go)、[help gate](https://raw.githubusercontent.com/minio/minio/0d7408fc9969caf07de6a8c3a84f9fbb10a6739e/cmd/admin-handlers-config-kv.go)：实际 own-policy 与非 owner 判别必须组合读取。
- [ActionSet](https://raw.githubusercontent.com/minio/pkg/v3.1.0/policy/actionset.go)、[ResourceSet](https://raw.githubusercontent.com/minio/pkg/v3.1.0/policy/resourceset.go)：原生 map JSON 集合顺序不稳定，v2 摘要显式规范化。
- [mc policy create](https://raw.githubusercontent.com/minio/mc/RELEASE.2025-04-16T18-13-26Z/cmd/admin-policy-create.go)、[attach](https://raw.githubusercontent.com/minio/mc/RELEASE.2025-04-16T18-13-26Z/cmd/admin-policy-attach.go)、[user add](https://raw.githubusercontent.com/minio/mc/RELEASE.2025-04-16T18-13-26Z/cmd/admin-user-add.go)：上面的新建命令语法及交互输入依据；不保证原现场已经具备该权限。
