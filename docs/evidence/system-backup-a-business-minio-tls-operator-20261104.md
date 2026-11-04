# 实际业务 app 的 MinIO HTTPS/CA 切换

此包是首跳 TLS 的独立配套，不修改 A首跳、C/D 冻结源，也不需要未来 backup Config/KEK/Forward/grant。没有执行现场 app/Kube/MinIO 操作。首跳 MinIO TLS 单独完成不能证明业务恢复。

## 实际旧客户端依据

已读旧 fix18 源 dbb86137：NewObjectStorageService 使用 minio-go/v7 v7.0.85 默认 transport，Secure=OBJECT_STORAGE_USE_SSL；它没有 OBJECT_STORAGE_TLS_CA_FILE 配置字段。该固定版本 transport.go 明确读取 SSL_CERT_FILE，并加入 SystemCertPool。因此仅挂新 CA 专用变量不能修复旧二进制。

本包从每个真实原 app Pod（原owner/Deployment/RS UID、完整稳定ready roster、container image/argv、CRI identity）通过原认证 Kubernetes exec读取当前 SSL_CERT_FILE 路径或原默认 /etc/ssl/certs/ca-certificates.crt。只读这些公共根证书，拒绝 PRIVATE KEY、不同副本根内容不一致或无法确定的路径。将全部原根 + 原MinIO CA写成新immutable ConfigMap，不覆盖原全局CA文件。

保持实际原app image、其他env、Secret/account引用、bucket/basePath、PVC等全部原spec字段；仅增加只读CA挂载，设置OBJECT_STORAGE_ENDPOINT、USE_SSL、SSL_CERT_FILE。另设置同一CA的OBJECT_STORAGE_TLS_CA_FILE/SHA供已审新客户端使用；旧版本忽略它们，仍由实际SSL_CERT_FILE生效。不会猜测/更新对象存储密码，不导出容器env或业务Secret正文。

## 权限和阶段

输入原可信 installation-owner enrollment Plan/独立SHA、原静态验证Kubeconfig/CA和独立SHA。复用首跳Source实际SSR主体/UID/groups、cluster/ns UID、SSAR/RBAC通道。业务管理员用户名只取原Plan.LocalAdminUsername；缺失即拒绝，不猜admin。密码由原操作者私有文件读取（已知现场路径 /root/.clawmanager-backup-install/admin-password），不出现在argv正文、消息、日志或回执。

prepare先通过原app真实POST /api/v1/auth/login及受实际角色保护GET /api/v1/admin/skills校验现有admin会话，再读取原CA及真实server dry-run规范化app spec，完整原spec和新意图create-only/fsync落盘。该登录是实际原业务认证，不是写入权限证明；Kube服务端独立执行真实安装RBAC。会产生正常登录会话记录，因此整个基础设施切换必须在B/SQL原census采集之前完成。

apply/query先调用原首跳query-only：原MinIO真实TLS/CA/hostname/leaf/health必须已通过；没有发送的首跳不会被此调用安装。然后新CA ConfigMap/原app UID-RV CAS patch各自在发送前fsync意图，失回包只查固定目标，不重发。rollout以后对每个实际新Pod执行真实管理员登录、读取已有uploaded技能的实际archive_hash、调用 /api/v1/skills/:id/download，经真实DownloadSkill→storage.GetObject→SDK→MinIO取得对象并核对SHA256。前后核对同一Pod UID/CRI。无已有对象、权限/认证失败、哈希不匹配或任何副本未通过均返回未确认，绝不以health/ready替代业务SDK读取成功。只验证实际读通；不宣称实际业务上传写成功，不自动创建测试业务记录或桶。

## 可执行命令

Root将两个新脚本及原首跳脚本放入实际脚本目录；本包仅新增operator资产，二进制数量不变。

```bash
set -euo pipefail
umask 077
: "${APP_TLS_TOOL:?本包实际生产脚本}"
: "${FIRST_HOP_TLS_TOOL:?已审原首跳脚本}"
: "${KUBECONFIG_FILE:?原私有连接}"
: "${KUBECONFIG_SHA256:?原独立摘要}"
: "${INSTALLATION_PLAN_FILE:?原enrollment plan含实际LocalAdminUsername}"
: "${INSTALLATION_PLAN_SHA256:?原独立摘要}"
: "${MINIO_TLS_RUN:?原首跳私有状态目录}"
: "${MINIO_TLS_PLAN_SHA256:?原首跳prepare真实回执}"
: "${APP_TLS_RUN:?新的原操作者私有状态目录绝对路径}"
common=(--first-hop-helper "$FIRST_HOP_TLS_TOOL"
 --kubeconfig-file "$KUBECONFIG_FILE" --kubeconfig-sha256 "$KUBECONFIG_SHA256"
 --installation-plan-file "$INSTALLATION_PLAN_FILE" --installation-plan-sha256 "$INSTALLATION_PLAN_SHA256"
 --minio-state-directory "$MINIO_TLS_RUN" --minio-plan-sha256 "$MINIO_TLS_PLAN_SHA256"
 --state-directory "$APP_TLS_RUN" --service minio --app-deployment clawmanager-app
 --local-admin-password-file /root/.clawmanager-backup-install/admin-password)
python3 -B "$APP_TLS_TOOL" prepare "${common[@]}"
# APP_TLS_PLAN_SHA256只取上述真实business_cutover_prepared_only回执。
# 原首跳MinIO apply完成以后：
python3 -B "$APP_TLS_TOOL" apply "${common[@]}" --plan-sha256 "$APP_TLS_PLAN_SHA256"
# 失回包只查询同一操作；尚未发送阶段不会被query启动。
python3 -B "$APP_TLS_TOOL" query "${common[@]}" --plan-sha256 "$APP_TLS_PLAN_SHA256"
```

推荐先完成原首跳prepare和本app prepare，再在同一真实维护窗口执行MinIO apply → app apply（每副本实际SDK读回）→D/C更新原source SDK材料→C源账户/读取gate→B采集全新Pod/CRI/native事实和SQL census→A17/D纳管。两次rollout之间存在维护中断，不能描述为无中断切换。若首跳已改TLS但旧app不能读取对象，本app prepare仍只先检验SQL登录/管理员路由，不要求旧对象存储已通，因此没有循环。

## 完整原状态回退

```bash
python3 -B "$APP_TLS_TOOL" rollback "${common[@]}" --plan-sha256 "$APP_TLS_PLAN_SHA256"
# 再使用原首跳工具、原目录、原plan SHA执行其rollback，恢复原MinIO spec/传输。
# 两端均恢复以后，实际核对每个原业务实例：
python3 -B "$APP_TLS_TOOL" verify-business "${common[@]}" --plan-sha256 "$APP_TLS_PLAN_SHA256"
```

app回退复用原before/desired spec匹配、真实UID/RV CAS和原operation取消标记，推进RV阻止迟到旧patch；foreign spec不覆盖。原镜像、原SSL_CERT_FILE/CA/scheme/env/挂载完整恢复，不自动删除CA对象。回退无需MinIO仍TLS、CA有效、业务密码文件有效或未来backup配置。最后verify-business只有真实旧业务SDK读取已有对象并核对archive hash成功才报告恢复读通。C若已Acquire禁用旧业务账户，应先按C/D原恢复路径恢复原账户/gate；本工具不绕过原账户禁写，也不把其拒绝当作TLS成功。

## 验证边界

Windows Python -B：2专项模型通过（真实prepare代码保留旧image/Secret引用/bucket/system roots，且只server dry-run；私钥材料不能作为公共根写入）。AST通过，无Go/Docker/cache/pyc。最初测试helper定位错误已修正；临时目录自动清理。既有首跳4项已另通过，不重复计入本包。尚未执行原Kube/Linux exec/实际管理员登录/业务SDK对象读取或原生MinIO切换。没有现场PASS、业务写成功或backup纳管成功声明。
