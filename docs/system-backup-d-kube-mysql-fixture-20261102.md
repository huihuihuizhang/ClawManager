# D：独占 Kubernetes SAN/TLS MySQL 诊断入口

用途仅为 **隔离 fixture DATA**：消费 A 已审核预编译 Linux amd64 bundle，在原 30 秒策略、原源量和原授权检查下诊断 key-check 耗时。不是页面验收、生产数据备份或新增 App/controller 部署。用户自行连接、自行执行；本轮没有 SSH 或连接远端。

文件：`scripts/system-backup-d-kube-mysql-fixture.sh`（Bash 入口）、同名 `.py`（Python 标准库执行/清理）、`.test.py`（本地 mock，无 Kubernetes）。

## 资源与边界

- 仅创建新随机 namespace `sbk-apermit-<随机标识>`、该 namespace 的随机密码 Secret、deny-all ingress/egress NetworkPolicy 和单 MySQL Pod。namespace/Pod/Secret/policy 均带 128 位随机 owner label；不使用现场已有 namespace、数据、Secret、PVC、Service、App 或 controller。
- MySQL 镜像默认及完整命令使用用户已确认的私有仓库引用 `10.130.14.23:5000/mysql@sha256:5ea882b1859d3a61814e527215563d809a9f2bf70ffa24c9280f2ff6798f1977`，不会去 DockerHub 查找该私有仓库 digest。**不从旧 tag、引用名称或 digest 推断它是 MySQL 8.4**；执行时读取本轮新实例的 VERSION()。若实际受信镜像仓库引用不同，可用 `--mysql-image` 给真实引用，摘要仍须为上述精确值。镜像须可拉取或已在可调度节点缓存；不拷贝生产 imagePullSecret、不修改节点仓库信任配置。
- 数据、TLS 证书及 CA 私钥均在该 Pod 的 emptyDir；没有 HostPath、PVC、hostNetwork/hostPID/hostIPC 或 privileged，关闭 ServiceAccount token 自动挂载。MySQL 保留官方 entrypoint 所需默认能力，不加特权。若集群 admission 拒绝就停止，不降低安全策略。
- 同一固定 MySQL 镜像的 initContainer 用它自带的 `/bin/sh` 和 OpenSSL 生成一日临时根 CA/服务证书，SAN 精确含 `DNS:localhost,IP:127.0.0.1`。CA 私钥不挂给主容器。镜像缺 OpenSSL 或 admission 注入其他 sidecar/token/外部卷时拒绝，不回退明文/不关闭验证。
- MySQL 参数强制 `require_secure_transport=ON`、`tls-version=TLSv1.3`。只 exec 本轮 namespace/Pod，在原 owner/UID 检查后通过本 Pod 内 mysql socket 读实际 VERSION()、UUID 和 TLS 配置；不要求宿主机 mysql/OpenSSL。Ready 后从同一原 Pod status 采集 mysql/tls 两容器实际 imageID（保留 CRI 原始形式），缺失或格式不合法拒绝继续，不拿请求的 image 字符串代替实际 imageID。
- 本诊断保守支持 MySQL 8.0.16+ 的 8.0 分支或 8.4.x；其他分支/低版本在 A runner 前拒绝，报告保留合法格式的实际版本。8.0.16 起的 TLS1.3 还取决于构建的 OpenSSL 支持，见 [MySQL 官方 TLS 协议说明](https://dev.mysql.com/doc/refman/8.0/en/encrypted-connection-protocols-ciphers.html)。版本门只提供基本能力下限，不保证当前迁移都兼容；原完整迁移/native 测试仍须实际执行，TLS1.3 配置和证书检查也不能省略。
- kubectl port-forward 仅监听 `127.0.0.1`，默认使用 `:3306` 让 kubectl 原子选空闲本地端口，从该子进程输出读回端口；可显式指定高位端口，但拒绝 3306、低位或越界端口。若被占用则失败，不误连其他监听。普通 GET/DELETE/exec 的 HTTP request-timeout 为25秒；port-forward 与 Ready wait 独立使用 request-timeout=0，避免25秒 HTTP超时干扰原30秒诊断。Ready condition 上限仍240秒、外层subprocess上限260秒；port-forward 启动等待30秒且由准确子进程/A runner 生命周期清理，A runner外层等待1080秒和其原15分钟test上限仍保留。deny-all policy 下若现场 CNI 不支持此 port-forward 路径，保持拒绝，不为此开放生产网络。
- 生成本轮私有 `credentials.json`：Host=127.0.0.1、真实转发端口、root/随机密码、临时 CA 路径、TLSServerName=localhost、本轮 UUID。仅该独占实例允许 root 建立 synthetic 测试 schema/account；不继承生产身份或宽权限。

## 参数与前提

主机需 Linux x86_64、Bash、Python3、kubectl，及 A runner 使用的常规 coreutils/tee/grep（预检逐项检查）。**无需主机 Go、Node、Docker、mysql CLI 或 OpenSSL。** kubeconfig 必须有创建/读取/删除本轮 namespace、创建 Pod/Secret/NetworkPolicy、读取/exec/port-forward 自有 Pod 的权限，不能把管理员 context 当数据面授权。

A bundle 必须含已审 `run-diagnostic.sh`、ELF、完整 SOURCE receipt 和 SHA256SUMS，独立核对传输摘要；入口和 A runner 都先校验其 SHA256SUMS。不能把旧二进制/旧源码 receipt 当成当前版本。宿主机与可调度节点需要足够 CPU/内存/临时存储：Pod request 1CPU/1Gi，memory limit 3Gi，无 CPU limit，数据 emptyDir 上限16Gi。测得时延是该 fixture 节点/port-forward 实际条件下的 DATA，不证明生产容量/延时。

```text
bash scripts/system-backup-d-kube-mysql-fixture.sh
  --bundle /absolute/reviewed-A-bundle
  --scratch /absolute/existing/private-scratch
  --logs /absolute/NEW-log-directory
  [--context kubernetes-admin@kubernetes]
  [--mysql-image exact-reviewed-reference@sha256:5ea882...]
  [--port 0]                  # 默认动态 loopback；固定端口须 1024..65535 且非3306
  [--cleanup-timeout 90]      # 1..300秒，不强删finalizer
```

该命令不查询既有 namespace/生产 MySQL；所有 kubectl 均显式 context，资源创建/exec 限于本轮新 namespace。不再进行跨 namespace 排查。`--logs` 必须是新绝对路径，输入 bundle/scratch 必须存在，解析到真实路径。

## 原样 Bash 执行命令

以下由用户在 zhanghui08 验收机执行。先填真实 checkout/工具包路径和实际 A bundle 路径；D Bash 与 Python 两个文件须在同一 scripts 目录，并独立核对其审核摘要。没有部署命令，不需要 SSH 密钥。

```bash
# 必填实际路径：
# export REPO_ROOT=/absolute/path/to/ClawManager
# export A_PERMIT_NATIVE_BUNDLE=/absolute/path/to/reviewed-linux-amd64-bundle
(
  set -euo pipefail
  umask 077
  : "${REPO_ROOT:?absolute checkout/tool package path}"
  : "${A_PERMIT_NATIVE_BUNDLE:?absolute reviewed A precompiled bundle path}"
  [[ "$REPO_ROOT" = /* && "$A_PERMIT_NATIVE_BUNDLE" = /* ]]
  fixture_repo=$(realpath -e -- "$REPO_ROOT")
  fixture_bundle=$(realpath -e -- "$A_PERMIT_NATIVE_BUNDLE")
  fixture_base=$(realpath -e -- "${TMPDIR:-/tmp}")
  fixture_run=$(mktemp -d "$fixture_base/clawmanager-native-kube.XXXXXXXX")
  fixture_run=$(realpath -e -- "$fixture_run")
  [[ "$(dirname -- "$fixture_run")" = "$fixture_base" && "$(basename -- "$fixture_run")" = clawmanager-native-kube.???????? ]]
  mkdir -m 700 -- "$fixture_run/scratch"
  printf 'fixture_review_directory=%s\n' "$fixture_run"
  set +e
  bash "$fixture_repo/scripts/system-backup-d-kube-mysql-fixture.sh" \
    --bundle "$fixture_bundle" --scratch "$fixture_run/scratch" --logs "$fixture_run/logs" \
    --context 'kubernetes-admin@kubernetes' \
    --mysql-image '10.130.14.23:5000/mysql@sha256:5ea882b1859d3a61814e527215563d809a9f2bf70ffa24c9280f2ff6798f1977' \
    --port 0 --cleanup-timeout 90 2>&1 | tee "$fixture_run/run.log"
  fixture_pipeline=("${PIPESTATUS[@]}")
  fixture_rc=${fixture_pipeline[0]}
  if [[ "$fixture_rc" = 0 && "${fixture_pipeline[1]}" != 0 ]]; then fixture_rc=1; fi
  set -e
  printf '%s\n' "$fixture_rc" >"$fixture_run/entry-exit-code.txt"
  printf 'fixture_exit=%s\nfixture_review_directory=%s\n' "$fixture_rc" "$fixture_run"
  exit "$fixture_rc"
)
```

预期完整执行退出0，但它只表示该 **fixture** 的 A native diagnostic PASS/未SKIP和清理完成。原测试失败返回原退出码，例如7保持7；仅清理失败时返回1。预检失败在任何 Kubernetes 创建前结束；init OpenSSL/证书、镜像拉取或 Pod readiness 问题会在相应固定 stage 失败，保留非秘密阶段/归属报告。不会用 SKIP、30秒失败或 SQL回执冒充页面完整备份。

日志：`logs/diagnostic/native.log`、A SOURCE receipt、`test-exit-code.txt`，以及 `logs/fixture.json` 的 namespace/UID/owner/stage/server_version/observed_image_ids/original_exit_code/cleanup_exit_code/residuals。`logs/ownership.json` 在第一次创建前写入随机 name/owner，并在取得 namespace/Pod UID、实际 imageID、server version 和子进程 PID 后更新，供异常中断后定位；未读到版本时为 null，未读到 imageID 时为空集合，不能据此宣称通过。imageID 可为运行时配置摘要而非Registry manifest摘要，不强行将二者等同。日志里的历史 PID 不能单独用作后续杀进程的依据。没有导出 Pod/MySQL 原始日志、Secret JSON、密码、CA私钥、DSN或 kubectl 失败正文；fixture 命令只输出固定阶段/归属报告及 A 原诊断日志。测试成功仍不代表页面任务、正式 acceptance/catalog 或 Runtime 物理恢复完成。

## 清理与失败残留

正常、错误或 SIGINT/SIGTERM 都进入有界清理：先停止本次持有的 A runner session 和 port-forward 子进程，使用准确 Popen PID，绝不 `pkill`/按进程名删除。只在创建已尝试且 namespace 的随机 owner 对应时确认原 UID；删除前再次读 owner/UID，再经 Kubernetes DELETE 的 `DeleteOptions.preconditions.uid` 原子限定原 namespace。创建 ACK 丢失只允许通过同一随机 name+owner 查回 UID，不能接管其他资源。

实现使用 `kubectl delete --raw=/api/v1/namespaces/<精确本轮名称> -f -` 发送 DeleteOptions；该 raw DELETE 支持一个文件或 stdin，参见 [kubectl 官方实现](https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/delete/delete.go)。不是检查 UID 后再做无前置条件的名称删除。不会按 prefix 清理、不强改 namespace finalizer。

删除响应丢失、UID/owner 变化、权限或 API 失联时，`residuals` 保守报告该 **精确名称/原UID/owner 的未确认清理项**，不代表已经证明仍存在；必须由用户核对处理，不能反复对同名前缀删除。进程停止失败仍继续尝试 namespace 删除；namespace 删除失败仍继续清除本次本地 credentials/CA/work。清理错误不覆盖原测试失败码。若报告写失败会给固定错误并保留原失败码，不把秘密异常正文输出。

本地秘密 work 在经 realpath/父目录/非symlink检查后删除；A runner 自己的运行副本也在其原 cleanup 中删除。保留非秘密日志供审核。确认报告没有未处理 residual 后，只删本次外层日志目录：

```bash
: "${FIXTURE_REVIEW_DIRECTORY:?exact fixture_review_directory from this run}"
fixture_base=$(realpath -e -- "${TMPDIR:-/tmp}")
fixture_run=$(realpath -e -- "$FIXTURE_REVIEW_DIRECTORY")
[[ ! -L "$FIXTURE_REVIEW_DIRECTORY" && "$(dirname -- "$fixture_run")" = "$fixture_base" && "$(basename -- "$fixture_run")" = clawmanager-native-kube.???????? ]] || exit 1
rm -rf -- "$fixture_run"
```

不删除原 A bundle、其他测试目录、缓存或已有 Kubernetes 资源。残留 namespace 只能按报告的精确 owner/UID 重新确认后处理；不要把删除本地日志当成 Kubernetes 清理证明。

## 本地验证

`py -3.10 -B scripts/system-backup-d-kube-mysql-fixture.test.py`：10项 mock 回归最终全部 PASS，退出0，全部不运行 kubectl/真实MySQL/网络。覆盖完整模拟资源/TLS/动态loopback/原测试7保留、namespace UID变化、owner变化、进程停止失败后继续删除namespace和本地秘密、删除API失败后清理本地秘密、创建ACK丢失只能找回原owner，以及拒绝信号发给非本轮进程组。新增实际版本/运行时imageID记录、8.0.15在runner前拒绝并清理、8.4版本来自查询观测、短GET/DELETE的25秒与长wait/PF的0请求超时分别核对；外层有界等待未移除。测试目录在仓库根下创建、清理。

Windows首轮新增进程组用例因 os.getpgid 不存在而发生测试mock兼容错误，已仅在mock中使用 create=True，不改变 Linux 生产逻辑。默认沙箱启动Git Bash因 signal pipe权限被拒绝；以仅允许本地语法解析的升级执行对入口和本文两段完整Bash块分别做 `bash -n`，均退出0，没有执行Bash脚本或任何kubectl。提取代码块的本轮临时目录在finally删除。尚无远端实测或镜像内OpenSSL实证，测试报告不能写成真实SAN/TLS MySQL通过。
