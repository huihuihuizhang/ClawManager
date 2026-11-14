# 本次团队卷现场续接

范围仅限已经确认的空闲 RWX 卷挂载阻断和过期 metadata 凭据。执行入口是 `bash run-p2-team-continuation.sh`。务必在独立解包目录内运行；脚本以子进程退出，不关闭登录终端。仅回传 P2_ 开头的摘要，不回传 private 文件或 token。

入口按顺序完成：
1. 校验包内文件；从已确认的应用镜像构建三个工具的 OCI 覆盖层，推送现场 registry 并按 digest 回读。成功后删除该目录中三个镜像临时 tar，保留 image.json。
2. 用原安装者密码、enrollment、完整 writer selection 和实际 Vault 作用域签发 metadata-only 身份。不会使用过期 source window 作为签发前置条件；其余证书有效期仍独立检查。
3. 创建新的 immutable Secret，以 Deployment UID、resourceVersion 和完整旧 spec 为条件更新控制器；核验 rollout、Pod 所有者、文件模式/属主/哈希及运行二进制。
4. 更新同一来源 ServiceAccount 的 token，重新签发 30 分钟来源窗口；创建团队卷只读消费者，等待实际 ShareManager 运行，调用原生 prepare-mount-materials。

成功标志 `P2_LONGHORN_SOURCE_MATERIALS_AUTHORED_NO_HOLD` 仅表示挂载材料已经原生签发。它不是 task grant、实际 hold 或备份成功。把该行和此前 P2_ 摘要交回，随后直接按真实材料衔接现有安装/任务签发和正式采集，不再追加通用生命周期建设。

本次固定记录：
- `/root/sbk/p2-cert-renewal.1KyqMtsd/p2-team-continuation-20261114`
- `/root/sbk/p2-cert-renewal.1KyqMtsd/longhorn-source-20261114-team-attachment`

失败处理：保留 journal 和部分输出。重复运行只接受已经记录且身份相同的结果；未知签发结果、部分原生输出或丢失 Pod 创建回执均拒绝盲重试。若明确在准备阶段失败、原生输出为空且没有成功材料，可运行：

```bash
python3 -B prepare-p2-team-attachment.py --rollback-failed-preparation --nov14
```

该操作仅删除记录中的 Pod UID，并重新检查原 PVC/PV 保留。材料签发成功后不可用此命令卸载。

正式采集、恢复和清理验收顺序：使用本次原生 SourceSelection/LonghornHoldMaterials 衔接现有签发入口；任务开始后检查真实 hold/capture 回执；通过原有恢复路径核对 recovery proof、原业务写入者和卷状态，再退休本次来源，最后按记录 UID 清理只读消费者。当前没有现场 task/config/consumption 标识，不能在包中捏造这些调用参数，也不能凭任务状态或 kill-switch 当作恢复完成。此步骤随首单真实回执执行，不增加通用接口。

本地离线验证不能证明现场证书仍有效、registry 可用或备份成功。若证书检查拒绝，保留摘要中的确切阻断，续签对应证书后继续；不扩大本次范围。

## 重跑、有效期与独立新批次

所有成功记录复用前都重新验证 pin 链、NotBefore/Until，并要求至少剩余十分钟；挂载复用还重读实际消费者及控制器。过期或不足十分钟不会再输出准备完成。新签发仍使用受证书、API token 和 Vault TTL 约束的三十分钟窗口。

- 有效期内中断：重跑原入口。已创建 Secret 或已更新 Deployment 通过实际读取确认，不重复提交。原生成功 receipt/exit 均在、仅 completed.json 缺失时，可以补齐汇总。来源定义沿用原时间窗口，不能偷偷改写已签发材料。
- 原生超时、只有 sent、输出部分写入或缺少成功 receipt：拒绝重发，保留原目录，先核对真实结果。不得删掉 sent 文件绕过检查。
- 来源已过期且尚未产生 Parts/SourceWriters/RedisSources 正式事实：显式运行下一批次。例如第一批过期后执行 `bash run-p2-team-continuation.sh --source-attempt 2`。它读取上一批真实成功回执，创建 source-2 和挂载 -2 目录，签发新 API token 与时间窗口；保留上一批全部记录，并重新核验原只读消费者 UID/spec。第三批同理填写 3，不允许跳过未完成批次。
- 已正式采集、未知原生结果或已退休：新批次入口拒绝。先按真实任务/来源结果恢复和退休，不能通过加编号绕开。
- 新批次仍独立检查 metadata token 和证书；这些凭据过期会明确拒绝，来源编号不会续签它们。

编号批次准备失败时，撤销命令同样带 `--source-attempt 2`，不能操作第一批日志。

## 成功后的具体清理入口

先通过现有业务恢复流程完成恢复，停用本次来源，并停下本安装控制器、等待其 Pod 全部退出。保留真实恢复与来源退休回执。在人工核对两份回执和实际任务编号后执行：

```bash
python3 -B retire-p2-team-attachment.py \
  --source-attempt 1 \
  --task-id '现场实际任务编号' \
  --recovery-evidence-file '/绝对路径/实际恢复回执' \
  --recovery-evidence-sha256 '恢复回执的实际SHA256' \
  --source-retirement-evidence-file '/绝对路径/实际来源退休回执' \
  --source-retirement-evidence-sha256 '来源退休回执的实际SHA256' \
  --confirm-business-restored --confirm-source-disabled
```

必须选择最新批次。两个 confirm 是操作者依据实际证据的明确确认，不是脚本生成的原生恢复证明。脚本校验证据文件 pin 并保留它们与任务编号、来源选择的关联；现场检查原 Deployment UID、replicas=0、无控制器 Pod、无其他团队 PVC 消费者、PVC/PV 原绑定，再以创建回执中的 Pod UID/spec 和当前 resourceVersion 删除本次只读消费者。成功后再次确认 PVC/PV 保留，输出 `P2_TEAM_ATTACHMENT_RETIRED_PVC_PRESERVED`。不删除业务 PVC/PV，不修改业务恢复状态。

若删除响应丢失，使用同一组参数重跑：实际 Pod 已消失且有本入口 sent 记录时补齐回执；仍在终止则继续等待；同名替换 Pod、来源存在新批次、证据变化或控制器仍运行均拒绝。

离线验证使用真实 Python 编排、pin 校验、交付计划、原生调用日志和输出传递，仅模拟 Kubernetes/Vault/原生进程边界。它不证明现场实际恢复或存储健康。
