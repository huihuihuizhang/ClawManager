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
