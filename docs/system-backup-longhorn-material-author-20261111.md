# 本次 Longhorn 原生卷材料的生成接线

原 `host-materials` 只校验并打包已有 `LonghornVolumes`，不会生成文件。本次在既有、经原 installer 认证的 `system-backup-source-registries prepare-mount-materials` 流程增加显式选项：mount-layouts DATA 中设置 `AuthorLonghornHold: true`，并提供原有 `Longhorn` namespace/snapshot/clone class 名称选择。

原 reader 仍完整执行 SQL/API/native roster、租户 mount、原生 Longhorn source 前后读回。新增生成步骤从这些实际 source 派生：

- RWO：真实 running tenant Deployment→ReplicaSet→Pod、PVC/PV 与完整 PV spec，读取单容器 CRI 身份及完整卷的挂载点。
- RWX：真实 Volume/share-manager owner 链、原 provider Pod/Node/CRI 身份、NFS endpoint，并枚举完整命名空间内普通、init 和 ephemeral 容器的实际运行挂载。同 source/Node 上不能由现有 v3 template 唯一描述的挂载根拒绝生成。
- 使用原 `SharedObserver` 的实际 CA、client certificate/key 文件摘要，验证证书链、当前有效期、client 用途与精确 controller ServiceAccount SPIFFE URI。
- 同一个真实 source 被多个 capture part 使用时只生成一份 provider 坐标。前后 provider、客户端、Node 与 endpoint 比较不一致则拒绝写出。

输出新增 `longhorn-hold-materials.json` 与 `longhorn-deployment-core.json`，原 Core 不覆盖。successor template 的 Core SHA 与 successor source selection 同时更新，并由原 installer/reader 再检查新组合。receipt 的 `LonghornHoldMaterials`、`Deployment` 是新输入文件的 pin；后续必须消费这些 successor，不能混用旧 Core。未启用该选项的既有 wire 保持不变。

生成物是安装坐标 DATA：Claim、Attempt、OperationID、ReservationID、InventorySHA、Generation、FenceEpoch、ExpiresAt 都没有任务授权。原 host-materials 的签名 V2 source registry / tenant 来源校验继续保留。实际 Node 服务随后独立通过 CRI、block device、mount namespace、ext4/NFS FD 和原协议核验；真正任务仍由原 keeper 注册和 SQL lease/claim 绑定。这里不创建任务、hold、snapshot 或成功回执。

本地定向测试覆盖 RWO/RWX 来源及完整客户端、重复 shared part、Node/Pod/PVC/PV/provider/process/mount 漂移、前后 endpoint 改变，以及实际 client PKI 的过期、错误主体、文件 pin 和私钥错误。原 mount author、tenant source 和 keeper recovery 测试一并运行。该交付尚未在现场生成并加载 Longhorn 坐标，亦未通过完整原生 FD、真实停写/恢复或整单验收。

现场快照已固定，连接恢复前可继续完成本地配置与工具接线；真实首次配置和正式 page task 仍须完整原 owner 材料，不能以旧 offline TenantPro 拒绝条件被删掉、虚构 task/claim 或补造成功状态代替。
