# 固定 OpenClaw shared-service wrapper layer 分支

交付只是既有Registry V2 producer的窄源码扩展。没有接触Root私有树、实际bundle/镜像层、Go、Docker、缓存、现场Registry或Agent进程。B固定wrapper源保持未改。Hermes路径行为保持原状；不允许用这个flag选择Hermes。

新增显式 --openclaw-shared-service-gate；不提供任意wrapper文件、base/service/hash覆盖参数。不带flag仍为旧Agent-only路径，不能宣称已修复旧独立service或shared安全。实际CLI固定37c base/openclaw-lite/linux-amd64、7425 bundle/63a Agent长度9994402；新分支验证这些精确值后才读完整base，每个descriptor/diffID/gzipEOF仍用原验证。Index仍只允许唯一linux/amd64 child。

按原层顺序处理OCI whiteout/opaque并保留跟踪路径的kind/mode/UID/GID/link/content hash。Agent usr/usr-local/usr-local-bin和service etc/services.d/openclaw-agent父路径必须实际存在、directory、root:root且非group/world writable。run必须regular/root:root/0755/656bytes且SHA=f74cd95d…，拒绝软硬链接/未知脚本。/bin/sleep必须为原不可变base中的root只读可执行regular；仅允许bin本身为真实directory或精确merged-/usr的bin→usr/bin(/usr/bin)软链接，后者要求usr/bin同样真实root非可写directory；不接受hardlink或其他alias。

新追加层确定性只含两个文件：usr/local/bin/clawmanager-agent(0555,root:root,mtime0)和etc/services.d/openclaw-agent/run(0755,root:root,mtime0)，run字节是代码内固定B3649b636…（980bytes）。所有原config键（包括Env/Entrypoint/Cmd/User）以及原layer descriptors/order保留；仅原diff_ids/history各append一次。新blob/config/manifest按原Registry通道上传并独立读回hash/metadata/两个准确文件；只PUT不可变digest，不写tag。

回执增加 openclaw_shared_service_gate、original_service_sha256、service_wrapper_sha256、legacy_state_migrated=false，并保留base root/selected child/config、新Agent/newLayer/newImage digest映射，不含Env/Token。Root应将真实成功回执在原可信root私有发行目录持久化；本JSON本身没有新的签名授权，不是运行时能力或已迁移证明。

## 实际producer命令

```bash
umask 077
python3 -B scripts/system-backup-agent-runtime-layer/agent_runtime_layer.py \
 --runtime openclaw --bundle "$ACTUAL_PINNED_AGENT_BUNDLE" \
 --openclaw-shared-service-gate
# GET-only完整读/构造通过后，同一来源显式发布：
python3 -B scripts/system-backup-agent-runtime-layer/agent_runtime_layer.py \
 --runtime openclaw --bundle "$ACTUAL_PINNED_AGENT_BUNDLE" \
 --openclaw-shared-service-gate --push > "$NEW_PRIVATE_RELEASE_RECEIPT"
```

需要Registry凭据时继续原 --credentials-file（原私有file，正文不进argv/日志）。不接受调用者指定新base/wrapper。只有真实image-pushed不可变reference可交后续实际安装，构造/model通过不算image发布或场景成功。

## 尚未实现的旧状态迁移

wrapper只在原service启动入口按原shared raw-token选择先exec固定/bin/sleep，不关闭已经存活的olddesktop子进程，不证明新sharedAgent正常模式，不把state.json转换slot-assignment.json，不创造baseline/emptyjournal，不续任务/grant。实际旧业务源是否由旧service管理、原正常停止/数据根/身份交接、新Runtime原认证创建、未知quarantine/恢复仍B/D真实owner单独完成；混合Pro/shared、未知env/mount/启动路径及其他历史消费者仍原UNKNOWN。安装前后新镜像/Pod/CRI/native观察必须重新建立，不能沿用旧anchor。

## 执行验证

Python3.10 -B最终10根/44子场景，零fail/error/skip。含原7Registry回归和新3根：准确两文件/原config/layer保留/重复发布无写；服务parent软硬链接/ownership/writable/错误service/whiteout/opaque/不可执行sleep在上传前拒绝；错base/Agent/Hermes/任意wrapper拒绝。只有synthetic ELF、ordered layer和loopback Registry模型；没有读取实际冻结bundle或Root私有输入。最初两个测试桩问题（fixture路径、Python3.10不支持TestCase.enterContext）已修后完整通过，不计此前失败为通过。

无测试二进制、Go/Docker或新缓存；loopback服务器全部通过addCleanup停止，无pyc(-B)。原run_tests.py包含实际bundle检查，Root若执行它必须自行传真实已审bundle路径，不得以本模型代替真实ELF资格（既有Root资格另记）。
