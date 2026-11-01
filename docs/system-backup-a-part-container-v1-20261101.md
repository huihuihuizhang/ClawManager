# Original C part container v1（候选 codec）

本项提供实际字节 Writer 与独立 Reader，尚未接入 upload-only Job、正式 manifest 或独立 DR。没有 source grant、旧 capture Authority、DEK、SQL、KMS 或私钥输入。所有返回值都是 inert byte facts；不构成任务所有权、业务校验或发布许可。

## 物理格式

`system-backup-part-container.v1`：8 字节 `53 42 50 43 00 00 00 01`，随后 4 字节大端无符号 header 长度，随后 UTF-8 JCS header，随后各 member 的 **原 C 完整字节 + 原 envelope 完整字节**。成员严格按原 PartIndex 升序，组内允许原 index 有间隔，禁止重名、重复 index、重排、空洞、重叠、遗漏或尾随字节。offset 相对 payload 起点；Reader 返回绝对 offset。

Header 固定包含 `members`、`schema_version`、`scope`、`source_inventory_sha256`，按 JCS key 顺序串行编码。每个 member 保留原逻辑 C/envelope object path、原完整 stream spec/KeyRequest（仅公开 key reference/context，无 grant/key）、原 index、offset/length/SHA、原 framing/envelope 版本及原 checkpoint 完整 bytes（base64）。嵌套 StreamSpec 使用 Go 公共 DTO 的原字段名；不得改写原 AAD/path、重新加密或生成新 C。

checkpoint bytes 保持原 producer 序列化，typed round-trip 比较仅用于拒绝别名/缺失/多余字段；其 JCS SHA 必须与独立传入的原捕获证书 checkpoint 集相同。每个 envelope 的原始 SHA/长度和 `ParseStreamEnvelope(originalSpec, bytes)` 都需通过。这里只验证物理 bytes/绑定形状；独立当前 Unwrap、完整 AEAD/EOF 和 domain 验证仍是正式调用方的必需步骤。

用于未来 `PartSummary.ciphertext_sha256` 的候选值是 **完整真实物理容器对象的 SHA256**，包括 prefix/header 和全部原 C/envelope 字节；不是摘要列表的 SHA 假称密文 SHA。`Facts.CipherBytes/EnvelopeBytes` 另保留原成员物理总量，不混同 plaintext/business 计数。

## 配置容量与内存边界

Write/Inspect 必须显式传入该原任务真实 `max_artifact_bytes` 与 `max_index_bytes`。绝对上限复用 v12 CapacityConfig：artifact 900 GiB（966367641600），index 8 GiB（8589934592）；支持原默认 16 GiB/512 MiB，不再设静态 8 GiB artifact/8 MiB header 上限。完整 prefix/header/成员 C/envelope 均计入配置 artifact budget，header 计入配置 index budget；生产组合器还须合计所有组与其他 artifact 对象的全任务预算。

成员数 10000 对应原 `publicadapter/modules.go`/runner 的原 capture part 上限，不是 max_source_items；源行、对象和工作区 entry 均保留在原 C 内。每个原 stream AAD/key/context 字符串原已有 256 字节边界、逻辑/公开 path 1024、checkpoint inline 8192；容器为完整序列化 member 预留 64 KiB（包含 checkpoint base64 和 JSON escaping），scope 4096。由原分片数与字段形状推导的 header 最大值小于 4 GiB，4 字节长度可完整表示；不是把配置 max_index_bytes 收窄到 8 MiB。所有超预算均明确拒绝，绝不截断。

Header Writer 两遍计算并比较每成员 canonical SHA，串行输出；Reader 按最多 64 KiB 单成员对象流式解析，先检查数量再添加 typed member，不按配置的 512 MiB/8 GiB 分配整个 header byte buffer。Envelope 内存至多原 crypto parser 的 32 MiB/成员，C 流复制为 64 KiB，metadata 类型数组保留原每成员记录。没有生成、读取或分配 16 GiB/900 GiB 的测试数据。

## 同一字节序列与固定版本

Reader 直接将**实际读取且解析的 prefix/header**送入 whole SHA，再以同一个顺序 payload reader 同时计算 whole/member SHA；不能先解析 header A，再从头读取 B 验 SHA 而返回 A。监督提供的可变 ReaderAt 反例已经纳入回归。固定 version DTO 不是 Reader 可免除一致性检查的理由。

Writer 不知道未来 native object version，因此不会编造。独立 native readback 传入真实固定 version，Reader 把这一完整对象 version 与每个绝对 member range 一并返回。空/null/latest/current/default、控制/空白字符版本拒绝。v12 public artifact index **不新增 version 字段**；其 framing_version 可识别本 container 版本，实际 native version 留在原 readback/私有游标中。

## 验证范围

- 本地实际 AES-GCM C 的 named DATA 正例：物理字节完整 SHA、不同输入枚举仍同序输出、完整独立 Reader、原 C/envelope/AAD/checkpoint 与固定对象 version/range 保持。
- omission/reorder/replacement、gap/overlap、截断/尾随、header alias/未知字段、checkpoint substitution、scope/hash/budget/cancel、额外/不足 C、错误 envelope：失败只返回零完整 facts。
- 16 GiB/900 GiB 是布局运算与写入前容量 gate 的 named DATA，不是巨量原任务成功；配置过小/超原契约上限提前拒绝。10000 个 header member 的真实序列化/流式解析超过 8 MiB，验证 512 MiB 配置可用与 1 MiB 配置拒绝。
- `.tools/a-part-container-capacity-header-aba-data-v3.log` PASS5.257s，session7128 terminal0；此前首轮 DATA PASS2.997s 仍保留，但没有修正前 header ABA 安全结论。监督原红日志 `.tools/supervisor-container-header-baseline.log` 保留。
- 去除不用于实际 Reader 的整体 header 解码路径后，最终同套 codec/Reader/容量/ABA 回归 PASS5.398s，session60670 terminal0，`.tools/a-part-container-codec-final-local-v4.log`。结构化范围、源码/日志 SHA256 见 `docs/evidence/a-part-container-codec-20261101.json`。

本项尚未修正上传/组装旧链路中的静态 8 GiB gate，也未进行 native Job/readback/AEAD/domain 验收；这些需在实际 RunPublicationPass first-forward 接线中继续完成，不能据此声称整链容量或发布已通过。
