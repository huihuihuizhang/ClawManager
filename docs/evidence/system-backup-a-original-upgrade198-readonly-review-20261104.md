# A独立只读审查：D1原库198升级冻结v1+r2

审查对象为v1 map09cd596bc9b80d8d856bde967455878395370bd797c3a5bdc864c527c2a216a7及HEX r2，最终生产脚本c18ebccdd0dcfa768ddda82059251ab95e7bf6a500784ca213ae90886c2fed14。已核两个map全部源码SHA一致。只读公开源码/操作说明/测试源，没有运行脚本、Go、Docker、SQL、Kube或缓存，没有修改冻结源。本报告不是完整原库/Kube/99表演练资格；Root先前17模型/6原生子项通过不代替本脚本的中断恢复验收。

## 必须修复的两项

### [P1] 临时高权限账户必须先锁定，再终止会话和删除

文件：backend/.d-original-upgrade198-native-r2-20261104/system-backup-original-upgrade198.py，OriginalUpgrade.cleanup，1188–1195（原始行号）。初次prepare 668附近向该账户授予ALL ON *.*及SYSTEM_USER/SYSTEM_VARIABLES_ADMIN/CONNECTION_ADMIN/PERSIST_RO_VARIABLES_ADMIN。

目前先SELECT PROCESSLIST→逐个KILL→DROP USER，只检查mysql.user不存在，随后删原scratch/排他ConfigMap并发布cleanup-completed。窗口内仍可用当前一代临时凭据建立新连接；DROP USER不会终止已建立会话，该会话继续持有既有权限。触发时序：cleanup读完IDs或KILL结束→延迟原kubectl exec/mysql（或仍持该临时凭据的进程）完成认证→cleanup DROP USER成功→旧会话不在mysql.user但仍在PROCESSLIST。账户被删除不能作为“临时高权限已撤销”的充分读回。此前fence_pending_native隔离较旧密码代际，不能替代最后当前代际账户关闭。

最小修复：当前已验证原root连接执行：
1. 在本地持久化same-operation cleanup-account-close意图。
2. 若该精确临时user@localhost仍实际存在，ALTER USER ... ACCOUNT LOCK；实际读回locked=Y；回包未知只查询/确认该原目标，不直接宣告完成。
3. 在禁止新认证之后枚举并KILL该用户名的全部旧连接，重新查询直到真实EOF（包括KILL延迟完成的情况）；只有EOF才DROP USER IF EXISTS。
4. 再读mysql.user不存在且PROCESSLIST该用户名EOF；原账户/只读配置/业务副本读回保持。全部成立才清除scratch/exclusion及写cleanup-completed。

不修改任何原业务/root认证hash，不增加授权JSON或新账户，不要求一个新框架。应补可控时序回归：KILL之后尝试以原临时凭据新连、以及DROP之前已连入的会话；修后新认证拒绝、旧会话被终止、完成标志不可先于EOF。需Root原生MySQL验证，不把本静态时序当已执行实测。

### [P1] 失败原库留档中断后，固定xb文件名会永久阻断完整回退

同一文件：rollback 783–785；dump 459–467，特别463的open("xb")。

原DDL已部分完成后用户选择rollback。首次dump("failed-original-full.sql")先创建文件，再远程mysqldump、文件fsync、barrier，最后才写failed-original-preserved.json。任一dump超时/远程失败/本地进程中断发生在创建之后、seal之前，留下部分或未确认的SQL文件，没有preserved标志。下一次rollback经过新临时密码fence后仍调用同一文件名，必FileExistsError；query不能使部分DDL成立，release拒绝未知DDL，cancel也拒绝原DDL已尝试。因此即使实际verified原备份、原35 escrow身份、原凭据都仍完整，正式恢复命令仍被这个残缺留档文件堵死。不能指望操作者手动删/覆写，因为它可能是唯一失败现场材料，且文档要求保留。

最小修复：失败原库留档改为逐尝试create-only新名称（编号或随机），发送前保存same-operation snapshot-attempt意图；每次仍先fence/真实barrier。仅完整远程dump退出0、实际文件fsync和SHA、前后barrier通过之后，才通过原create-only failed-original-preserved.json选择那一个已完成文件。所有旧partial/unknown尝试原样保留，永不覆盖，不把存在文件或部分SQL当成功。没有完整封存的失败原库快照之前，仍禁止DROP原库。原verified original-full.sql及其SHA/35表TABLE_ID策略保持，不以新的部分数据库快照覆盖独立原备份。

最小回归应覆盖：①dump刚创建文件后中断；②远程dump成功但seal之前中断；③已有完整sealed失败快照不能被后续半恢复库替换。重新调用同一rollback可新增完整失败留档、保留旧partial，然后才进入隔离恢复/原35保存/完整回退。不要在此补“继续执行剩余DDL”。

## 已逐项追踪且本轮没有另报严重缺陷的路径

- DDL单发：apply739–752在任何35别名/101迁移发送前持久化original-ddl.send-unknown；其后第二次apply拒绝。query只读/读回，不续DDL。exclusive_sql不做MySQL事务回滚假设；错误保留原账户锁/read_only，并尝试重立super_read_only。
- 原备份：backup先最终barrier→原99基线→full dump同文件恢复到随机副本→全部原行/完整hash对照→原backup SHA封存；rollback重复核原备份hash、重做隔离恢复；首次破坏原库前保留失败态（但上述P1必须可恢复）。原备份/状态/日志均不由cleanup删除。
- 原35 escrow：preserve_original_control_tables817起逐个核原InnoDB TABLE_ID在原名/原alias/同操作cm_native限定范围且COUNT0；不接受凭表名新造替代。原表真实RENAME移出业务库，再DROP/恢复；归还前核原TABLE_ID和新副本空，再DROP空副本/RENAME归还。完整原schema/99行/97账本读回前不可释放；cm_native非空不可清理。这些静态检查不代替实际跨schema FK/崩溃演练。
- 释放后旧备份倒灌：rollback开头必须fence_pending_native；它在521明确拒绝released.json或release.send-unknown.json。release先保存意图才解原账户/持久只读，finish-release仅恢复原设置/业务副本，不调用DROP或备份导入。恢复new-container的releasing分支也不fence/获取capture资格。
- 代际与samePV：auth-NNNNNN私有文件/路径不可变，新密码实际认证后终止本操作旧会话；load不接受highest意图未知为成功。recover-controller真实重枚举原Deployment、新Pod/CRI、image、SA UID、PVC/PV及本地node UID，保留server UUID认证；新controller绑定另外create-only，不覆盖原state。原层迟到DDL使用旧凭据路径，恢复会更换密码并清旧会话。这里没有宣称原生Kube普通重启全脚本已通过。
- preDDL取消与完成：cancel拒绝original-ddl存在；初始root创建用原cancel marker+active dir+GET_LOCK确认收敛。release/cancelled完成写入均位于原SQL状态与原app实际副本读回以后；finish-release不会恢复97旧快照。cleanup-completed的“临时账户完全消失”仍受上述会话竞态影响，不能按当前实现放行。

结论：先修这两项再冻结新exact-before增量，由Root选择最小失败时序验证和实际原库演练；不重开框架，不要求新手写授权文件。A保持只读，修复归D1，完整资格和发行归Root。
