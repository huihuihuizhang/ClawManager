# 系统备份与恢复开发流程图

> 生成时间：2026-09-17 15:25（北京时间，UTC+08:00）  
> 依据：当前工作树、[四人分工与开发门禁](system-backup-restore-division-plan.md#16-四人分工和开发门禁)、[D 阶段步骤](system-backup-restore-d-role-steps.md)、[进度盘点](system-backup-restore-d-p0-0a-inventory.md)及 [v12 合同清单](../contracts/system-backup/v12/contract-manifest.json)。阶段表示开发顺序，不代表计划已给出日历排期。

## 横向开发流程

```mermaid
flowchart LR
    S["01 · 能力摸底<br/>A / B / C / D 接入"]
    A["02 · P0-0a 合同冻结<br/>当前：29 项草案 / 7 项缺失"]
    B["03 · P0-0b 安全与控制面<br/>当前：部分代码及迁移已完成"]
    C["04 · P0a 备份闭环<br/>capture → artifact → catalog"]
    D["05 · P0b 恢复侧能力<br/>隔离演练 + 生产只读预检"]
    U["06 · P0b 页面<br/>/admin/backups<br/>当前：无页面入口"]
    E["07 · P0c 运维闭环<br/>prune / promotion / 监控 / 四矩阵"]
    G(["08 · P0 发布验收"])
    J["09 · P1 前置<br/>独立 control database / journal"]
    P(["10 · P1 生产恢复执行"])

    S --> A --> B --> C --> D --> U --> E --> G --> J --> P

    classDef active fill:#DBEAFE,stroke:#2563EB,stroke-width:2px,color:#172554
    classDef partial fill:#FEF3C7,stroke:#D97706,stroke-width:2px,color:#78350F
    classDef planned fill:#F3F4F6,stroke:#9CA3AF,stroke-width:1.5px,color:#374151
    class A active
    class B partial
    class S,C,D,U,E,G,J,P planned
```

**阅读方式：** 箭头是阶段验收及真实集成的先后顺序。P0b 的只读 adapter/verifier 可以用固定 fixture 提前准备，但真实恢复集成仍需 P0a 产出的 committed artifact。`/admin/backups` 在 P0b 开发，P0c 再完成 prune 等运维流程；只有 P0c 与四种部署矩阵通过后，才进入 P0 发布验收。生产环境执行恢复属于 P1，须先建设独立 control journal。

## 人员接入与当前程度

| 人员 | 按开发顺序的接入和交付 | 当前可确认的程度 |
| --- | --- | --- |
| **A**（实际开发人未填写） | **P0-0a 接入** users、AI Gateway 策略和合同评审 → P0-0b 审计、脱敏、强认证 → P0a Secret、KEK、签名、证据 → P0b 只读证据验证 → P0c 安全告警。 | A 的对象策略及跨 Owner 评审尚待提交；A 域仍有运行时 DDL 待收敛。 |
| **B**（实例域标注 **ltt**） | **P0-0a 接入**实例及 CSI/HostPath 能力确认 → P0-0b participant、runner、relay → P0a capture、checkpoint、staging → P0b 隔离恢复资源、normalizer、cleanup → P0c 资源收敛。 | 控制面的 Job observation 和 drill resource 表已有 D 提交；B 的 status-relay、restore target 合同及真实执行尚待交接。 |
| **C**（Teams 域标注 **hxc**） | **P0-0a 接入** Teams、Skill Hub、Redis、对象存储能力确认 → P0a artifact、finalizer、catalog → P0b catalog import 与 artifact 读取验证 → P0c artifact health、prune provider。 | catalog record/import/scan 仍有合同与控制表缺口；尚无可验收的 artifact 和灾备发现闭环。 |
| **D**（资源域标注 **zh**） | **P0-0a 起持续牵头**机器合同与归属盘点 → P0-0b migration、controller → P0a resources 数据模块与备份编排 → **P0b `/admin/backups` API/Console** → P0c promotion、监控及发布证据。 | 已有合同、controller、控制表及 resources 计数代码草案。测试安装已验证 `064`–`077` 迁移和资源表只读计数；合同冻结、权限/接管验收及真实备份 Job 均未完成。 |

表中的 **ltt / hxc / zh** 是主计划分别在实例、Teams、资源管理业务域标注的实际开发人；主计划没有填写 A 的实际开发人，也没有为每人提供具体开工日期。

## 当前进度总结

- **阶段位置：** P0-0a 正在推进，P0-0b 有部分底座提前开发；五个 P0 阶段目前均未通过完整门禁。v12 合同清单为 **29 项 draft、7 项 missing、0 项 frozen**，能力证据和跨 Owner 评审仍是阻断项。
- **已有代码与验证：** 当前工作树包含独立 controller、控制面 migration、资源域范围/计数代码和 Go/TypeScript DTO 草案。测试安装已应用并核查 `064`–`077`；这些结果不能替代合同冻结、权限隔离、真实 controller 接管或备份链路验收。
- **页面状态：** 前端已有 `systemBackupContract.ts` DTO 草案，但当前路由和导航中没有 `/admin/backups` 入口。该页面按计划在 **P0b** 开发，展示备份、隔离恢复演练及生产目标只读 preflight/diff；P0c 补齐 prune 等运维闭环。
- **交付边界：** **P0 发布**需要经过 P0c 的四矩阵验收；**生产恢复执行**属于 P1，须先交付独立 control database/journal，再实现确认后的执行链路。
