# Backup / Team integration workbench

This branch is an **in-progress integration**, not a released replacement backup
engine. Do not enable v2 from a database edit or infer runtime readiness from a
passing library test. Production submission, backup/preflight details and safe
unstarted cancellation are composed. The v2 capture runner and independent
restore composition remain unavailable; submission refuses without fresh
executor readiness. See `task-admission.md` for the implemented boundary.

## Provenance and preservation

- Team baseline: `be7da27dff85c2daf3321b8245ffdab024e67853`.
- Backup source: `huihuihuizhang/ClawManager`, latest reviewed commit
  `8ef5fa7fd4df45f6306e910705db01f589266ba7` on `backup`; the d3c5715a control/dispatch and 8ef5fa7f relay additions are included; initial
  port and unchanged SQL came from `63a13b2771091e4ba47b691ce066a670cbc88d54`.
- Common base: `b5582554f330e0e92a115bf9f4afe6a669a9e3d6`.
- `source-map.json` records module provenance and adaptations;
  `sql-map.json` records the exact versioned SQL identifier/file map.
- `reference/` contains source SQL for review, not application migrations.
- The original Team branch, backup checkout and Runtime checkout are preserved.
  This is a module port, not an `ours` merge of the source history.

## Implemented compatibility boundary

The new control metadata uses `system_backup_v2_*`. Historical Team SQL and
unversioned control records are retained. The appended migrations do not select
or start a new engine. The installation selector defaults to `legacy`.

The existing Team maintenance gate supports both engine selectors through
`BeginForEngine`; the versioned controller's source gate is **not yet wired to
that gate**. Its capture activation remains disabled. The shared primitive checks
engine selection under the same authority transaction before closing admission. Switching
requires an idle gate, no unfinished tasks/participants, no outstanding mutation
leases, and no unresolved provider writes or unconfirmed restore executions.
Time expiry alone does not establish that a writer stopped. The selection API is
internal and has no public activation endpoint.

The task-claim adapter now provides `BeginVersionedCapture`,
`HoldVersionedCapture` and `ResolveVersionedCapture` against this shared gate.
It rejects stale task claims and recovers the same acquisition after response
loss. The watchdog cannot reopen v2 work based on a missing legacy capture plan.
This is a tested adapter, not a composed scheduler or remote recovery service.
See the root `BACKUP_TEAM_INTEGRATION_HANDOFF.md` for implementation status and
the remaining execution work.

Schema migration and capture share the historical migration lock plus the
connection-owned backup exclusion. Failed/uncertain lock cleanup discards the
physical connection. A backup-fork unversioned schema is rejected **before DDL**;
the `system-backup-import` command converts only a `cm_import_<32hex>` isolated copy whose full 122-table source structure and 136-file historical ledger match the embedded reviewed profile. It preserves every original row/identifier and ledger entry, journals atomic table renames, resumes interruption and independently compares original-column row hashes after migration. Unknown columns, active work and normal database names are rejected. It never imports an original live installation in place.

Skill materialization joins canceled work before admitting a replacement run,
returns acknowledged unstarted claims, and retains the existing backup work-unit
boundary through child completion. A stop timeout reports an unconfirmed drain.
An initial admission refusal defers backfill until the gate reopens; successful
admission still performs that backfill only once. The source mutation registry
defaults to Team's work boundary here, not a bypass when no v2 gate is installed.
This is not proof that remote Runtime tools or all source writers are quiescent.

## Optional security components

- Login/refresh/logout recording is opt-in via
  `SYSTEM_BACKUP_READ_SESSIONS_ENABLED=true`. Its independent pool configures UTC
  on each physical connection and cannot start an isolated restore as business.
  Disabled mode preserves normal application authentication. Session enrollment
  failure withholds credentials; read authority never grants operate authority.
- `clawmanager-secret-broker` is a separate optional binary. Default application
  behavior uses direct Secrets. Broker selection requires the explicit
  `CLAWMANAGER_SECRET_BROKER_MIGRATION_COMPLETE=true` cutover plus a pinned HTTPS
  endpoint/token. After cutover, a broker fault does not fall back to direct RBAC.
- Namespace policy follows `Client.GetNamespace`: `<prefix>-user-<id>`, with
  canonical prefix validation. Team creation has a create-only operation: a
  retry cannot rotate an existing bus token or adopt another Team's Secret.
- This branch does not deploy a broker, change cluster RBAC or install grants.
  Those need their own real-environment acceptance before cutover.

## Bounded local checks

The driver only accepts a running local `mysql:8.4` container labeled
`codex.task=backup-team-integration`, bound exclusively to loopback with disposable
test credentials. It cannot target a server database by URL.

```powershell
python e2e/backup-team-integration/check.py --stage import --mysql-container <owned-local-mysql>
python e2e/backup-team-integration/check.py --stage schema --mysql-container <owned-local-mysql>
python e2e/backup-team-integration/check.py --stage control --mysql-container <owned-local-mysql>
python e2e/backup-team-integration/check.py --stage data --mysql-container <owned-local-mysql>
python e2e/backup-team-integration/check.py --stage storage --mysql-container <owned-local-mysql>
python scripts/backup-team-catalog.py --check
```

Run these stages serially: migration and capture intentionally exclude one another.
The schema stage replays the exact Team baseline before the additive upgrade.
The storage stage creates three uniquely labeled temporary containers from cached
images, uses fresh in-memory object credentials and removes only those exact IDs
after ownership checks. Required skipped/missing/timed-out tests fail a stage.
JSON receipts and raw logs stay under the ignored local evidence directory.

The data pipeline checks cover real SQL, Redis, objects and files; their Kubernetes
boundary is controlled, not a live cluster. Browser workbench tests simulate API
and model responses. Neither establishes live model, cluster, v2 API, final image
or deployment acceptance. Source libraries' opt-in tests may skip without their
own environments; ordinary `go test ./...` is not proof those tests ran.

## Remaining activation gates

1. Full writer inventory and one production controller adapter; actual remote
   quiescence, exit/UID evidence, fencing and bounded business recovery.
2. Current Team/Gateway/Skill/object coverage in the v2 registry and readers. Its
   source draft is not upgraded merely by updating a SQL catalog hash.
3. Durable dispatch, actual runner, full control/health views and independent
   restore verification. Transaction-owned backup/preflight submission and their
   persisted detail projections are implemented; this does not satisfy execution.
4. Real auth/grant/TLS/Broker/download deployment acceptance.
5. Final image, real-environment closure, compatible rollback and cleanup receipts.

Keep v2 disabled until all applicable gates pass. Never substitute fixture
responses, omit unknown columns or remove a `not_ready` guard to meet a checklist.

## Application and tool wiring

The existing `/admin/backups` Team-data page and its production API remain the
entry point. Its system-task link uses the existing working Store/controller at
`/admin/backups/system`; task links retain their original IDs. The control-history
page is `/admin/backups/records`, with source translations for all five locales.
Demo data requires an explicit switch and never executes operations.

Versioned HTTP records are opt-in through `SYSTEM_BACKUP_READ_LIVE_ENABLED=true`,
with the source deployment-pinned read authority, independent UTC/session pool and
cursor key. No fixture HTTP fallback is registered. Existing admin checks still
apply; read permission does not confer operation authority. New record routes
retain maintenance-time access using an explicit registered method/path allowlist;
unknown suffixes do not bypass the gate. The composed transaction-owned
writer uses a deployment-owned execution profile and capacity report, with a
fresh readiness receipt required for each task type/config/profile. Missing
dependencies return `not_ready` without leaving a task. Detail queries use actual
SQL records; no test adapter is installed.

Docker includes distinct migrate/import/bootstrap/registration/grant/audit tools,
the optional Secret Broker and a separately named `system-backup-v2-controller`.
The original controller binary is retained. The versioned controller has a new,
explicit `SYSTEM_BACKUP_V2_CONTROL_PLANE_ENABLED` opt-in and refuses capture
activation because the production runner and shared-gate composition are absent. The
legacy `SYSTEM_BACKUP_ENABLED` flag cannot accidentally activate it.

The standalone migration tool pins server UUID, database and the exact current
catalog on the same connection holding both migration locks; it does not enroll
config, run business processes or activate backup work. Historical review inputs
are provenance only, never permission to replay unknown SQL. Business connections
reject both `cm_restore_<32hex>` and `cm_import_<32hex>` isolated targets.

Necessary local regression results and boundaries are recorded in `validation.json`.
These results do not assert full v2 execution, real-cluster recovery, an image
publication or a deployment. Activation gates above remain explicit.

The next local phase adds a durable SQL execution queue, claim-bound encrypted
plans, and persisted single-send Job intents. The shared Team gate adapter is
implemented but not yet called by a production execution loop. Job response-loss
tests use real MySQL and a simulated Kubernetes boundary; they do not validate
an actual capture or restore Job. See `../../BACKUP_TEAM_INTEGRATION_HANDOFF.md`
for the paused implementation status and remaining execution work.
