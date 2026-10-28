# Transactional task admission and original-execution cancellation

This is an implemented part of the integration, not capture/restore acceptance.
An explicitly pinned public-v1 platform-workspace functional production runner now publishes matching readiness. Full backup remains unavailable; do not manufacture readiness or update database flags. See public-capture-deployment.md and the root M3/M4 handoff for the current accepted boundary. The foundation sections below record earlier stages.

## Production composition

The opt-in live records composition retains its pinned login session/RBAC checks.
`SYSTEM_BACKUP_EXECUTION_PROFILE_FILE` selects a closed deployment-owned JSON
profile (installation, revision, source orchestrator/profile, target class/risks,
failure domain and immutable restore-target reference/hash).
`SYSTEM_BACKUP_CAPACITY_REPORT_FILE` supplies the same database-identity-pinned
capacity report used by registration. Neither file contains browser credentials.
An absent or invalid profile disables new submission. Authorized reads and safe
unstarted cancellation remain available, using their independent control-capacity
report. Invalid capture configuration must not remove recovery/history routes.

Creation supports POST `/api/v1/admin/system-backups` and
`/api/v1/admin/system-backup-preflights`. Request shapes are linked from the
OpenAPI contract. Operator authority is checked in the same SQL transaction as
the task, original configuration snapshot, execution input and admission event.
The task's `next_reconcile_at` is the durable scheduling input, not an in-memory
queue. Execution readiness must match task type, profile hash and config version,
must use database time and must expire within sixty seconds.

The same actor/endpoint/idempotency key and normalized request return the original
task, even if readiness subsequently disappears. A different request conflicts.
The transaction rejects disabled/mismatched configuration, insufficient capacity,
an unsafe acceptance target, unsupported source artifacts and missing readiness.
It never creates a task solely to display a permanently pending operation.
Metadata reservations share the monotonic registration ledger; rollback rolls
back the reservation, and a new capacity sample never silently resets it.

## Reads and cancellation

Backup/preflight detail reads use the existing authorized snapshot/final authority
recheck. Pending work has no execution/checksum/consistency evidence. Recorded
success is not a fresh provider-health check; `acceptance_ready` stays false until
the independent availability composition is implemented. Manual-hold free text
and actor are explicitly redacted. Historical legacy IDs keep their old reader.

POST `{}` to the backup/preflight `/{id}/cancel` endpoint accepts an idempotency
key and returns the actual operation. Only a pending task with no controller
owner, attempt, external action or artifact lease can be canceled here. Even an
expired controller lease blocks this operation. Running cancellation requires the
runner's stop/restore protocol and is not implemented by rewriting a status.
Configuration being disabled does not itself prohibit safe cancellation.

Task transition, operation and event commit together; a failed audit write rolls
all three back. The route remains reachable through maintenance middleware, but
the handler still checks operation authority and the execution evidence. The UI
retains the original request key across uncertain retries, checks the complete
live response and offers this action only for a pending, unstarted live detail.

## Verification and boundaries

Targeted tests exercise real disposable MySQL with the full migration catalog,
concurrent same-key submission, request conflicts, audit rollback, readiness
loss, real HTTP session/RBAC authorization and persisted detail reads. The
readiness receipt in these tests is explicitly synthetic; these tests do not
execute a capture Job. Cancellation tests cover viewer denial, expired-claim
refusal, audit rollback and exact replay. Frontend transport tests reject fixture,
cross-installation, mismatched-key and unconfirmed responses.

The new readiness and execution-input tables are installation-local authority.
They are classified as metadata/reference-only in the legacy backup registry;
restoring a business backup must not replay their queued work or readiness.

## Shared gate adapter and remaining composition

`systembackup.Gate.BeginVersionedCapture` and `HoldVersionedCapture` use the
existing Team gate, not a second `system_backup_v2_maintenance_locks` authority.
They verify installation, admitted task inputs, controller owner, row version,
lease and deadline. The live claim is rechecked inside the gate transition
transaction; an old controller cannot proceed after takeover. Expired writer
leases still block capture until the writers explicitly stop.

`ResolveVersionedCapture` finds the original gate generation after a lost
response without extending deadlines or acquiring a replacement generation.
The legacy watchdog fences an expired v2 gate but cannot reopen application
writes if a v2 attempt, Job observation or external action exists. A missing
legacy capture plan is not evidence of v2 collector exit.

Real MySQL tests verify this adapter and the unchanged legacy gate behavior.
Historical foundation tests used synthetic controller transitions. Current production public-v1 scheduling calls these methods; its native acceptance is recorded in the root M3/M4 execution report. Remote participant pause/resume, actual collector stop
verification and versioned recovery/release composition remain required. Do
not publish readiness or enable capture based on these library tests.

## Durable execution foundation (historical foundation boundary)

`SQLExecutionQueue` claims admitted work once and detects takeover that requires
recovery instead of automatically starting a second execution. `PlanStore`
persists immutable AES-GCM plans bound to the task, installation, configuration,
profile and encryption key version. Keys remain outside SQL.

`JobDriver.Ensure` records an attempt and send intent before the API call. After
an uncertain send it only looks up the original Job and checks its specification
and actual UID; it does not resend or accept a same-name replacement. An unresolved
intent remains blocked until the still-required recovery implementation can
establish what happened. This is deliberately not a full execution state machine.

The current phase verifies concurrent claims, takeover, input/plan tampering and
lost Job responses with real MySQL. Kubernetes calls are simulated for this
failure boundary. Production scheduling, authenticated Job observation, original stop/recovery and workspace functional capture are now composed. Formal publication and independent restore remain unimplemented in this path; only the bounded functional readiness may be published.
