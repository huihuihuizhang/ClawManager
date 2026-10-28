# Transactional task admission and safe unstarted cancellation

This is an implemented part of the integration, not capture/restore acceptance.
No production runner currently publishes readiness; do not manufacture a receipt
or update database flags to activate task submission.

## Production composition

The opt-in live records composition retains its pinned login session/RBAC checks.
`SYSTEM_BACKUP_EXECUTION_PROFILE_FILE` selects a closed deployment-owned JSON
profile (installation, revision, source orchestrator/profile, target class/risks,
failure domain and immutable restore-target reference/hash).
`SYSTEM_BACKUP_CAPACITY_REPORT_FILE` supplies the same database-identity-pinned
capacity report used by registration. Neither file contains browser credentials.
An absent profile leaves reads available and refuses new submission. An invalid
profile refuses the composed task application.

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
