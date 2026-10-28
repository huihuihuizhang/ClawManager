# Public capture deployment contract

Current implementation is **public-v1 / platform-workspace / functional_test**.
The source inventory must contain zero runtime instances. This is a real
controller/Job/source-recovery path, not full-system backup or restore readiness.
Do not enable acceptance or advertise six-domain coverage from these checks.

## Separate database roles

Use the existing administrator installation account to review and apply output:

```sh
system-backup-controller-grants --public-capture --schema <schema> --user <dedicated-controller> --host <exact-host>
```

This only renders SQL; it does not create accounts/passwords or execute grants.
Wildcard hosts require explicit `--allow-any-host`. The role has exact control
table grants only, no business table access, config updates, immutable-record
updates, deletes or DDL. Its positive and negative native test includes actual
denial of users/config writes, record deletion and table creation. Source
inventory uses a separate direct SELECT-only users/instances account. Capacity
measurement has its own SELECT-only account and complete declared control-table
inventory. Neither source nor capacity credentials belong in the control role.

Public controller startup uses `ConnectPublicBackupMetadata`: an independent
UTC pool, no migration/business initialization/global Session assignment, with
mandatory exact-grant admission. It is not the business SQL writer. It can record
recovery while `SYSTEM_BACKUP_SQL_GATE_SCOPE=installation` holds the business
gate. All ordinary business/read/operate connection paths retain that fencing.

## Explicit deployment inputs

Start `/usr/local/bin/system-backup-v2-controller` with controller and v2 control
plane explicitly enabled and `SYSTEM_BACKUP_EXECUTION_PROTOCOL=public-v1`.
Public and legacy controller modes are exclusive. Supply:

- `SYSTEM_BACKUP_PUBLIC_CONFIG_FILE` and `SYSTEM_BACKUP_PUBLIC_CONFIG_SHA256`.
- `SYSTEM_BACKUP_FORWARD_GRANT_SHA256` and `SYSTEM_BACKUP_RECOVERY_GRANT_SHA256`.
- Existing dedicated control DB environment and actual controller Pod identity.
- Separate mounted forward/recovery signed grants, pinned profile, key versions,
  source DSN, fresh capacity report, TLS issuer/server files and staging claim.

The JSON contract is `systembackupexecution.DeploymentConfig`. It binds namespace,
actual UID, trust domain, original source deployment UIDs, worker image digest,
service-account/node/volume identities, limits and signed file paths. Both grants
bind its SHA; their own SHA pins remain outside that JSON to avoid a hash cycle.
Private files require Linux owner-only access. The control listener requires
verified client certificates and TLS 1.3. No development key/DSN is shipped here.

Readiness is published only by the actual elected Pod UID, with fenced SQL
publisher generation and five-second freshness. Forward/recovery materials,
source scope, actual SQL grants, registered writers, namespace and effective
config are rechecked. An unresolved failed execution suppresses new readiness;
empty polling does not clear it. Recovery scheduling remains independent of that
readiness flag. A health listener alone is not backup capability.

## Current material and acceptance boundaries

Retain original signed deployment/profile/key metadata for recovery; disabling
new submissions must not delete original journals, snapshots or recovery keys.
Runtime capture, full registry approvals, formal artifact finalization, remote
providers and independent restore are not installed by this contract. There is
no safe full-system production switch or rollback acceptance yet. Native minimum
grants/real-binary tests still used a synthetic capacity feed at this checkpoint;
the physical data-volume collector has a separate entry. The subsequent native
`--physical-capacity` acceptance connects it to the production entry: actual
MySQL UID, exact SELECT-only account, actual auto.cnf/server UUID, complete live
control-table inventory, Statfs and an unmodified fresh report. The small local
fixture uses a two GiB tmpfs and an explicitly configured one GiB metadata budget;
this is not a production storage durability or full-domain capacity certificate.

## Independent recovery restart

Pin `issuer_certificate_sha256` in the signed deployment JSON. A valid independent
recovery grant with exactly `recover` is required before loading forward inputs.
Missing or expired forward material selects recovery-only mode: no source DSN,
issuer private key, server private key, issuing listener or new-work readiness.
Original frozen writer/Job/Secret identities and original journal/key metadata
remain required; a missing recovery grant fails closed. Recovery never reissues
a worker credential or adopts a same-name replacement Secret.

Native production acceptance removes forward/source/private-key files, restarts
the real controller, waits for the original lease to expire, proves original
collector exit/source resume and ends the original task failed/idle. This is
recovery acceptance, not successful publication or isolated restore.

## Canceling sealed, unpublished work

An authorized cancel may close a validating capture only after the original
collector exit and every original writer resume are durably verified, with one
sealed capture attempt and no publication actions, artifact references or remote
effects. It preserves encrypted staging and sealed history. It never touches
the current source gate, re-captures source data, deletes data or claims a
successful backup. Publishing/unknown-result work is not accepted on this path.

## Durable blocked-recovery diagnostics

After an execution returns without conclusive cleanup, the exact live claim may
record one redacted `diagnostic.d.recovery_blocked` event. Repeated reconciliation
does not spam events; stale claims cannot report for newer or terminal work.
This is an observed failure, never exit proof, a gate release or a completed
backup. The control account needs SELECT+INSERT on events for atomic deduplication.

## Worker image and source exit watches

Build the `backup-worker` target from the root Dockerfile. Its only payload is
`/backup-worker`, statically built from the same backend source as the app and
controller. Pin the actual loaded/registry digest in deployment inputs. The
worker has no shell, app server or baked-in credential. Job-level filesystem
identity/capabilities remain explicit and are checked against the original spec.

Ordinary Kubernetes requests retain their ten-second timeout. Exit watches use
a separate client without a global HTTP timeout and the existing bounded
two-minute witness context. A real thirteen-second preStop passed with the
final scratch worker. Watch timeout/disconnection still cannot prove exit.

`backup-public-native.py --worker-image <cm-backup-worker:tag>` records/uses the
exact loaded digest. `--controller-image <cm-backup-app:tag>` extracts the exact
controller binary and records its image ID and binary SHA. These flags target
only explicitly owned local fixtures and do not install shared-cluster material.

## Minimum Kubernetes grants

Render RBAC from the signed deployment (no cluster mutation or credential output):

```sh
system-backup-controller-grants --kubernetes-config /absolute/deployment.json --kubernetes-config-sha256 <sha256> --controller-service-account <controller-sa>
```

SQL and Kubernetes modes are exclusive. Pre-create a dedicated controller SA,
different from the worker SA. Review/apply the returned List as installation
administrator; the controller receives no role-management permission.

Dynamic Jobs/identity Secrets/ConfigMaps are restricted to the dedicated capture
namespace. Source namespaces get only Pod observation, ReplicaSet/HPA listing
and GET/PATCH of the exact frozen Deployment names. Nodes, namespace, PVCs/PVs
and worker SA are named; no wildcard, exec/log, source Secret listing, source
lifecycle creation/deletion or node proxy permission is granted. A shared
namespace still shares its Secret-read scope: use a dedicated capture namespace.

Current SelfSubjectAccessReview checks gate forward readiness/Prepare. Recovery
has separate explicit admission and original authority; removing create rights
must not block original cleanup. Native acceptance temporarily removes the old
broad fixture role, exercises actual minimum access and denied operations, then
restores only those fixture rules before cleanup. No shared-cluster grant changes.
