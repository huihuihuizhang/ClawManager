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
