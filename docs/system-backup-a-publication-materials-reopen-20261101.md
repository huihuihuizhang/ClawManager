# Original publication materials and process reopen

Private original request, exact v2 presigned PUT set and ephemeral mTLS
identity are durably stored in one immutable native Secret BEFORE original
121 sending. Original diagnostic evidence contains only hashes, coordinates,
actual observed Secret UID, actual claim receipt fields and the fixed original
deadline. No grants, request bytes or TLS private key enter SQL/evidence.
Native payloads are bounded to fit the Secret API without truncation.

An existing material intent selects GET of its original Secret and bytes before
any new issuance. Missing after intent remains unknown; no Secret/Job/grant or
CA key is regenerated. The exact original request bytes are checked against
their pin and deterministic reconstruction. All API deadlines are bounded by
both original material expiry and fresh current publisher authority. A new
actual task claim cannot extend an expired original material deadline.
If original 121 already exists without material intent, recovery refuses before
new candidate/key creation or issuance. New material/Job sends also require the
task's original cancelable state and a NULL commit_started_at.

After original 121 binds the actual suspended Job, a separate immutable owner
intent precedes Secret metadata update. The original Secret UID/resourceVersion,
unchanged whole body and exact batch/v1 Job owner are checked. ACK loss resolves
by GET; absent ownership after an unknown update is not permission to update
again. Owner-bound restart checks original 121 namespace/UID/spec and native Job
generation; foreign or additional owners and replacement same-name UIDs fail.
Secret update is added to shared generated RBAC/readiness only when the explicit
publication worker is configured, only in the dedicated backup namespace.
The controller checks original ownership/UID/body before that metadata-only API
call. Capture/source permissions and worker role subjects are unchanged.

Actual local UUID-pinned MySQL 59355 plus named native Kubernetes fixtures:

- Two separate OS child-process reopens reconstruct a new service/factory from
  original files/SQL. The native API bridge permits GET only. The child opens no
  CA private signer and is passed no old in-memory request or capability bytes.
  Both original 121 sending-before-107 and Job-owner-bound restart retain exact
  request/grant/body hashes, Secret/Job UIDs and expiry, with one native create
  each. Its transport uses the existing production controller's 50 QPS/100 burst
  and 10s timeout; no permission check or original window is skipped.
- Twelve fault modes cover actual Secret/owner-update lost ACKs and absence,
  UID/body/foreign/extra-owner drift, update 403, actual Release with NULL owner
  and advanced row version, missing material intent after 121, and real expiry
  followed by a real new AcquireWithReceipt. Positive recovery works without a
  CA signer. Native/SQL one-send and private-byte exclusion assertions remain on.
- Original ten 121 cases, four issuer/current-claim identity cases and generated
  RBAC/readiness checks were included in the combined PASS 139.052s run.
  This run preceded the preparation-open guard. Post-commit refusal, two child
  reopens and original ten 121 cases passed 59.800s with that guard. Full
  execution/worker command packages passed 9.301/5.075s before syncing 975d2cec.
- Independent supervisor review passed the earlier frozen two-process/twelve-
  fault version in 93.855s and execution/worker packages in 8.439/4.416s.
  Current RBAC inventory/denied-readiness checks independently passed 3.476s.
  The supervisor has not independently rerun the later preparation-open guard.
  The requested full rerun after syncing 975d2cec was not executed: automatic
  approval review could not complete because its usage allowance was exhausted.

Logs in the shared workspace parent's `.tools`:
`a-publication-material-combined-final.log`,
`a-publication-material-dispatch-commit-guard.log`,
`a-publication-material-process-reopen-v1.log` (retained initial default-client
throttle failure), and `a-publication-material-process-reopen-v2.log`.

These fixtures use one real original workspace C and inert index/minimal manifest
DATA. They are material/transport recovery evidence, not complete six-domain
assembly, online Kubernetes/provider admission, source-independent DR, original
107 reception, actual unsuspend or final publication. Those production stages,
cleanup and three-purpose signatures/catalog finalization remain required.
