# JointEight public-worker native evidence - 2026-11-02

This delta adds exactly four Go test files. No production file, existing test,
module, migration, shared database, or external service changes. It exercises
one ordinary local encrypted SQL/object data-plane cohort containing all eight
nonempty owners: gateway_keys, gateway_key_budget_reservations,
gateway_key_budget_ledger, gateway_image_artifacts, gateway_image_jobs,
northbound_admin_settings, northbound_settings_audit, northbound_owner_records.

Parent is 8197c591b0b6c7fa205836d6c8f69d1caec59381. Apply only this commit's
four-test-and-evidence delta. Never merge owner ancestry: held175 is outside
this delivery. The receiver must preserve its four baseline MySQL interpolation
lines. Our executed worker is this owner's unchanged parent version; independent
validation on the receiver's latest composition remains separate.

## What the native test actually does

The source uses actual current trusted image072/073/074 and Northbound migrations,
one shared core and actual budget/image/Northbound producers. Instance8 is created
and deleted once, after both owner/image histories exist. Real owner Bind/Apply,
repository CAS, deleted-actor SET NULL, artifact Save/Load/Finish/Settle/expiry/GC,
raw audit bodies, unsigned64/DECIMAL/NULL/bitmap boundaries feed the SAME source.

Public RunDatabase capture seals one SQL file containing all eight nonempty
owners. Authenticated AEAD/gzip/EOF decoding equals an independent SQL capture.
Actual immutable-version image GET/hash/GCM is bound to that complete source
digest. SQL source accounts and SDK source/operator capabilities are revoked
before target work. Original encrypted source SQL is authenticated again at end
and compared unchanged, including original unredacted audit data.

Four independently provisioned targets receive trusted DDL and bootstrap ID1;
source ID1 reuse and observed target settings version5 are deliberate. Each gets
distinct SDK writer/reader credentials and a new bucket on the SAME signed TLS
object realm. Actual SDK PUT/version/GET/hash/GCM creates the opaque image receipt.
One public restore invocation receives both that receipt and the actual separate
Northbound target observation, then writes all eight owners in its common TX.

Before evidence, the separate administrator queries actual InnoDB transactions
joined to the writer's physical PROCESSLIST entry: exactly one TX and at least
eight modified rows are required. GLOBAL Com_commit is measured directly around
the isolated public restore, after observations and before other DDL/child work.
The passing assertions establish delta1 on success and delta0 on all negatives.
The log does not print absolute counters or exact modified-row counts; none are
invented here. Changed-source rejection never reaches the custody observation.

Actual staging.WriteUnpublishedFile durably writes the image receipt descriptor
before SQL COMMIT. A closed own os.Root causes the real custody I/O failure.
Cancellation retains and hash-checks the actual unaccepted descriptor. Failed
targets are compared across the complete pre/post SQL snapshot, including core,
bootstrap/settings and every eight-owner cell. A separate real version-list and
fixed-version GET/hash/GCM inventory proves the one owned object version remains
identical until fixture teardown. SQL rollback does not pretend to delete it.

Successful target comparison covers every raw cell with only the named existing
quarantine/redaction transformations. A fresh process receives only actual
encrypted files/descriptors, DEK and new read-only credentials, without previous
receipt/observation/CAS/source/writer pointers. It authenticates SQL and image
metadata, reads every SQL cell through restrictive actual grants, and proves
actual MySQL1142 for image and Northbound UPDATE attempts. Admin identity checks
are fixture custody, not proof of production isolation.

The second child receives a valid changed Northbound expected file and matching
SQL descriptor in valid image AEAD, while the full expected digest remains old.
It must reach the public before-verify boundary and reject. The administrator
observes the SAME reader physical session before/after; SHOW SESSION Com_select
is unchanged across public verification. This proves zero target SELECT delta,
not zero protocol I/O. Positive child requires a positive SELECT delta. Reader
Ping/SHOW and separate administrator queries are not disguised as no I/O.

## Actual runs, including original failure

| Run | Actual handle | Natural exit | Observed result |
| --- | --- | --- | --- |
| Initial SQL-off typecheck | 19544 | 0 | package2.542s; native and child both SKIP; no runtime proof |
| First build | 82779 | 0 | binary6900b4fa...f388; original four source pins |
| First native | null (short command naturally completed) | 1 | 2.37s FAIL before targets; actual3159 passed; original source revocation assertion failed |
| Necessary SDK probe | 60884 | 0 | package2.537s; actual GET/PUT403 SignatureDoesNotMatch, old HEAD403 AccessDenied |
| Corrected build | 37127 | 0 | binary4127dd2e...a1ec6; only export test changed |
| Corrected full native | 65591 | 0 | 13.03s; four targets and both fresh children PASS; zero SKIP |

The first failure is retained as native-v1-native.log with its original binary,
source scope, final state and cleanup evidence. Stat() used HEAD, whose error body
is absent, so the SDK exposed AccessDenied despite the fixture's signature error.
The correction uses actual fixed-version GET reading and strictly requires both
HTTP403 and SignatureDoesNotMatch for GET and operator PUT. The tiny SQL-off probe
records the original HEAD behavior too. No production or existing helper changes,
no acceptance of arbitrary network failures. The only source difference between
first and second native runs is original-v1-export.go.txt versus current export
test, recorded in v1-to-v2-fixture.diff. Other three files and13 dependencies match.

| Corrected native target | TX at custody | COMMIT delta | SQL/object assertion |
| --- | --- | --- | --- |
| success (2.87s) | exactly1, modified>=8 | 1 | all8 nonempty, every raw cell, real persisted descriptor, fresh positive child0.25s |
| evidence-custody-failure (2.43s) | exactly1, modified>=8 | 0 | closed-root real I/O failure after seals; full SQL rollback; one identical object version retained |
| cancel-before-commit (2.09s) | exactly1, modified>=8 | 0 | reaches commit callback then cancels; durable unaccepted descriptor; full SQL rollback; same version retained |
| changed-Northbound-source (2.11s) | custody not reached | 0 | changed complete source digest, identical image-only projection; old receipt refuses before evidence; full SQL unchanged; same version retained |

Within success, changed-Northbound-expected-with-matching-descriptor (0.24s)
includes a separate negative child0.07s, strict full-digest refusal before target
SELECT, same physical session/Com_select equality and actual1142. A source
settings signed-max-to41 change normalizes to the same target6; a target owner
unsigned-max bitmap-to0 change preserves the image-only projection. These are
cross-domain full-digest counterexamples, not malformed-file/parser failures.

## Isolated SQL identity and cleanup

Both attempts used fresh ASCII roots, unused loopback ports, new datadirs and
the same locally copied read-only MySQL8.4.13 binaries. SANs contain127.0.0.1 and
gateway-restore-native.local. CLI used VERIFY_IDENTITY; Go used pinned CA/DNS TLS;
require_secure_transport rejected actual plaintext login with3159. Locked source
and writer accounts really rejected fresh logins with3118. Read-only child SQL
accounts rejected actual zero-row UPDATE with1142.

| Attempt | Port | Hidden PID | Server UUID | Binary SHA256 |
| --- | --- | --- | --- | --- |
| v1 eed55aa7... | 50441 | 24732 | 9b3b9641-d62f-11f1-b8cb-745d22085e06 | 6900b4fa0f00c127d46ab472cef2dfd008312d45e244b00abd78d68b6424f388 |
| v2 335a12ca... | 61701 | 19856 | ba2e1703-d630-11f1-8d7f-745d22085e06 | 4127dd2e39e346d4231625b150d455dd9ae7c2f24dce0d5e1b21b1fbee0a1ec6 |

front_session is null for both actual hidden SQL processes; these are actual
PIDs, not invented foreground handles. Exact roots/nonces/CA hashes/copied binary
pins appear in final-state files. Before shutdown, each exact UUID/PID/executable/
command-line/nonce/CA/path boundary was rechecked. Census contained only the four
system schemas, three locked mysql.* accounts and initial root, other sessions0.
mysqladmin with transport-only TLS flags acknowledged normal shutdown, the same
PID exited naturally and the exact own temporary root was removed. Initializer
and shutdown logs plus public CAs are retained. No private key/datadir/credentials
are committed. The helper and reviewed script are inert evidence snapshots.

Builds and native runs used GOMAXPROCS2, build-p1, GOTOOLCHAINlocal and
GOPROXY/GOSUMDBoff, local module/cache paths. Native binary cwd was
backend/internal/systembackup/domain for trusted migration paths. Exact entry:
-test.run=^TestJointEightPublicWorkerActualTLSMySQL$ -test.v -test.timeout=4m.
Successful builds emitted no stdout/stderr, so no raw build log is fabricated.
One extra Python read-only certificate check initially decoded a UTF8 pointer
using Windows default encoding and failed before reading the certificate; the
explicit UTF8 retry verified CA signature and both SANs. This was not a SQL/TLS
startup failure; its limitation is retained in certificate-preflight JSON.

## Scope limits and hashes

This is one ordinary local eight-table data-plane cohort. It does not qualify
formal fullC/SourceVerified authority, source IAM, native deployed S3/MinIO,
all-consumer physical isolation, production full175, activation, or the original
nine-table resources writer. The object endpoint is a real local TLS/SigV4 SDK
protocol fixture. Publicadapter.NewRestoreRunner remains unavailable as before.

scope.json lists exactly four sources and every evidence file with raw byte
length/SHA256, Git-normalized byte length/SHA256 and actual expected Git blob.
Original CRLF evidence is distinguished from committed LF. Historical source
scope files retain their original pre-run status strings and are not rewritten
as runtime claims. validation.json describes the final observed results. Native
passing assertions prove the stated equalities/bounds; unlogged counter values,
version strings and rows are not reconstructed or fabricated. No Go/SQL reruns
followed the final passing run.
