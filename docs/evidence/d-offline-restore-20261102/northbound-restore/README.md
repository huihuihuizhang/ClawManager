# Northbound three-table restore candidate — 2026-11-02

This batch implements the ordinary local encrypted SQL data plane for current
`northbound_admin_settings` (35 columns), `northbound_settings_audit` (6), and
`northbound_owner_records` (56). It contains exactly 14 Go files: 7 production
files and 7 test files. Only three existing production files change:
`domain/normalize.go`, `domain/restore.go`, and `worker/database.go`.

Parent: `87ff105458aae4cabee143624c638f9556d8d7fb`. Review/apply this single
commit's delta only. Do not merge this worktree's ancestry: its earlier held175
migration and prior component commits are outside this batch. Primary's existing
four MySQL interpolation lines must be retained when composing this delta.

## Actual write path

The new resources bridge observes the actual database/UUID/UTC session, entire
target settings row, empty audit table and bootstrap administrator IDs in a
read-only RR transaction. These observations and policy declarations do not
grant source authority, SELECT-only IAM or physical isolation.

`BeginNorthboundRestoreTransaction` owns the one common SERIALIZABLE transaction.
Its privately bound observation cannot be used with an arbitrary external
transaction. `PrepareNorthboundRestoreInTransaction` locks current settings and
audit ranges and compares the entire original target row, including changes
without a version increment. It measures source rows/bytes before copying,
freezes original settings/audit/bindings, obtains real target JSON rendering and
reuses the unchanged private settings/audit normalizers. `MatchesSource` checks
original audit bodies, so different bodies that redact identically still fail.

The original common quota DELETE remains first. A narrowly scoped bridge helper
then performs the actual users DELETE, checks affected rows and the full actual
SET NULL transition, and records a private executed marker. Merely changing an
actor to NULL cannot manufacture that marker. This permits the source admin to
be reinserted with the same ID as the deleted bootstrap admin.

At the settings node of normal FK order, `ApplyNorthboundSettingsCAS` replaces
generic INSERT. It checks the same TX/target, current entire row and empty audit
range, executes INSERT for observed absence or CAS UPDATE against the observed
version, requires affected rows=1, and compares all actual settings cells. The
target version is actual observed+1 (absence→1), never source version+1. API and
owner teams are disabled, explicit callers required, target port/limits/types
remain declarations requiring external review. No audit event is fabricated;
source updates without an audit row remain legal. Audit/owner rows share the
common TX, and final current settings/audit readback precedes common COMMIT.

Original audit JSON remains in the authenticated encrypted source archive.
Target audit uses the existing private owner redaction rule for every non-NULL
before/after body, while SQL NULL, IDs, actors, actions and timestamps remain
literal. Owner records preserve all original 56 cells: unsigned64 identities and
counters, scope/version0, bitmap version, exact DECIMAL/NULLs, private JSON and
case-significant keys. Their intentionally absent account/instance FKs are not
invented by a generic relationship validator. Store/Current/SaveSettings are
never called to restore or verify target rows.

## Observed validation, with original failures retained

All source versions, actual binary SHA-256s, original logs, Git-content hashes
and test-only diffs appear in `scope.json` and accompanying artifacts. All seven
production files are unchanged across the following runs.

- SQL-off handle `79504`, natural exit0: resources 3 PASS / 0.680s; domain 3
  PASS / 2.564s; worker 1 PASS / 2.938s. Native and child explicitly SKIP.
- Setup failures are retained separately: garbled script paths, missing `go run`
  subcommand, rejected CLI flag, and wrong binary cwd. They are not restore
  business-regression results.
- First actual source-producer run: native FAIL / 1.76s, because real
  `InstanceRepository.Delete` needed trusted migration066 absent from the tiny
  fixture. V2 adds only that unchanged migration to the fixture.
- V2 handle `10305`, natural exit1, **overall FAIL / 24.53s**: eight scenarios
  PASS; absent-settings scenario failed its stale-CAS assertion. Actual absent
  INSERT had produced version1, so WHERE version=1 correctly updated it. V3
  changes only that scenario's probe to WHERE version=0.
- V3, natural exit0, **PASS / 7.16s**, only
  `TestNorthboundPublicWorkerActualTLSMySQL/success-absent-settings` rerun.
  Previously passing eight cases were not repeated. This is not a claim of a
  final single-run full-nine PASS.

The nine scenarios cover missing observation, same-version content drift,
version drift, evidence failure, cancellation, legal empty audit, heterogeneous
audit, absent target settings, and observed target version5→6. Source settings
version MAX(signed64) remains history. Real source repository CAS and actual
Store Bind/Apply/saved Report occur only before capture; actual instance deletion
retains owner history, and actual actor deletion produces audit SQL NULL.

Native schemas execute complete unchanged 057/058/066/067/077 migrations; the
shared fixture also executes unchanged gateway migrations. Core and empty
supporting teams/template/operations tables are explicitly small named fixtures,
not a full production release schema. Each positive case compares all 35/6/56
raw SQL cells; each then starts a new process with only the sealed expected SQL
and fresh SELECT-only SQL connection. Public verification checks restrictive
actual grants and complete raw rows, with real UPDATE denial1142. Source/writer
connections exit and real reauthentication denial3118 is checked. Changed owner
bitmap is rejected by expected-file verification.

Other real counterexamples include arbitrary READ COMMITTED TX, different TX or
UUID, original audit drift with identical redaction, and manual actor NULL.
Concurrent existing-settings CAS and audit INSERT in a second SQL session both
receive actual1205 while the common SERIALIZABLE TX holds locks. A separate
concurrent INSERT into an absent settings range before DML is reserved for
independent reviewer coverage; this batch does not claim it was exercised.

## Resource custody and limits

Fresh private TLS MySQL8.4.13: port62877, PID31928, UUID
`c3c5502d-d623-11f1-b899-745d22085e06`, nonce
`63d35aed9a52418b83ca82740a8db450`. It used a new private CA and an exact owned
ASCII temporary root. Front PTY session is null; the actual hidden process
identity and live TLS UUID/port were checked. Plaintext login actually failed
3159. Final census found only four system schemas, initialized accounts and zero
other sessions. Normal TLS mysqladmin shutdown was acknowledged; exact process
exited and exact root was removed. Two failed-setup marker-only roots were
nonce-checked and removed nonrecursively. Public CA and diagnostics are retained;
private TLS key/datadir are removed. No shared ports/SQL, remote service or
dependency download was used.

Go1.26.1, GOMAXPROCS2, package build parallelism1, existing offline module cache;
no module/dependency files change. New production dependencies are the existing
resources private normalizers/RowsAffected helper plus the existing ordinary
SQL/staging/worker path. Existing gateway/native test helpers are reused only by
tests. The old nine-table resources writer and its proof semantics are unchanged.

`bytes`/`raw_sha256` describe original local artifact bytes.
`committed_bytes`/`committed_sha256`/`git_blob` describe the Git copy, with explicit
CRLF→LF normalization where applicable. Earlier manifests retain their own
original execution version and are not silently rewritten as final-source pins.

Empty source settings remain refused: Current's API-enabled fallback cannot be
treated as an observed disabled singleton. Target absence is supported and
actually tested. Pure settings/audit Normalize requires the controlled prepared
candidate; this does not open the formal preflight/restore authority boundary.
Formal fullC source authentication, all-consumer physical target isolation,
full175 production qualification, activation and an all-eight-nonempty single
cohort remain unproven. The formal B runner still refuses unavailable source
authority. Primary latest-combination review/verification remains required.
