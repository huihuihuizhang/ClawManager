# Original capture certificate input producer

This component prepares the existing `public-c-crypto.v1` capture-certificate
payload from a complete, independently verified original capture. It is not yet
called by first-forward publication. The original component verification below
covers mapping/SQL facts. The later same-task health test separately covers an
actual capture certificate; remote publication, acceptance, catalog registration
and standalone DR remain incomplete.

## Original facts and transaction boundary

`publicationCertificateParts` requires the private complete-capture verification
receipt, all six requested domains and both control-evidence parts. It checks
each exact original checkpoint, including scope, invocation, ciphertext hash,
native Job UID and generation, before canonical checkpoint hashing. Original
linked build provenance and frozen source facts must validate; an `unknown`
commit is refused.

`prepareOriginalCaptureCertificate` binds the current original publisher, reads
the actual sealed capture attempt completion time and original normalized
certificate TTL, and consumes every capture/secret-capture resource row with a
current locking query. The current controlled-directory implementation requires
exactly one original ready hostpath resource. Unknown or extra rows are refused.
Its controller resource ID is not represented as a PVC UID. Physical marker and
HMAC checks run after releasing SQL; the next transaction checks the same facts.
There is no reconstructed capture Authority or new staging ledger.

The private `preparedPublicationCaptureCertificate` retains the original
publisher facts, complete-capture receipt, stage identity/MAC/key/lifecycle/row
version, capture completion time, TTL and task row version. Its `Stage` binds the
current publisher and compares these facts before and after the inner signing
input Stage in the caller's same real transaction. It performs no external I/O
while that transaction is held. The caller owns rollback/commit and can invoke
`SignCommitted` only against committed original signing input.

## Verification and limits

On backup `ad951f494979334c4c5a4807899c60bb71af43be`, the targeted run completed
with `PASS 52.365s`. Log:
`.tools/a-capture-certificate-full174-facts-v3.log` in the parent workspace.
The complete execution package also passed in the authorized local TLS/file
environment (`8.916s`), recorded in
`.tools/a-capture-certificate-execution-package-ad951f49-elevated.log`. The prior
sandboxed package run failed local loopback/file-identity checks and is retained
as a failed run; it is not counted as a successful semantic verification.

The pure checkpoint-mapping tests use explicitly named DATA and a test-local
receipt to exercise closed decoding. They do not supply actual capture or
signing authority. The MySQL tests apply all 174 embedded migrations through the
real pinned migration runner, preserve FK/CHECK enforcement, and use a separate
SELECT-only reader on four tables. The fixture cannot pass the complete C gate.
The healthy snapshot and 11 independent committed mutations cover an additional
resource, replaced observed UID, expired claim/task, stage/task row versions,
capture completion time, marker/MAC key, lifecycle and missing resource. Each
fault has affected-row and independent administrative SQL readback assertions.
The immutable reviewed migration catalog is
`d4fe00a440acf094e1def2d99586e333bed7803ba82b504ab25829b133680a21`.

These component tests establish reader/snapshot behavior. Recovery of the exact
original prepared/signed bytes, external-signing unknown
outcomes and certificate artifact transport also remain to be wired before this
producer can be used by first-forward publication. Recreating timestamps or
re-signing after an unknown outcome is not authorized.

## Same original task health continuation

After backup `c3a0a45273b41efe173fee35fe30a4ba5c7d5078`, A ran the new explicit
pre-composition fixture hook on the exclusively handed-over SAN/TLS MySQL
`127.0.0.1:63507`, UUID `f3756194-d52b-11f1-b8cc-745d22085e06`.
The first attempt failed during initialization because `BeforePrepare` came
after the original runtime access inventory. The corrected fixture installs
declared publisher materials after original formal materials and before runtime
composition, passes the actual publisher to that inventory, and rechecks the
unchanged sealed core. It does not skip any production access/readiness check.

The targeted current-health case completed `PASS 155.769s` (test body `152.50s`),
log `.tools/a-same-task-certificate-current-v2-precompose.log`. Same task:
`sbk_18008602-3282-43e5-8534-1388f55f7a5e`. All ten original native workers
completed, original Store.Record actually entered validating, and the current
publisher independently verified all C streams/domains. The business prepared
wrapper then staged the signing input in its original SQL transaction and
committed before exactly one external capture-certificate Sign call. Independent
public history verification and original task/completion/stage/TTL assertions
passed. Signed certificate SHA-256:
`31c33abdd103695c85541a0f500b7a2a3fd2d1b098b18e3620b9e224f6eabaa2`.
The capture source linked the real committed build SHA
`4aa30db42508ac9c32e0a487f7b74541f67209f2` before capture; there was no environment
display override or late source-fact repair.

This is A's self-test of a local protocol fixture, with original grants and
deadlines retained. It establishes neither worst-case source-window margin nor
production readiness. The three fresh-task post-Prepare mutation cases are
running separately and are not counted as passed in this health result.
