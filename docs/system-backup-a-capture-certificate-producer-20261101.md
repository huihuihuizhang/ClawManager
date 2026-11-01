# Original capture certificate input producer

This component prepares the existing `public-c-crypto.v1` capture-certificate
payload from a complete, independently verified original capture. It is not yet
called by first-forward publication. No complete six-domain publication,
certificate signing, acceptance, catalog registration or standalone DR success
is asserted by this change.

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
input Stage in the caller's same real transaction. It performs no Kubernetes or
provider network I/O while SQL is held; bounded local material checks remain
mandatory. The caller owns rollback/commit and can invoke
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

These tests establish reader/snapshot behavior, not actual wrapper authorization
or a completed six-domain capture. Same-task producer/Stage integration must
still exercise changes after Prepare and before Stage with zero signing calls.
Recovery of the exact original prepared/signed bytes, external-signing unknown
outcomes and certificate artifact transport also remain to be wired before this
producer can be used by first-forward publication. Recreating timestamps or
re-signing after an unknown outcome is not authorized.
