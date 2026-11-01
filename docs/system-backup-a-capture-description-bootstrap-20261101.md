# Original capture description and administrative bootstrap

This component is under development. It does not establish a completed MF,
an upload-only Job, native artifact readback, final acceptance or a DR handle.
The original eleven-member SQL variant is available as
`TestAOriginalSixPartDescriptionCaptureMySQL`; it has not yet been executed.

The original plan declares a dedicated `capture_description` member using
`capture-description`. The execution order is business B, description D,
then control sidecar E and proofs P. D describes exactly B, using the original
Invocation bytes, complete original candidate-wrapper bytes and each member's
original ModuleResult SHA. That result SHA is not the aggregate capture-result
SHA. D separately retains the frozen D/E/P Invocations, without their future
candidate/results. The original source inventory is preserved byte for byte.
The control finalization policy still names exactly B. Its exact frozen seed
is retained in the original administrative Invocations and encrypted proofs.

Every member is still an original real C stream with its own original Job,
Generate/use window, candidate and checkpoint. D is not a business member and
does not borrow a secret-bundle operation. Historical Authority fields inside
the encrypted candidate wrappers are inert history, never current permission.
The producer reads exact authenticated candidate wrapper bytes rather than
re-marshaling the inner FormalCaptureResult under the wrapper's old hash.

The controller endpoint uses the current original using Job's mTLS/workload
identity, original nonce, SQL authority and exact frozen Invocation. It reads
the same original B candidates and registered member results, then repeats its
authorization and record snapshot before returning bytes. It reads no business
source, creates no replacement old claim and extends no provider window.

The publisher independently reads the complete D C stream and compares its
full Scope, including ConfigVersion, against authenticated original input. It
closes the entire B/D/E/P set against the original plan, all C records and the
control owned basis. D's own candidate/result is not recursively embedded.

`control/capture-bootstrap.json` uses
`system-backup-capture-bootstrap.v1`. Its exact raw SHA and length must enter the
artifact index authenticated through the final MF. It exposes only original
D/E/P StreamSpecs, checkpoint bytes and C/envelope coordinates, SHA and length.
The original signed certificate pins all checkpoint hashes. It contains no raw
Invocation, source inventory or candidate wrapper. D is stored at
`control/capture-description.json.enc` with
`control/capture-description.envelope.json`. Consumers must authenticate fixed
native object versions and actual byte receipts, bind the original Seed to the
independent business-container set, and validate the full KEK mapping before
Unwrap. Bootstrap role/shape validation grants no key permission. After D is
decrypted its exact Invocations must match the external checkpoint/StreamSpec;
the complete B/E/P semantic and post-use checks precede a final handle.

The original four-MiB plan bounds source plus Invocation bytes; each complete
candidate wrapper is bounded to sixteen KiB. Derived plaintext budgets include
base64 and typed overhead for at most 9,997 B members plus D/E/P. The maximum
is approximately 223 MiB, an arithmetic limit rather than a large-I/O proof.
Decode failures clear allocated byte buffers. Explicit memory admission uses
finite process GOMEMLIMIT, current Go memory usage, and the sum of conservative
reservations for all concurrent descriptor pipelines. Each live buffer owner
retains its reservation until cleanup. A process with no finite declared budget
is refused. The Job freezes its corresponding memory request/limit. This is
resource admission, not source authorization or a measured RSS guarantee.
The local native fixture runs workers/controller as goroutines in one process;
both paths reserve against the same real four-GiB declared allowance. Separate
production processes each account against their own declared process budget.

The production file/bootstrap and early database startup paths load publisher
materials before capture templates. A D template's original
`Request.MaxArchiveBytes`/`MaxCompressedBytes` is an explicit equal upper cap;
its actual derived Seed must fit that cap before Prepare. Publisher materials
opt in with `description_max_plaintext_bytes` at least this cap. Both loaders
check a finite, sufficient process declaration and fail at startup with
`ErrMemoryDeclaration` when absent/insufficient. Legacy disabled protocols keep
their old startup behavior. No code raises an OS or Pod resource limit.

For example, an original 16-MiB D template cap requires
`12 * 16 MiB + 128 MiB = 320 MiB` of declared Go memory; each runtime pipeline
also reserves `12 * actual Seed bytes + 32 MiB` against current usage and the
sum of concurrent reservations. Configure an independently suitable process
and Pod budget first. On the existing controller/publisher entry point an
explicit shell launch is:

```sh
export GOMEMLIMIT=1GiB
exec system-backup-v2-controller "$@"
```

The installed controller binary is on PATH and its existing arguments remain
unchanged. One GiB is an example for
the stated 16-MiB cap, not a maximum-size/concurrency/RSS proof or an automatic
deployment change. The signed publisher material in that example contains
`"description_max_plaintext_bytes":16777216`; the capture template uses the
same declared upper cap. Production startup validates this configuration.

Validation so far: typed DATA/negative scope and budget tests; actual worker
C/AEAD/EOF/file readback with an explicit key-authority fixture; seven complete
native-filesystem package checks with SQL opt-in disabled. Full-WIP startup
source ledgers and logs are preserved in `.tools/a-description-*-v*.json/log`.
Those checks do not substitute for the pending same-original-task SQL variant.
