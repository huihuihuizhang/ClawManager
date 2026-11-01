# Original publication payload counts

The complete publication-capture producer now retains redacted counts derived
from the actual decompressed business payloads. These are inputs for a future
full v12 manifest; they do not create a manifest, upload Job, eligibility or
terminal success.

## Actual call path and admission

`openPublicationCaptureFiles` calls `inspectOwnedBusinessPayloadCounts` inside
the existing current-Unwrap/complete-AEAD reader. The object is returned only
after the complete stream and post-read authorization checks pass. Its Close
clears the retained observations. `verifyOriginalPublicationCapture` copies
those observations into each original verified part, requires
`publicationPayloadCountsComplete` before returning its private complete-input
receipt, and includes the counts in that receipt hash.

Missing/default statistics, unknown units/operations, `Complete=false`, negative
counts, missing SQL tables or inconsistent SQL byte totals fail this actual
publication-input boundary. A later manifest caller cannot receive a complete
input from that producer while an operation remains uncounted. The separate
certificate checkpoint-mapping DATA tests do not supply this production receipt.

Units are explicit:

- SQL: each captured table's rows and non-NULL raw cell-value bytes, including
  empty tables. No row values or plaintext row hashes are retained.
- Source Redis: actual captured keys, DUMP and group bytes; Team Redis: key and
  DUMP bytes.
- Objects: actual completed object bodies and their verified sizes, after exact
  original version/size/digest/index checks.
- Resources/Secrets: completed captured object JSON lengths, with no secret
  values or plaintext value hashes retained.
- Workspace: all tar entries and entry-content bytes, including directories,
  hidden files and files outside the Skill MD5 selection.

`VerifyWorkspaceCaptureWithCounts` shares the original complete archive policy,
MD5, memory/entry/byte limits and EOF/suffix verification. Failed or canceled
verification returns zero counts. The original error-only API remains a wrapper
around that same verifier.

These units still need an explicit full-manifest business-domain/part mapping.
They must not be silently relabeled as compressed bytes, whole-object ciphertext
hashes, registry coverage or proof of source-independent recovery.

## Local verification

With SQL environments cleared, the targeted native suite passed execution
`4.217s` and skillhub `0.377s` in
`.tools/a-payload-counts-all-local-readers-v3.log`. It covers a complete encrypted
workspace fixture, nonempty local TLS Redis capture, nonempty resource history,
nonempty object records, SQL row DATA, count-admission refusals, and existing
Skill MD5/archive regressions. Invalid/truncated data returns no successful
counts. The resource/object/SQL DATA cases are parser properties, not current
source or publisher authority.

Both complete local packages passed execution `8.084s` and skillhub `1.890s` in
`.tools/a-payload-counts-full-local-packages-v4.log`. The independently authored
whole-workspace Skill-count probe was also adopted as a permanent test; its
golden archive includes content outside the Skill selection and its negatives
cover truncation, suffix, MD5, entry/byte bounds and cancellation.

The existing actual migrated-MySQL source/candidate fixture additionally checks
nonempty rows and cell bytes from its authenticated dump, rather than the formal
report's deliberately zero Files/Bytes. Its targeted original-valid case passed
on A's independently UUID-checked local `127.0.0.1:65298`
(`9679c9da-d595-11f1-b25e-745d22085e06`): package `23.138s`, case `1.24s`, with
the full 174 migration ledger, 177 base tables, 82 captured business tables and
95 excluded control tables. Log:
`.tools/a-payload-counts-original-sql-65298-v1.log`. Handle 51424 reached exit 0
and closed. This existing source adapter test does not assert SAN/TLS transport
or a complete six-domain task. It did not connect to the D-owned 63507 instance.

A new same-task complete-publication run has not yet validated these count
additions; prior same-task source-window failures and the interrupted task
remain failures/retained audit evidence. The complete manifest mapping and
provider-unknown signature outcome handling remain separate unfinished work.
