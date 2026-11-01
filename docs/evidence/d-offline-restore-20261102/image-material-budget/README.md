# Image material allocation budget — 2026-11-02

This independent batch changes exactly three Go files. It does not contain the
Northbound bridge or its shared-file WIP. Parent: `c31c3df2095299d7082787367fd78fcf6a4e94f4`.

The old authenticated reader decoded the complete typed object array before
checking its length. The new zero-copy lexical preflight checks each fixed wire
field, refuses a 65th object before parsing/appending it, and checks ciphertext
size before base64 decoding. Each item is limited to the actual 16 MiB plaintext
plus AES-GCM's 12-byte nonce and 16-byte tag; total ciphertext is at most 32 MiB.
Receipt object arrays independently receive the same count and size limits.
The existing 48 MiB staging plaintext cap remains an outer bounded buffer.

Typed decode still rejects unknown fields and trailing data, and requires the
canonical marshalled representation. Missing/duplicate/reordered fields fail
the earlier fixed schema walk. Decode/canonical/cancellation failures clear
decoded ciphertext backing buffers and reset partial output. The staging
plaintext buffer is cleared separately. Actual envelope authentication and final
frame, SQL/binding/full-digest correspondence and fixed-version object readback
remain in force.

Independent supervisor runs used `GOMAXPROCS=2`, `-p=1`, downloads disabled, no
SQL credentials or MySQL process, and only the existing private TLS/SigV4 object
protocol fixture. The logs and counter source are preserved here as Git copies:

- `76169`: original counter **FAIL**, 2.637 s. Both 65-item material forms were
  accepted and materialized. The two 64-item controls passed.
- `20944`: frozen regression **overall FAIL**, 2.897 s. The fixed 64/65 counter,
  item/total capacities, cleanup/cancellation cases and four actual SDK/public
  worker groups passed. One new test failed because Windows correctly refused
  O_RDWR on the intentionally read-only sealed fixture.
- `8450`: only that failed encrypted-open test **PASS**, 2.561 s, after adding
  test-only `root.Chmod(0600)` before explicit corruption. It actually truncated
  the final frame and recomputed the outer receipt; AEAD still rejected it.
  Production files and previously passing groups were unchanged.

No large memory-pressure experiment was run. This is allocation-bound regression
evidence, not complete restore qualification, deployed S3/MinIO evidence, native
SQL evidence, or formal fullC source/physical isolation authority. Exact raw
hashes and Git blobs appear in `scope.json`.

The supervisor's original log/counter/freeze artifacts use CRLF. Git normalized
seven committed evidence copies to LF. Their existing `bytes`/`raw_sha256`
fields retain the original supervisor artifact's byte length and SHA-256, with
the exact original path recorded as `raw_artifact_origin`; they do not describe
the LF Git copy. `committed_bytes`/`committed_sha256` describe the actual Git
content, and `git_blob` is that content's Git object ID. `normalization` records
the CRLF-to-LF conversion explicitly. The original supervisor files were not
modified; committed content equals their bytes with CRLF replaced by LF.

The README's original raw fields identify its owner-written pre-clarification
version in commit `769d0f528da21e71084e59283d6ddccbd5d14e0e`; its committed fields
identify this updated explanation. The three Go files have no normalization or
source changes in this documentation-only follow-up. Test outcomes above are
unchanged and no source tests were rerun for the documentation correction.
