Agent runtime Registry V2 overlay / 2026-11-04 / source-only Python stdlib

This tool has not contacted the field registry or executed SSH, Docker, a builder,
ctr, nerdctl, an Agent ELF or a workload. The validation receipt covers actual
offline pinned input bytes and a loopback HTTP Registry V2 protocol fixture.
The two base digests are historical operator observations, not a claim of current
field identity. At operator execution every manifest/config/base layer is fetched
and verified before any upload; deployment identity must be re-observed separately.

Fixed input and scope
  Registry origin (the ONLY explicit insecure HTTP origin):
    http://10.130.14.23:5000
  openclaw repository/base:
    openclaw-lite@sha256:37c43ba05ff7fd4f0949f274fc67c3e9825f6d3d0f9124b5fc45dc8366c39cee
  hermes repository/base:
    hermes-lite@sha256:6688834a944161d8dada995cdffd90781533b24ab1e75bb2182c46eaee3fb52c
  Prebuilt bundle (provided separately by root; do not rebuild or substitute):
    agent-prebuilt-2408962c473d-linux-amd64.tar.gz
    SHA256 74257a0908591107fcfde27371e0799a593e02aab0e0d50c75890ccfc1191249
  Revision 52f47fc-core-2408962c473d-sameepoch-r1
  OpenClaw ELF SHA256 63a68c0a916a5d873c420c086f81a77d7d3c3f41bd5d798428b4608db0552cc1
  Hermes ELF SHA256 851104a524ff26797c58c6a5a1e0e8172353ecdd31c31a07032a81073a225a42
  No CLI override exists for origin/repository/base/Agent checksum. Updating an
  approved source input requires a new reviewed source revision.

Direct remote Bash examples (operator runs these; A did not execute them)
  Put the source helper and the independently verified prebuilt bundle in the
  current directory. Python 3.8+ with stdlib gzip/zlib is sufficient. No pip,
  BuildKit, docker/buildctl, daemon access or source build is needed.

  # Read/validate the entire pinned base and construct the candidate in memory.
  # GET only: no upload. image-built does not mean the image is in the registry.
  python3 -B agent_runtime_layer.py --runtime hermes \
    --bundle "$PWD/agent-prebuilt-2408962c473d-linux-amd64.tar.gz"

  # Publish each runtime by immutable manifest digest, after full verification.
  python3 -B agent_runtime_layer.py --runtime openclaw \
    --bundle "$PWD/agent-prebuilt-2408962c473d-linux-amd64.tar.gz" \
    --push > openclaw-runtime-image.json
  python3 -B agent_runtime_layer.py --runtime hermes \
    --bundle "$PWD/agent-prebuilt-2408962c473d-linux-amd64.tar.gz" \
    --push > hermes-runtime-image.json

  A successful JSON has status=image-pushed and immutable_reference. Consume
  immutable_reference, not a guessed tag. A refused invocation exits nonzero;
  do not consume its output as a successful image reference. Socket timeout is
  at most 30 seconds; --max-seconds bounds the entire operation (default 1800,
  explicit range 30..7200). Large Hermes bases require reading ALL original
  compressed and decompressed layer bytes for digest/diffID/CRC validation.

Tag policy and idempotence
  Standard Registry V2 has no portable atomic create-only tag operation. This
  tool therefore NEVER PUTs a tag, including a seemingly unused derived tag.
  derived_tag is cm-agent-<full new manifest sha256> in the original repository;
  tag_written is always false. The actual image is published via PUT by its
  manifest digest and returned as repository@sha256:..., avoiding old-tag
  overwrite races entirely. Do not describe derived_tag as a published tag.
  Same inputs produce identical tar, deterministic gzip stored blocks, diffID,
  config and manifest. Repeat push verifies existing blobs/manifest and performs
  no POST/PUT when they already match. A conflict/corrupt readback refuses.

What is verified and changed
  OCI image manifest / Docker schema2 and their index/manifest-list forms.
  Index must select exactly one linux/amd64 descriptor. Root and selected child
  raw manifests, media/size/SHA256, config blob size/SHA256 and linux/amd64, every
  original layer's compressed blob size/SHA256, gzip CRC/EOF, full uncompressed
  diffID and tar parse, original rootfs/diffID/history correspondence. Tar state
  at the Agent path and its parents accounts for whiteouts; symlink/hardlink or
  non-directory parents and nonregular target are refused.
  The only new layer member is usr/local/bin/clawmanager-agent, regular 0555,
  uid/gid=0, mtime=0. The exact bundle and actual static Linux amd64 ELF SHA,
  length, program headers, segment bounds and executable entry are verified.
  Original layers remain byte-for-byte descriptors in the same order. All
  original config values (Entrypoint, Cmd, Env, User, paths, labels and other
  keys) remain semantically exact; only rootfs.diff_ids and existing history get
  one append. No runtime script, release lock/manifest or business content is
  regenerated. Image construction does not prove runtime startup/integrity
  checks or real Agent protocol calls; those still require actual acceptance.
  The new config/layer are uploaded and fully read back before manifest publish;
  the manifest/config and pinned bases are read back again before image-pushed.
  Foreign/external layer URLs, inline descriptor data, foreign/zstd layers and
  schema1 are refused. Supported layer payloads are tar or gzip tar.

Network and credentials
  Proxy environment is disabled. All Location paths must remain on the exact
  original scheme/host/port/repository and original blob-upload namespace.
  ALL redirects are rejected before following them, including same-origin ones.
  There is no skip-verify option and no external bearer-realm discovery.
  Anonymous access is default. If required, add:
    --credentials-file /absolute/private/registry.json
  The file must be a regular non-symlink input; Linux requires current uid and
  no group/other access (0600). Supported exact keys are username/password or
  bearer_token; use pre-issued credentials from the original source. Do not put
  credentials in command arguments. Config.Env, credentials and response bodies
  never appear in stdout/stderr. Failures return fixed public codes only.
  Failed uploads may leave unreferenced blobs or an uploaded immutable manifest;
  the tool does not delete registry data or claim success after failed readback.

Acceptance flags
  Status is image-built (candidate, GET-only) or image-pushed (verified readback).
  page=false, native=false, live=false, workload_mutated=false and
  deployment_identity_rechecked=false always. Neither status is deployment,
  first adoption, native recovery, runtime acceptance or page acceptance.

Tests (no field network; actual input bundle is REQUIRED, no skipped check)
  python3 -B run_tests.py \
    --bundle "$PWD/agent-prebuilt-2408962c473d-linux-amd64.tar.gz"
  Tests use temporary directories with automatic cleanup, loopback HTTP servers
  and actual pinned bundle bytes in memory; never execute or retain an ELF.
  The local HTTP registry is a controlled protocol fixture, not a field registry.
  Keep non-secret validation receipts; remove any __pycache__/pyc produced by an
  invocation without -B. No test/build binary or daemon/container is created.
