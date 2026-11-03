# D native SQL roots using explicit test issuer declarations

Status: SOURCE_ONLY, uncompiled and unexecuted by D. This is an additive two-Go-file test batch on top of the frozen six-Go-file native foundation. Historical manifests and frozen bytes remain unchanged.

The supervisor narrowed the immediate native regression scope: generate fresh explicit test issuer declarations for the already enrolled native fixture, then test the real importer, independent consumer, rollback, commit-unknown resolution and lock behavior. A production `IssueSigningResourceInstall` fixture is no longer a prerequisite for **these narrowly scoped native SQL tests**. It remains required for proving actual production issuance/provider authorization. This supersedes only the earlier foundation handoff's statement that all lifecycle test roots must wait for that production issuer helper.

`nativeSignerOriginalDeclarationInputs` is intentionally distinct from the proposed A `issueNativeSigningResourceOriginalBundles` helper, so A can add the actual production issuer fixture without a symbol collision. It:

- starts from the same independently selected native fixture plan/target/enrollment and its original issuer key/public pin;
- authenticates the actual native local admin and checks actual enrolled owner/pins through existing A code;
- constructs each explicit new TEST declaration for acceptance_record then catalog_record before signing, using existing A Grant/Head codecs and their separate single-NUL domains;
- declares signing-material and three-purpose binding/history metadata as test data only; it does not authenticate this metadata through installed material or a provider observation;
- never calls the old model-target `originalSigningResourceBundleFixture`, changes an existing signed target, or re-signs an existing grant;
- verifies the resulting exact native tuple with the common codec/data verifier and logs the production-issuance limitation.

No successful `IssueSigningResourceInstall`, provider probe, real Vault, runtime signing, retained terminal admission, task/config installation or end-to-end backup is established by this helper. Native SQL remains real; test declarations are not field permission proof. Revocations in the scenario runners still invoke the actual existing `IssueSigningResourceRevocation` against installed original SQL rows and preserve original grant/signature bytes.

## Exact root inventory

The full eight-file native source set now contains **four top-level native roots**, with two lock subcases:

1. `TestSigningResourceSQLNativeFull177AndNarrowRoles` (foundation): full177 actual migration runner, independently limited installer/SELECT-only consumer, actual FOR SHARE, FK/CHECK rollback.
2. `TestSigningResourceSQLNativeDeclaredInstallReplayAndRevoke`: explicit test declarations, actual four-row import, actual consumer/state/signature drift denial, no-write replay guarded by server triggers, exact original terminal revoke and old-active denial.
3. `TestSigningResourceSQLNativeDeclaredRollbackLostACKAndResolve`: real trigger rollback at catalog install/revoke writes, real successful COMMIT with controlled driver-boundary ACK loss, unknown result and independent original-pool exact-tuple resolve guarded against DML by real server triggers.
4. `TestSigningResourceSQLNativeDeclaredConsumerRevokeLockOrder`: `head:acceptance_record` and `grant:catalog_record`; each uses a fresh owned fixture. Requires actual performance_schema wait edges and actual acquired exclusive head/grant order before/after releasing SELECT-only locks.

The earlier runner helpers remain ordinary helpers and are not additional test roots. Missing independently pinned root-owned native credentials may cause the reused fixture to skip; a skip is unverified, never PASS evidence. Lack of actual lock metadata fails rather than skips.

Root owns compilation, execution and exact original UUID/schema/marker cleanup. Suggested selection from `backend`, for root-owned execution only:

```text
go test -mod=readonly -tags systembackup_mysql -count=1 -timeout=30m -run '^TestSigningResourceSQLNative(Full177AndNarrowRoles|DeclaredInstallReplayAndRevoke|DeclaredRollbackLostACKAndResolve|DeclaredConsumerRevokeLockOrder)$' ./internal/systembackupinstallationowner/install
```

Use the exact complete dependency manifests, not only these two Go files. Root must delete every test/build product and dedicated cache afterward. D ran only gofmt and static source/hash checks, created no test/build products, and performed no SQL, test/build, Docker, Git, remote or field commands.

All existing installation/publication gaps and NO_GO scope remain unchanged. DR remains unavailable/not_provided.
