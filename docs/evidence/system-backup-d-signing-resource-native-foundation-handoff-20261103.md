# D native signer SQL source foundation

Status: SOURCE_ONLY. No compilation, tests, MySQL statements, containers, field access or Git operations were executed by D for this batch. No test/build products were created. Existing A15, schema136 nine files, D lifecycle three files and concrete-main six files remain byte-identical to their frozen manifests.

## Exact prerequisite for A

Add a new build-tagged test helper in package `install`, without modifying the frozen A15 or old native fixtures:

```go
func issueNativeSigningResourceOriginalBundles(
    t *testing.T,
    ctx context.Context,
    n *nativeAuthorityFixture,
) ([]owner.SigningResourceTrustPin, [][]byte)
```

D calls this only after `newNativeSigningSQLFixture` has applied the complete real catalog177 and replaced the two owned fixture accounts' privileges. The helper must invoke the actual `n.f.i.IssueSigningResourceInstall` for acceptance_record then catalog_record against that same native installer. Return the actual issued bytes and original matching pins. The native issuer must authenticate the original local admin password and enrolled owner, use the independently selected native UUID/database/installer and consumer accounts, and verify the actual original two-purpose signer domains through the A codec. No new target may be transplanted into an already signed model bundle, and D will not re-sign such a transplant.

The existing `originalSigningResourceBundleFixture` targets the component SQL model. It is not this interface. The old native authority fixture's controlled Vault protocol accepts capture `ProbeDomain`; it does not implement the new `SigningResourceProbeDomain`. A must supply the dedicated original signer observer/material fixture through the actual issuer. Controlled Kubernetes/Vault protocol fixtures remain controlled fixtures and do not prove field Vault authorization.

The helper does not install SQL rows. D's importer performs the real four-row install only after issuance. Do not add capture grants, tasks, enabled configurations or synthetic Passed/approval callbacks to satisfy it.

## Source contents and test-root accounting

Six new Go files, all guarded by `//go:build systembackup_mysql`:

- `signing_resource_native_fixture_test.go`: reuses the existing independently pinned localhost/non3306 TLS1.3 UUID fixture, its random owned schema/accounts and exact UUID/marker cleanup. Verifies the original three minimal tables are disposable and empty, replaces only those tables before any signer declaration, applies all177 real migrations with catalog SHA `0031e3825416f419fb7308b6bd72c9616c6179eab376e0579f448965fbe7b4c3`, preserves the original authenticated actor7, and grants exact signer columns. Consumer is SELECT-only; installer receives selected INSERT/UPDATE columns and no users UPDATE, capture SELECT or signer DELETE.
- `signing_resource_native_schema_test.go`: actual FK1452 and CHECK3819 negative statements inside an explicitly rolled-back root transaction. Unsigned `{}` data is constraint-only scaffolding; never committed or passed into the owner. Independent counts must remain zero afterward.
- `signing_resource_native_readback_test.go`: verifies actual A-issued bundles bind the native plan/target/enrollment/public issuer, uses the real A consumer and codecs on independent SELECT-only transactions, compares all four rows/raw signatures/CAS, and invokes actual A revocation while requiring original grant/signature bytes remain unchanged. Its private SQL clock view is DATA inspection and cannot mint an A retained terminal guard.
- `signing_resource_native_drift_test.go`: actual A consumer must reject grant revoked/head active and a 64-byte invalid original head signature, then restore the exact original owned fixture tuple. ENUM alone is explicitly not head/grant agreement.
- `signing_resource_native_monitor_test.go`: native driver transport instrumentation, including ErrSkip/default prepared fallback, records acquired locks only after the first actual row. Requires an actual performance_schema wait edge for the exact schema/table and actual waiting/blocking CONNECTION_ID values. Missing metadata fails the case.
- `signing_resource_native_scenarios_test.go`: scenario runners for install/replay/revoke; server-trigger rejection of any replay/resolve INSERT or UPDATE; mid-install and mid-revoke rollback; driver-boundary loss of acknowledgement only after successful actual COMMIT, unknown result, independent exact-tuple no-write resolve; blocking at acceptance head and later catalog grant, with actual exclusive head/grant order and exact revoked readback.

**Exactly one top-level native test root is present:** `TestSigningResourceSQLNativeFull177AndNarrowRoles`. It includes actual narrow-role checks, SELECT-only FOR SHARE and the rolled-back FK/CHECK cases. It has not been run by D. The reused native fixture may explicitly skip when root-owned native credentials/independent UUID are absent; that skip is not evidence of success.

`runNativeSignerLifecycle`, `runNativeSignerRollbackAndLostACK`, and `runNativeSignerLockCase` are ordinary helper functions. They currently have no top-level callers. Do not count them as runnable roots or executed tests. Once A supplies the above helper, add separate thin top-level roots that create a fresh owned fixture, call the actual issuer, pass its result through `nativeSignerIssuedInputs`, and invoke the corresponding runner. Lock cases must use separate fresh fixtures for `head:acceptance_record` and `grant:catalog_record`.

For the later catalog-grant blocker, the consumer holds only the current-admin shared prefix and exact catalog grant. This is diagnostic lock instrumentation, not actual full terminal admission. The acceptance-head blocker uses the actual A consumer to read both purpose tuples.

The lost-ACK fixture suppresses the caller-visible acknowledgement after the actual driver's successful COMMIT; it is a controlled driver-boundary fault, not a claim of a real network disconnect. Independent resolve uses the original distinct installer pool, with four real server triggers forbidding DML; the fault connector counter alone is not the no-write proof.

## Required root verification

Root owns compile/native execution and cleanup. Compile the exact complete dependency sets, then run the one present schema/role root against the owned TLS fixture. Lifecycle/fault/lock execution requires the actual A target-bound helper and additional thin roots first. Do not treat source inspection, DDL text, component SQL transports or controlled provider fixtures as native SQL permission/locking or end-to-end publication evidence.

Reused native fixture cleanup closes owned pools, checks the independent original UUID and exact random schema marker, drops only successfully created random accounts and that schema. New database objects and triggers remain confined to that schema; rollback-only scaffolding must leave no rows. Root must delete all test/build outputs after the run.

Complete first installation, main's two signer reference owners, all other missing owners, nonempty six-domain collection/publication, real source recovery, final same-task succeeded CAS and field/page acceptance remain unproven. This batch grants no deployment approval. DR remains unavailable/not_provided.
