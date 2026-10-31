# Original suspended publication Job boundary

`ensureSuspendedPublicationJob` creates a real native upload-only Job through
the original 121 send intent, outside the capture gate. It accepts only v2
finite presigned PUT delegation and the original 104 candidate owner MAC.
It independently authenticates original 122 capture records to select only
their individual observed C/envelope file mounts. It does not copy a 120 plan.
Migration 133 and reviewed catalog 174 are prerequisites.

The administrator-pinned core selects a distinct publication worker SA name
and UID. Native namespace, SA and staging PVC/PV UID/claim identities are read
currently. The shared actual RBAC/readiness inventory includes only a named
`get` for this added SA; it cannot become the controller or capture SA.

Original 121 `sending` commits before native Create. No SQL transaction spans
Kubernetes I/O. Any SQL/native ACK loss retains the original intent; retries
only GET the exact original name/spec/UID, including absent-after-sending.
The Job remains suspended. Final binding re-reads the actual 121 row under
the current publisher claim rather than accepting a stale pre-GET UID.

Named fake Kubernetes API plus actual UUID-pinned MySQL 59355: ten scenarios
passed 38.399s, log `.tools/a-original121-suspended-job-v3.log` in the shared
workspace parent. They include actual sending/bound SQL commit ACK loss,
native Create ACK loss, sent-but-absent, actual Release during Create with
NULL owner/advanced version readback, changed source request, replaced SA,
actual named SA GET 403, and bound SQL UID mutation during GET. The global
SQL-transaction/Kubernetes overlap assertion remains enabled. The initial
ordering failure is retained and fixed by checking authority before BeginTx.
Denied inputs perform no Job Create, source/KMS request or native provider IO.
The generated-RBAC/readiness named-SA allow/deny test also passes.

Complete package tests without optional SQL fixtures: execution 10.950s,
kube 3.619s, worker command 6.389s.

This is a suspended transport boundary using one real original workspace C
fixture and explicitly inert index/minimal manifest DATA. It is not a complete
six-part assembly or admitted publication caller. Original 107 receiving
identity, immutable Job-owned request/credential resources, controlled result
delivery or independent fixed-version reconstruction, unsuspend, full v12
candidate verification, cleanup/signatures/finalization and DR remain required.
The result directory is memory-only; no controller reads it through the PVC.
