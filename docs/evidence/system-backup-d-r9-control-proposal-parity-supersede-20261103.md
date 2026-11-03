# R9 second fixed-count fixture correction

SOURCE_ONLY, no tests/build/SQL/Git/remote commands executed and no test/build products created. Keep the first frozen parity2 unchanged. Root is building from clean43e and must explicitly overlay this independent batch before delivering R9; do not rerun historical R8.

The two diagnostic roots call `runDOriginalSixPartCaptureWithOptions` -> `checkOriginalMetadataSources` -> `installLocalOriginalControlApproval`. After the first census fix, the latter still required `len(proposal.Tables)==95`. Full current catalog yields97 control tables at that stage. This later guard would reject the real original control proposal before the native permit timing stage.

Explicit supersede: `production_same_task_control_mysql_test.go`, previous SHA `020cf72b07ad84e2dbce01c50fe97a048a47f832c660c4d16bc3386cbbc765e9`. Replace ONLY the fixed95/status assertion with `checkOriginalControlProposalCensus(proposal, observed.Census.Control)`.

The actual root `NewControlScopeProposal` still validates independently observed real column/PK/schema/policy structure and draft status. New helper then requires exact ordered names equal the already authenticated full source census.Control, exact original root.Policy for each name, and system_backup / metadata_only / reference_only classification. Unknown, duplicate, omitted or business-substituted names reject. It grants no approval and changes no production capture rule, exclusion, migrations or original permission window. It does not change the fixed count to97.

New root `TestOriginalControlProposalRequiresExactObservedControlNames`, six source-only cases: exact current names, omitted signer head, same-count wrong name, duplicate census, business substitution, non-draft status. These minimal name projections are DATA-only helper tests, not schema constructors, source observations or owner approval.

Static search over both entry roots, their original same-task/source/control/formal/capture helpers, and package-wide exact numeric tokens82/95/97 found no further schema business/control fixed-count comparison after this patch. Unrelated zero-residual guards and positive/negative cardinality checks for intentionally finite payload fixtures remain intact. Root should independently repeat the search and compile both parity roots plus the original native selectors. Source inspection is not proof native timing passed.
