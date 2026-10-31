# Publication original plan parent

Migration 133 changes only the original 121 parent selection in one atomic
ALTER. Capture and secret_capture still require their original 120 plan.
Publish requires the same installation/task/attempt's original 122 capture
`plan`; `capture_result` is never interchangeable. Generated task references
prevent a caller selecting another parent path. The original attempt=1 CHECK
and original 121 source SQL remain unchanged. No second/placeholder plan is
inserted. Existing publish rows without that original plan fail the upgrade.

Reviewed catalog: 174 files,
`d4fe00a440acf094e1def2d99586e333bed7803ba82b504ab25829b133680a21`.
Registry admission statuses are unchanged.

On A's UUID-pinned isolated MySQL 59355,
`TestStagingIdentityFreshAndOriginal172UpgradeMySQL` passed 59.870s:
fresh 174, unchanged historical 172→174, unchanged historical 173→174,
and invalid old publish parent refusal. Existing capture/secret/publish sends
remain present on valid upgrade. Missing/wrong-task/wrong-attempt plan and
result-only parent inserts fail native constraints; a matching 122 plan works
without a 120 copy. The attempt=2 refusal explicitly reaches the original
CHECK after its other parents exist. Bound plan deletion and phase switching
cannot escape their respective parent constraints.

The invalid 173→174 case verifies no new columns, the original FK still
present, no new publication FK, all three old rows and the 173 migration ledger
unchanged. No plan is manufactured to repair it. Log:
`.tools/a-publish-parent-174-full-v5.log` in the shared workspace parent.
Earlier fixture mapping failures remain in v1–v4 logs; they were not migration
or publication successes. The SQL rows are named inert relational fixtures,
not valid business ciphertext or six-part acceptance evidence.

This migration does not complete PublishJob dispatch, result reception,
cleanup, three-purpose signing, catalog admission or standalone recovery.
