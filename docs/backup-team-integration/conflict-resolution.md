# Reviewed conflict disposition

Current completion status and remaining work are defined only in the [root handoff](../../BACKUP_TEAM_INTEGRATION_HANDOFF.md). The table records integration choices; resolved file conflicts do not imply complete production behavior.

| Path / contract | Disposition |
| --- | --- |
| Dockerfile | Retain Team frontend, Hermes build, nginx modules and original controller/artifact executables. Add the optional Secret Broker executable; do not replace the controller command with a different program of the same name. |
| server/main.go | Retain current owner Team, portal, Runtime and route wiring. Merge worker lifecycle and opt-in session recorder only. Do not install the source fixture/read/task routes as a substitute for a production application. |
| db/db.go | Keep gated business connections and isolated-restore startup rejection. Add an independent per-connection UTC pool without changing the global business session. Detect incompatible unversioned control schema before migration. |
| db/migrations.go | Keep historical migration bodies and the current migration ledger. Serialize the old and source advisory lock protocols on a dedicated connection and reject DDL during either capture state. |
| historical backup SQL | Do not merge source 065–081 into automatic execution. Append the reviewed mappings in sql-map/catalog, preserving source references and collision-free table/constraint identities. Re-entry guards are explicit. |
| Repository conflicts | Retain current Team/owner/WorkBuddy/Gateway behavior. Merge only the reviewed login-state CAS and acknowledged Skill claim-return changes; no whole-repository replacement. Source-only APIs that need a production composition remain deferred. |
| Skill materialization worker | Keep Team's shared backup work boundary; merge cancellation, joined cleanup and no-overlap restart. Latest source backpressure/gate release semantics are adapted through the same boundary, including deferred initial backfill. |
| auth / LDAP / JWT | Keep existing local/enterprise/owner hooks. Propagate request cancellation and conditional login state, issue unique session token identities, and make new backup session recording opt-in. |
| Secret provisioning | Preserve owner Team create-only/token replay semantics. Adapt optional broker without changing resource namespace generation or granting cross-tenant access. |
| System backup command conflict | Preserve the working legacy command. Do not advertise the source coordination-only controller as a ready capture runner. A separate v2 workspace functional production owner exists; complete nonempty Runtime/full-domain composition remains outstanding. |
| Team UI / northbound | Keep latest compact cards, six-member template editing, notifications, internal scrolling, navigation and file preview behavior. No source UI wholesale replacement. |
| Source docs/evidence/deployments | Keep only referenced deterministic contract/test inputs and source SQL. Do not bulk import workstation caches, live evidence, credentials or site-specific deployment scripts. |

The source dispatch ABI added in `d3c5715a` defines a call boundary only. Missing
runner/ports dependencies return `ErrNotReady`. Neither that ABI nor the mutation
registry is proof of a complete scheduler, writer inventory or full-system restore.
Activation and final publication remain gated as described in README.md.
