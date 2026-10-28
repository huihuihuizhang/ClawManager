package systembackupevidence

import (
	"context"
	"database/sql/driver"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func addGCTaskDependent(m *gcTaskEligibilityModel, kind string, id int64) string {
	publicID := map[string]string{
		"drill":           "sdr_88888888-8888-4888-8888-888888888888",
		"preflight":       "spf_88888888-8888-4888-8888-888888888888",
		"artifact_verify": "sav_88888888-8888-4888-8888-888888888888",
	}[kind]
	row := append([]driver.Value(nil), m.tasks[m.backup]...)
	row[0], row[2], row[3], row[5] = id, publicID, kind, "failed"
	row[13], row[14] = "backup", m.backup
	row[15], row[16], row[17], row[18], row[19], row[20], row[21], row[22], row[23], row[24] = "", nil, false, "", false, false, nil, int64(0), "", ""
	if kind == "drill" {
		row[23], row[24] = "succeeded", "none"
	}
	m.tasks[publicID] = row
	return publicID
}

func TestDownloadRetentionGCTaskOtherArtifactDependents(t *testing.T) {
	for _, owner := range []string{"backup", "drill", "preflight", "artifact_verify"} {
		for _, dependent := range []string{"drill", "preflight", "artifact_verify"} {
			for _, state := range []string{"retained_failed", "retained_succeeded", "foreign_installation", "contradictory_source_type", "active", "future_deadline", "future_finish", "pending_reconcile", "active_claim", "later_expired_task"} {
				t.Run(owner+"/"+dependent+"/"+state, func(t *testing.T) {
					f := newGCTaskEligibilityFixture(t, owner)
					id := addGCTaskDependent(f.m, dependent, 91)
					switch state {
					case "retained_succeeded":
						f.m.tasks[id][5] = "succeeded"
					case "foreign_installation":
						f.m.tasks[id][1] = "installation_other"
					case "contradictory_source_type":
						// Model a corrupt row; a type predicate must not hide it.
						f.m.tasks[id][13] = "catalog_import"
					case "active":
						f.m.tasks[id][5] = "running"
						if dependent == "drill" {
							f.m.tasks[id][5] = "restoring"
						}
					case "future_deadline":
						f.m.tasks[id][7] = f.now.Add(time.Microsecond)
					case "future_finish":
						f.m.tasks[id][9] = f.now.Add(time.Microsecond)
					case "pending_reconcile":
						f.m.tasks[id][12] = f.now
					case "active_claim":
						f.m.tasks[id][10], f.m.tasks[id][11] = "other-worker", f.now.Add(time.Second)
					case "later_expired_task":
						at := f.scope.AdmittedAt.Add(time.Hour)
						f.m.tasks[id][8], f.m.tasks[id][9], f.m.tasks[id][7] = at, at.Add(time.Hour), at.Add(2*time.Hour)
					}
					q := downloadGCTaskDependentSQL(dependent)
					g, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now)
					allowed := oneOf(state, "retained_failed", "retained_succeeded", "later_expired_task")
					if (err == nil) != allowed || !f.m.locked[gcTaskRangeKey(q, f.m.backup)] {
						t.Fatal("wrong dependent eligibility or target range was never reached", err, f.m.queries)
					}
					if allowed {
						f.m.rechecking = true
						if g.Recheck(context.Background(), f.tx, f.scope, f.now.Add(time.Second)) != nil {
							t.Fatal("unchanged expired dependent could not remain")
						}
					}
				})
			}
		}
	}
}

func TestDownloadRetentionGCTaskDependencyKeysAndOwnExclusion(t *testing.T) {
	// Independently spell the published table predicates. There is no SQL
	// installation/type/status/expiry filter or PK exclusion hiding a live row.
	tables := map[string]string{"drill": "system_backup_v2_restore_drills", "preflight": "system_backup_v2_preflights", "artifact_verify": "system_backup_v2_artifact_verifications"}
	for _, owner := range []string{"backup", "drill", "preflight", "artifact_verify"} {
		t.Run(owner, func(t *testing.T) {
			f := newGCTaskEligibilityFixture(t, owner)
			g, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now)
			if err != nil {
				t.Fatal("original owner blocked its own eligible group", err)
			}
			for kind, table := range tables {
				q := downloadGCTaskDependentSQL(kind)
				if !strings.HasSuffix(q, " FROM "+table+" WHERE source_public_id=? ORDER BY id LIMIT 10001 FOR UPDATE") || !f.m.locked[gcTaskRangeKey(q, f.m.backup)] {
					t.Fatal("missing broad dependent range", q)
				}
			}
			if !f.m.locked[gcTaskRangeKey("SELECT id FROM system_backup_v2_prune_items WHERE artifact_public_id=? LIMIT 1 FOR UPDATE", f.m.backup)] {
				t.Fatal("missing retained prune range")
			}
			originalLocks := append([]string(nil), f.m.locks...)
			f.m.rechecking = true
			if err = g.Recheck(context.Background(), f.tx, f.scope, f.now.Add(time.Second)); err != nil || !reflect.DeepEqual(originalLocks, f.m.locks) {
				t.Fatal("recheck selected new ranges", err)
			}
		})
	}
	t.Run("same_pk_other_table", func(t *testing.T) {
		f := newGCTaskEligibilityFixture(t, "drill")
		other := addGCTaskDependent(f.m, "preflight", f.m.tasks[f.m.ownerID][0].(int64))
		f.m.tasks[other][5] = "running"
		if _, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now); err != ErrDenied || !f.m.locked[gcTaskRangeKey(downloadGCTaskDependentSQL("preflight"), f.m.backup)] {
			t.Fatal("another table's active equal-PK task was hidden", err)
		}
	})
	for _, kind := range []string{"backup", "system", "catalog_import", "drill;DROP TABLE users"} {
		if downloadGCTaskDependentSQL(kind) != "" {
			t.Fatal("unpublished dependent table accepted", kind)
		}
	}
}

func TestDownloadRetentionGCTaskDependentDrillInventory(t *testing.T) {
	for _, mode := range []string{"empty", "settled", "cleanup_retained", "cleanup_failed", "not_started_with_inventory", "residual", "active_resource_claim", "query_failure", "late_settled_resource", "late_eligible_version"} {
		t.Run(mode, func(t *testing.T) {
			f := newGCTaskEligibilityFixture(t, "backup")
			drill := addGCTaskDependent(f.m, "drill", 91)
			resource := []driver.Value{int64(71), f.m.installation, "deleted", nil, nil, int64(3), "", "none"}
			key := gcTaskRangeKey(downloadGCTaskRestoreSQL, drill)
			switch mode {
			case "cleanup_retained":
				f.m.tasks[drill][23] = "retained"
			case "cleanup_failed":
				f.m.tasks[drill][24] = "residual_data"
			case "not_started_with_inventory":
				f.m.tasks[drill][23] = "not_started"
				f.m.ranges[key] = [][]driver.Value{resource}
			case "residual":
				resource[2] = "delete_failed"
				f.m.ranges[key] = [][]driver.Value{resource}
			case "active_resource_claim":
				resource[3], resource[4] = "cleanup-worker", f.now.Add(time.Second)
				f.m.ranges[key] = [][]driver.Value{resource}
			case "query_failure":
				f.m.failQuery = downloadGCTaskRestoreSQL
			case "settled":
				f.m.ranges[key] = [][]driver.Value{resource}
			}
			g, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now)
			allowed := oneOf(mode, "empty", "settled", "late_settled_resource", "late_eligible_version")
			if (err == nil) != allowed {
				t.Fatal("wrong dependent drill inventory decision", mode, err)
			}
			if allowed {
				if !f.m.locked[key] {
					t.Fatal("dependent drill inventory not locked")
				}
				f.m.rechecking = true
				if mode == "late_settled_resource" {
					f.m.ranges[key] = [][]driver.Value{resource}
				}
				if mode == "late_eligible_version" {
					f.m.tasks[drill][6] = int64(8)
				}
				err = g.Recheck(context.Background(), f.tx, f.scope, f.now.Add(time.Second))
				if (err == nil) != !strings.HasPrefix(mode, "late_") {
					t.Fatal("changed eligible dependent facts were accepted", err)
				}
			}
		})
	}
}

func TestDownloadRetentionGCTaskDependentBounds(t *testing.T) {
	for _, mode := range []string{"single_range", "combined_ranges", "duplicate_public_id"} {
		t.Run(mode, func(t *testing.T) {
			f := newGCTaskEligibilityFixture(t, "backup")
			addRange := func(kind, prefix string, count int) {
				id := addGCTaskDependent(f.m, kind, 91)
				base := f.m.tasks[id]
				delete(f.m.tasks, id)
				rows := make([][]driver.Value, count)
				for n := range rows {
					rows[n] = append([]driver.Value(nil), base...)
					rows[n][0], rows[n][2] = int64(n+100), fmt.Sprintf("%s_99999999-9999-4999-8999-%012x", prefix, n)
				}
				if mode == "duplicate_public_id" {
					rows[1][2] = rows[0][2]
				}
				f.m.ranges[gcTaskRangeKey(downloadGCTaskDependentSQL(kind), f.m.backup)] = rows
			}
			switch mode {
			case "single_range":
				addRange("artifact_verify", "sav", 10001)
			case "combined_ranges":
				addRange("artifact_verify", "sav", 5001)
				addRange("preflight", "spf", 5000)
			case "duplicate_public_id":
				addRange("artifact_verify", "sav", 2)
			}
			if _, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now); err != ErrDenied || !f.m.locked[gcTaskRangeKey(downloadGCTaskDependentSQL("artifact_verify"), f.m.backup)] {
				t.Fatal("dependent bound/duplicate was not checked", err)
			}
		})
	}
}

func TestDownloadRetentionGCTaskDependentRetryPromotionAndLeases(t *testing.T) {
	for _, kind := range []string{"drill", "preflight", "artifact_verify"} {
		for _, mode := range []string{"retry", "expired_lease", "active_lease", "foreign_holder_source", "holder_missing_from_source"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				f := newGCTaskEligibilityFixture(t, "backup")
				id := addGCTaskDependent(f.m, kind, 91)
				target := gcTaskRangeKey(downloadGCTaskRetrySQL(kind), id)
				if mode == "retry" {
					f.m.ranges[target] = [][]driver.Value{{int64(93)}}
				} else {
					lease := gcTaskExpiredLease(f, kind)
					lease[7] = id
					if kind == "artifact_verify" {
						lease[8] = "verify"
					}
					f.m.ranges[gcTaskRangeKey(downloadGCTaskLeaseStateSQL, f.m.backup)] = [][]driver.Value{{int64(51), f.m.installation, "shared", int64(3), int64(4)}}
					target = gcTaskRangeKey(downloadGCTaskHolderLeaseSQL, kind, id)
					switch mode {
					case "active_lease":
						lease[9] = f.now.Add(-14 * time.Second)
						lease[10] = f.now.Add(time.Microsecond)
						target = gcTaskRangeKey(downloadGCTaskSourceLeaseSQL, f.m.backup)
					case "foreign_holder_source":
						lease[3] = "sbk_77777777-7777-4777-8777-777777777777"
					}
					if oneOf(mode, "expired_lease", "active_lease") {
						f.m.ranges[gcTaskRangeKey(downloadGCTaskSourceLeaseSQL, f.m.backup)] = [][]driver.Value{lease}
					}
					f.m.ranges[gcTaskRangeKey(downloadGCTaskHolderLeaseSQL, kind, id)] = [][]driver.Value{lease}
				}
				g, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now)
				if (err == nil) != (mode == "expired_lease") || !f.m.locked[target] {
					t.Fatal("dependent protection missing or target not reached", err, f.m.queries)
				}
				if mode == "expired_lease" {
					f.m.rechecking = true
					if g.Recheck(context.Background(), f.tx, f.scope, f.now.Add(time.Second)) != nil {
						t.Fatal("unchanged expired lease should not revive an owner")
					}
				}
			})
		}
	}
	t.Run("other_drill_promotion", func(t *testing.T) {
		f := newGCTaskEligibilityFixture(t, "backup")
		id := addGCTaskDependent(f.m, "drill", 91)
		key := gcTaskRangeKey(downloadGCTaskDrillPromotionSQL, id)
		f.m.ranges[key] = [][]driver.Value{{int64(93)}}
		if _, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now); err != ErrDenied || !f.m.locked[key] {
			t.Fatal("other drill promotion was hidden", err)
		}
	})
}

func TestDownloadRetentionGCTaskPruneDependencyAndRequiredTable(t *testing.T) {
	for _, mode := range []string{"retained", "missing_table", "view"} {
		t.Run(mode, func(t *testing.T) {
			f := newGCTaskEligibilityFixture(t, "backup")
			if mode == "retained" {
				f.m.ranges[gcTaskRangeKey(downloadGCTaskPruneDependencySQL, f.m.backup)] = [][]driver.Value{{int64(93)}}
			} else {
				for n, row := range f.m.catalog {
					if row[0] == "system_backup_v2_prune_items" {
						if mode == "view" {
							row[1] = "VIEW"
						} else {
							f.m.catalog = append(f.m.catalog[:n], f.m.catalog[n+1:]...)
						}
						break
					}
				}
			}
			if _, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now); err != ErrDenied {
				t.Fatal("prune dependency protection missing", err)
			}
			if mode == "retained" && !f.m.locked[gcTaskRangeKey(downloadGCTaskPruneDependencySQL, f.m.backup)] {
				t.Fatal("prune reference test never reached its range")
			}
		})
	}
}

func TestDownloadRetentionGCTaskLateArtifactDependenciesPoisonCopies(t *testing.T) {
	for _, kind := range []string{"drill", "preflight", "artifact_verify", "prune", "owner_pk_changed"} {
		t.Run(kind, func(t *testing.T) {
			f := newGCTaskEligibilityFixture(t, "drill")
			g, err := f.m.service.Lock(context.Background(), f.tx, f.scope, f.now)
			if err != nil {
				t.Fatal(err)
			}
			copyGuard := *g
			f.m.rechecking = true
			switch kind {
			case "owner_pk_changed":
				f.m.tasks[f.m.ownerID][0] = int64(92)
			case "prune":
				f.m.ranges[gcTaskRangeKey(downloadGCTaskPruneDependencySQL, f.m.backup)] = [][]driver.Value{{int64(93)}}
			default:
				addGCTaskDependent(f.m, kind, 91)
			}
			if g.Recheck(context.Background(), f.tx, f.scope, f.now.Add(time.Second)) != ErrDenied {
				t.Fatal("late artifact dependency accepted")
			}
			// Restore every original row/range before testing the copied guard,
			// so a remaining dependency cannot conceal a missing shared poison.
			f.m.rollback()
			queries := len(f.m.queries)
			if copyGuard.Recheck(context.Background(), f.tx, f.scope, f.now.Add(2*time.Second)) != ErrDenied || len(f.m.queries) != queries {
				t.Fatal("failed guard revived after original facts were restored")
			}
		})
	}
}

func TestDownloadRetentionGCTaskCollectorLateArtifactDependenciesRollback(t *testing.T) {
	for _, kind := range []string{"drill", "preflight", "artifact_verify", "prune"} {
		for stage, query := range map[string]string{"tombstone": downloadGCTombstoneInsertSQL, "result_deleted": downloadGCDeleteResultSQL, "operation_deleted": downloadGCDeleteOperationSQL} {
			t.Run(fmt.Sprint(kind, "/", stage), func(t *testing.T) {
				f := newRetentionGCFixture(t)
				i := f.d.record.Manifest.Identity
				m := newGCTaskEligibilityModel(t, f.d.identity, i.Installation, i.OwnerType, i.OwnerID, f.d.now)
				f.d.taskEligibility = m
				before := f.d.reserved
				originalRows := [][]driver.Value{
					append([]driver.Value(nil), f.d.m.op...), append([]driver.Value(nil), f.d.m.receipt...),
					append([]driver.Value(nil), f.d.nonce...), append([]driver.Value(nil), f.d.resultRetention...),
				}
				originalAudits := [][]byte{append([]byte(nil), f.d.body...), append([]byte(nil), f.d.resultBody...)}
				injected := false
				f.d.afterWrite = func(q string) {
					if q != query {
						return
					}
					injected = true
					if kind == "prune" {
						m.ranges[gcTaskRangeKey(downloadGCTaskPruneDependencySQL, m.backup)] = [][]driver.Value{{int64(93)}}
					} else {
						addGCTaskDependent(m, kind, 91)
					}
				}
				err := f.s.Collect(f.ctx, f.operation)
				currentRows := [][]driver.Value{f.d.m.op, f.d.m.receipt, f.d.nonce, f.d.resultRetention}
				if !injected || err == nil || f.d.commits != f.commits || f.d.rollbacks != f.rollbacks+1 || len(f.d.stone) != 0 || f.d.reserved != before || !reflect.DeepEqual(currentRows, originalRows) || !reflect.DeepEqual([][]byte{f.d.body, f.d.resultBody}, originalAudits) || !reflect.DeepEqual(m.tasks, m.savedTasks) || !reflect.DeepEqual(m.ranges, m.savedRanges) {
					t.Fatal("late dependency did not roll back original group, tombstone, budget and model rows", injected, err)
				}
				writeSeen := false
				for _, write := range f.d.writes {
					writeSeen = writeSeen || write == query
				}
				if f.policy.taskGuard == nil || !writeSeen {
					t.Fatal("concrete dependency guard/target write not exercised")
				}
			})
		}
	}
}
