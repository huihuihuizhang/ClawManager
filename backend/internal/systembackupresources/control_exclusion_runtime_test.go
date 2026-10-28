package systembackupresources

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"testing"
)

var runtimeControlTables = []string{"system_backup_v2_admin_revocations", "system_backup_v2_admin_sessions", "system_backup_v2_metadata_reservations", "system_backup_v2_totp_credentials"}

func TestControlExclusionCurrentRegistryScope(t *testing.T) {
	tables, err := ControlExclusionAllowlist(frozenRegistryBytes(t))
	if err != nil || len(tables) != 35 {
		t.Fatal("incomplete current control table closure", len(tables), err)
	}
	seen := map[string]bool{}
	for _, table := range tables {
		seen[table] = true
	}
	if seen["schema_migrations"] {
		t.Fatal("target-local migration history became a source-row check")
	}
	for _, table := range runtimeControlTables {
		if !seen[table] {
			t.Fatal("runtime control table omitted", table)
		}
	}
}
func TestControlExclusionRuntimeTables(t *testing.T) {
	for _, table := range runtimeControlTables {
		for _, fault := range []string{"source_rows", "missing", "nontransactional", "count_error"} {
			t.Run(table+"/"+fault, func(t *testing.T) {
				state := controlFixture()
				switch fault {
				case "source_rows":
					state.rows[table] = 3
				case "missing":
					delete(state.engines, table)
				case "nontransactional":
					state.engines[table] = "MyISAM"
				case "count_error":
					state.failure = "count:" + table
				}
				checks, err := (SQLControlExclusionVerifier{DB: countDatabase(t, state), Proof: fixtureTargetProof{}}).VerifyRestoreTarget(context.Background(), frozenRegistryBytes(t), "sev_runtime_control_fixture")
				if fault != "source_rows" {
					if err == nil || checks != nil || state.commits != 0 || state.rollbacks != 1 {
						t.Fatal("incomplete runtime control check escaped", table, fault, len(checks), err, state.commits, state.rollbacks)
					}
					return
				}
				if err != nil || len(checks) != 35 || state.commits != 1 || state.rollbacks != 0 || len(state.queries) != 70 {
					t.Fatal("runtime table bypassed the complete snapshot", table, len(checks), err, state.commits, state.rollbacks, len(state.queries))
				}
				failed := 0
				for _, check := range checks {
					if check.Status == "failed" {
						failed++
						if check.ID != "control_plane.empty."+table || check.FailureCategory != "normalization_failed" || check.Expected["rows"] != int64(0) || check.Actual["rows"] != int64(3) || check.CheckClassification == nil || *check.CheckClassification != "integrity" {
							t.Fatal("wrong runtime source-row failure", check)
						}
					}
				}
				if failed != 1 {
					t.Fatal("source runtime rows were not rejected exactly once", table, failed)
				}
			})
		}
	}
}

type controlCompletionProof func(context.Context, *sql.Tx) error

func (f controlCompletionProof) VerifyReadOnlyTarget(ctx context.Context, tx *sql.Tx) error {
	return f(ctx, tx)
}
func TestControlExclusionCompletionContext(t *testing.T) {
	for _, mode := range []string{"normal", "canceled", "deadline", "commit_error", "canceled_nonempty"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "deadline" {
				ctx = &completionDeadlineContext{Context: ctx}
			}
			state := controlFixture()
			finish := func() {}
			if mode != "normal" {
				finish = cancel
			}
			if mode == "commit_error" {
				state.failure = "commit"
			}
			if mode == "canceled_nonempty" {
				state.rows["system_backup_v2_admin_sessions"] = 1
			}
			proofCalls := 0
			proof := controlCompletionProof(func(proofCtx context.Context, tx *sql.Tx) error {
				proofCalls++
				if tx == nil || proofCtx.Err() != nil || len(state.queries) != 0 {
					return fmt.Errorf("target proof escaped the original snapshot")
				}
				return nil
			})
			checks, err := (SQLControlExclusionVerifier{DB: completionDB(t, state, finish), Proof: proof}).VerifyRestoreTarget(ctx, frozenRegistryBytes(t), "sev_control_completion_fixture")
			if proofCalls != 1 || state.commits != 1 || state.rollbacks != 0 || len(state.queries) != 70 || !state.begin.ReadOnly || state.begin.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
				t.Fatal("changed target snapshot/proof boundary", proofCalls, state.commits, state.rollbacks, len(state.queries), state.begin)
			}
			switch mode {
			case "normal":
				if err != nil || len(checks) != 35 {
					t.Fatal("normal control checks lost", len(checks), err)
				}
				for _, check := range checks {
					if check.Status != "passed" {
						t.Fatal("empty target did not pass", check)
					}
				}
			case "commit_error":
				if err == nil || checks != nil || !strings.Contains(err.Error(), "commit control exclusion snapshot: injected commit failure") {
					t.Fatal("commit error lost to cancellation", len(checks), err)
				}
			default:
				if err == nil || checks != nil || !errors.Is(err, ctx.Err()) {
					t.Fatal("late control checks escaped", mode, len(checks), err, ctx.Err())
				}
			}
		})
	}
}
