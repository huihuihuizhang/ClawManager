package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

type transactionStep struct {
	rows int64
	err  error
}

type recordedTransaction struct {
	steps       []transactionStep
	queries     []string
	args        [][]any
	commitErr   error
	commitCount int
	rollbacks   int
}

func (tx *recordedTransaction) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	tx.queries = append(tx.queries, query)
	tx.args = append(tx.args, args)
	step := transactionStep{rows: 1}
	if len(tx.steps) > 0 {
		step = tx.steps[0]
		tx.steps = tx.steps[1:]
	}
	if step.err != nil {
		return nil, step.err
	}
	return fixedResult(step.rows), nil
}

func (tx *recordedTransaction) Commit() error {
	tx.commitCount++
	return tx.commitErr
}

func (tx *recordedTransaction) Rollback() error {
	tx.rollbacks++
	return nil
}

func TestExpirePendingTaskIsOneClaimedDBTimeTransitionAndOneEvent(t *testing.T) {
	tests := []struct {
		kind       TargetKind
		publicID   string
		table      string
		targetType string
	}{
		{TargetBackup, "sbk_11111111-1111-4111-8111-111111111111", "system_backups", "backup"},
		{TargetDrill, "sdr_11111111-1111-4111-8111-111111111111", "system_restore_drills", "drill"},
		{TargetPreflight, "spf_11111111-1111-4111-8111-111111111111", "system_backup_preflights", "preflight"},
		{TargetArtifactVerify, "sav_11111111-1111-4111-8111-111111111111", "system_backup_artifact_verifications", "artifact_verify"},
	}

	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			tx := &recordedTransaction{}
			token := ClaimToken{Target: Target{Kind: tt.kind, PublicID: tt.publicID}, Owner: "controller:pod-1", RowVersion: 8}
			version, err := ExpirePendingClaim(context.Background(), tx, "installation_test", token)
			if err != nil {
				t.Fatalf("ExpirePendingClaim returned error: %v", err)
			}
			if version != 9 || tx.commitCount != 1 || tx.rollbacks != 0 {
				t.Fatalf("version/commit/rollback = %d/%d/%d, want 9/1/0", version, tx.commitCount, tx.rollbacks)
			}
			wantStatements := 2
			if tt.kind == TargetBackup || tt.kind == TargetDrill {
				wantStatements++
			}
			if len(tx.queries) != wantStatements {
				t.Fatalf("deadline transition executed %d statements, want %d", len(tx.queries), wantStatements)
			}
			if tx.args[0][0] != "installation_test" || tx.args[1][0] != "installation_test" {
				t.Fatalf("deadline update/event escaped installation: %#v", tx.args)
			}
			update := tx.queries[0]
			for _, required := range []string{
				"UPDATE " + tt.table + " SET status = 'failed'",
				"failure_category = 'deadline_exceeded'",
				"started_at = COALESCE(started_at, UTC_TIMESTAMP(6))",
				"finished_at = UTC_TIMESTAMP(6)",
				"public_id = ? AND row_version = ? AND status = 'pending'",
				"origin_installation_id = ? AND public_id = ?",
				"controller_owner = ? AND controller_lease_expires_at > UTC_TIMESTAMP(6)",
				"deadline_at <= UTC_TIMESTAMP(6)",
				"NOT EXISTS (SELECT 1 FROM system_backup_attempts",
			} {
				if !strings.Contains(update, required) {
					t.Fatalf("deadline update missing %q:\n%s", required, update)
				}
			}
			if tt.kind == TargetBackup && !strings.Contains(update, "NOT EXISTS (SELECT 1 FROM system_backup_external_actions") {
				t.Fatalf("backup deadline update must reject every persisted external action: %s", update)
			}
			if tt.kind != TargetBackup && !strings.Contains(update, "NOT EXISTS (SELECT 1 FROM system_artifact_leases") {
				t.Fatalf("read/verify task deadline update must reject every artifact lease: %s", update)
			}

			event := tx.queries[1]
			for _, required := range []string{
				"INSERT INTO system_backup_events",
				"'" + tt.targetType + "', public_id, 'task_status_changed', 'error', 'failed'",
				"'pending', 'failed', 'deadline_exceeded'",
				"FROM " + tt.table + " WHERE origin_installation_id = ? AND public_id = ? AND row_version = ? AND status = 'failed'",
			} {
				if !strings.Contains(event, required) {
					t.Fatalf("deadline event missing %q:\n%s", required, event)
				}
			}
			if wantStatements == 3 {
				sequence := tx.queries[2]
				for _, required := range []string{
					"INSERT INTO system_backup_alert_states",
					"'acceptance'",
					"task_purpose = 'acceptance'",
					"ON DUPLICATE KEY UPDATE",
					"config_version = incoming.config_version",
					"consecutive_anomaly_count = LEAST(consecutive_anomaly_count + 1, 4294967295)",
					"row_version = row_version + 1",
				} {
					if !strings.Contains(sequence, required) {
						t.Fatalf("deadline acceptance sequence missing %q:\n%s", required, sequence)
					}
				}
				if strings.Contains(sequence, "VALUES(") {
					t.Fatalf("deadline acceptance sequence uses deprecated VALUES(): %s", sequence)
				}
				if tx.args[2][0] != acceptanceAnomalyStateKey || tx.args[2][1] != "installation_test" || tx.args[2][2] != tt.publicID || tx.args[2][3] != uint64(9) || tx.args[2][4] != true {
					t.Fatalf("deadline acceptance sequence args = %#v", tx.args[2])
				}
			}
		})
	}
}

func TestExpirePendingOperationIsRejectedUntilItsDetailLedgerIsImplemented(t *testing.T) {
	tx := &recordedTransaction{}
	token := ClaimToken{
		Target:     Target{Kind: TargetOperation, PublicID: "sop_11111111-1111-4111-8111-111111111111"},
		Owner:      "controller:pod-1",
		RowVersion: 4,
	}
	_, err := ExpirePendingClaim(context.Background(), tx, "installation_test", token)
	if err == nil || !strings.Contains(err.Error(), "unsupported pending deadline target kind") {
		t.Fatalf("operation deadline error = %v, want explicit unsupported rejection", err)
	}
	if len(tx.queries) != 0 || tx.commitCount != 0 || tx.rollbacks != 1 {
		t.Fatalf("operation deadline queries/commits/rollbacks = %d/%d/%d, want 0/0/1", len(tx.queries), tx.commitCount, tx.rollbacks)
	}
}

func TestExpirePendingAcceptanceAnomalyAllowsFunctionalSkipAndExistingState(t *testing.T) {
	token := ClaimToken{
		Target: Target{Kind: TargetDrill, PublicID: "sdr_11111111-1111-4111-8111-111111111111"},
		Owner:  "controller:pod-1", RowVersion: 4,
	}
	for _, tt := range []struct {
		name string
		rows int64
	}{
		{"functional-test-selects-no-row", 0},
		{"existing-acceptance-state-updated", 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tx := &recordedTransaction{steps: []transactionStep{{rows: 1}, {rows: 1}, {rows: tt.rows}}}
			if _, err := ExpirePendingClaim(context.Background(), tx, "installation_test", token); err != nil {
				t.Fatalf("ExpirePendingClaim returned error: %v", err)
			}
			if tx.commitCount != 1 || tx.rollbacks != 0 || len(tx.queries) != 3 {
				t.Fatalf("commit/rollback/statements = %d/%d/%d", tx.commitCount, tx.rollbacks, len(tx.queries))
			}
		})
	}
}

func TestExpirePendingClaimRollsBackEveryPartialOrRejectedTransition(t *testing.T) {
	token := ClaimToken{
		Target:     Target{Kind: TargetBackup, PublicID: "sbk_11111111-1111-4111-8111-111111111111"},
		Owner:      "controller:pod-1",
		RowVersion: 2,
	}

	tests := []struct {
		name      string
		tx        *recordedTransaction
		wantError error
		queries   int
	}{
		{"claim-or-guard-rejected", &recordedTransaction{steps: []transactionStep{{rows: 0}}}, ErrDeadlineTransitionRejected, 1},
		{"event-write-failed", &recordedTransaction{steps: []transactionStep{{rows: 1}, {err: errors.New("event unavailable")}}}, nil, 2},
		{"event-row-missing", &recordedTransaction{steps: []transactionStep{{rows: 1}, {rows: 0}}}, nil, 2},
		{"acceptance-write-failed", &recordedTransaction{steps: []transactionStep{{rows: 1}, {rows: 1}, {err: errors.New("alert unavailable")}}}, nil, 3},
		{"acceptance-bad-affected", &recordedTransaction{steps: []transactionStep{{rows: 1}, {rows: 1}, {rows: 3}}}, nil, 3},
		{"commit-failed", &recordedTransaction{steps: []transactionStep{{rows: 1}, {rows: 1}, {rows: 1}}, commitErr: errors.New("commit uncertain")}, nil, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExpirePendingClaim(context.Background(), tt.tx, "installation_test", token)
			if err == nil {
				t.Fatal("unsafe partial deadline transition returned nil error")
			}
			if tt.wantError != nil && !errors.Is(err, tt.wantError) {
				t.Fatalf("error = %v, want %v", err, tt.wantError)
			}
			if len(tt.tx.queries) != tt.queries || tt.tx.rollbacks != 1 {
				t.Fatalf("queries/rollbacks = %d/%d, want %d/1", len(tt.tx.queries), tt.tx.rollbacks, tt.queries)
			}
		})
	}
}

func TestExpirePendingClaimCanceledContextExecutesNoSQLAndRollsBack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tx := &recordedTransaction{}
	token := ClaimToken{
		Target:     Target{Kind: TargetBackup, PublicID: "sbk_11111111-1111-4111-8111-111111111111"},
		Owner:      "controller:pod-1",
		RowVersion: 2,
	}
	_, err := ExpirePendingClaim(ctx, tx, "installation_test", token)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if len(tx.queries) != 0 || tx.rollbacks != 1 || tx.commitCount != 0 {
		t.Fatalf("queries/rollbacks/commits = %d/%d/%d, want 0/1/0", len(tx.queries), tx.rollbacks, tx.commitCount)
	}
}

func TestExpirePendingClaimRejectsMissingInstallationBeforeSQL(t *testing.T) {
	tx := &recordedTransaction{}
	token := ClaimToken{Target: Target{Kind: TargetBackup, PublicID: "sbk_11111111-1111-4111-8111-111111111111"}, Owner: "controller:pod-1", RowVersion: 2}
	if _, err := ExpirePendingClaim(context.Background(), tx, "", token); err == nil {
		t.Fatal("missing installation accepted")
	}
	if len(tx.queries) != 0 || tx.commitCount != 0 || tx.rollbacks != 1 {
		t.Fatalf("invalid installation statements/commits/rollbacks = %d/%d/%d", len(tx.queries), tx.commitCount, tx.rollbacks)
	}
}
