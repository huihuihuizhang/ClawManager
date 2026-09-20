package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type recordedExec struct {
	rows    int64
	err     error
	queries []string
	args    [][]any
}

func (f *recordedExec) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	f.queries = append(f.queries, query)
	f.args = append(f.args, args)
	if f.err != nil {
		return nil, f.err
	}
	return fixedResult(f.rows), nil
}

type fixedResult int64

func (fixedResult) LastInsertId() (int64, error)   { return 0, nil }
func (r fixedResult) RowsAffected() (int64, error) { return int64(r), nil }

func validPolicy() LeasePolicy {
	return LeasePolicy{TTL: DefaultClaimTTL, HeartbeatInterval: DefaultHeartbeat, ReconcileInterval: DefaultReconcile}
}

func TestLeasePolicyV12Bounds(t *testing.T) {
	if err := validPolicy().Validate(); err != nil {
		t.Fatalf("default policy rejected: %v", err)
	}
	for _, policy := range []LeasePolicy{
		{TTL: MinClaimTTL - time.Second, HeartbeatInterval: MinHeartbeatInterval, ReconcileInterval: DefaultReconcile},
		{TTL: MaxClaimTTL + time.Second, HeartbeatInterval: DefaultHeartbeat, ReconcileInterval: DefaultReconcile},
		{TTL: DefaultClaimTTL, HeartbeatInterval: MinHeartbeatInterval - time.Second, ReconcileInterval: DefaultReconcile},
		{TTL: DefaultClaimTTL, HeartbeatInterval: DefaultClaimTTL/3 + time.Microsecond, ReconcileInterval: DefaultReconcile},
		{TTL: DefaultClaimTTL, HeartbeatInterval: DefaultHeartbeat, ReconcileInterval: MinReconcileInterval - time.Microsecond},
		{TTL: DefaultClaimTTL, HeartbeatInterval: DefaultHeartbeat, ReconcileInterval: MaxReconcileInterval + time.Second},
	} {
		if err := policy.Validate(); err == nil {
			t.Fatalf("invalid policy accepted: %#v", policy)
		}
	}
}

func TestAcquireClaimUsesOneDBTimeCASForEveryDTarget(t *testing.T) {
	tests := []struct {
		kind        TargetKind
		publicID    string
		table       string
		ownerColumn string
		leaseColumn string
	}{
		{TargetBackup, "sbk_11111111-1111-4111-8111-111111111111", "system_backups", "controller_owner", "controller_lease_expires_at"},
		{TargetDrill, "sdr_11111111-1111-4111-8111-111111111111", "system_restore_drills", "controller_owner", "controller_lease_expires_at"},
		{TargetPreflight, "spf_11111111-1111-4111-8111-111111111111", "system_backup_preflights", "controller_owner", "controller_lease_expires_at"},
		{TargetArtifactVerify, "sav_11111111-1111-4111-8111-111111111111", "system_backup_artifact_verifications", "controller_owner", "controller_lease_expires_at"},
		{TargetOperation, "sop_11111111-1111-4111-8111-111111111111", "system_backup_operations", "claim_owner", "claim_expires_at"},
	}

	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			exec := &recordedExec{rows: 1}
			token, err := AcquireClaimInInstallation(context.Background(), exec, "installation_test", Target{Kind: tt.kind, PublicID: tt.publicID}, "controller:pod-1", 7, validPolicy())
			if err != nil {
				t.Fatalf("AcquireClaim returned error: %v", err)
			}
			if token.RowVersion != 8 || token.Owner != "controller:pod-1" {
				t.Fatalf("unexpected token: %#v", token)
			}
			if len(exec.queries) != 1 {
				t.Fatalf("claim executed %d statements, want one", len(exec.queries))
			}
			query := exec.queries[0]
			for _, required := range []string{
				"UPDATE " + tt.table + " SET " + tt.ownerColumn + " = ?",
				tt.leaseColumn + " = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)",
				"row_version = row_version + 1",
				"origin_installation_id = ? AND public_id = ? AND row_version = ?",
				"next_reconcile_at IS NULL OR next_reconcile_at <= UTC_TIMESTAMP(6)",
				tt.ownerColumn + " IS NULL OR " + tt.ownerColumn + " = ? OR " + tt.leaseColumn + " <= UTC_TIMESTAMP(6)",
			} {
				if !strings.Contains(query, required) {
					t.Fatalf("claim SQL missing %q:\n%s", required, query)
				}
			}
			for _, forbidden := range []string{"NOW()", "provider", "catalog", "credential", "INSERT", "DELETE"} {
				if strings.Contains(strings.ToLower(query), strings.ToLower(forbidden)) {
					t.Fatalf("claim SQL contains forbidden %q: %s", forbidden, query)
				}
			}
			wantArgs := []any{"controller:pod-1", int64(DefaultClaimTTL / time.Microsecond), "installation_test", tt.publicID, uint64(7), "controller:pod-1"}
			if !reflect.DeepEqual(exec.args[0], wantArgs) {
				t.Fatalf("claim args = %#v, want %#v", exec.args[0], wantArgs)
			}
		})
	}
}

func TestClaimCASFailureAndCanceledLeaderContextFailClosed(t *testing.T) {
	target := Target{Kind: TargetBackup, PublicID: "sbk_11111111-1111-4111-8111-111111111111"}
	exec := &recordedExec{rows: 0}
	_, err := AcquireClaimInInstallation(context.Background(), exec, "installation_test", target, "controller:pod-1", 3, validPolicy())
	if !errors.Is(err, ErrClaimNotAcquired) {
		t.Fatalf("zero-row claim error = %v, want ErrClaimNotAcquired", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	exec = &recordedExec{rows: 1}
	_, err = AcquireClaimInInstallation(canceled, exec, "installation_test", target, "controller:pod-1", 3, validPolicy())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled claim error = %v, want context.Canceled", err)
	}
	if len(exec.queries) != 0 {
		t.Fatalf("canceled leader context executed SQL: %#v", exec.queries)
	}
}

func TestDeadlineClaimAcquireAndReleaseAreInstallationFenced(t *testing.T) {
	target := Target{Kind: TargetBackup, PublicID: "sbk_11111111-1111-4111-8111-111111111111"}
	exec := &recordedExec{rows: 1}
	token, err := AcquireClaimInInstallation(context.Background(), exec, "installation_test", target, "controller:pod-1", 7, validPolicy())
	if err != nil {
		t.Fatalf("AcquireClaimInInstallation: %v", err)
	}
	if !strings.Contains(exec.queries[0], "WHERE origin_installation_id = ? AND public_id = ?") ||
		!reflect.DeepEqual(exec.args[0], []any{"controller:pod-1", int64(DefaultClaimTTL / time.Microsecond), "installation_test", target.PublicID, uint64(7), "controller:pod-1"}) {
		t.Fatalf("unscoped acquire query/args: %q %#v", exec.queries[0], exec.args[0])
	}
	exec = &recordedExec{rows: 1}
	if _, err := ReleaseClaimInInstallation(context.Background(), exec, "installation_test", token, DefaultReconcile); err != nil {
		t.Fatalf("ReleaseClaimInInstallation: %v", err)
	}
	if !strings.Contains(exec.queries[0], "WHERE origin_installation_id = ? AND public_id = ?") ||
		!reflect.DeepEqual(exec.args[0], []any{int64(DefaultReconcile / time.Microsecond), "installation_test", target.PublicID, uint64(8), "controller:pod-1"}) {
		t.Fatalf("unscoped release query/args: %q %#v", exec.queries[0], exec.args[0])
	}
	exec = &recordedExec{rows: 1}
	if _, err := AcquireClaimInInstallation(context.Background(), exec, "", target, "controller:pod-1", 7, validPolicy()); err == nil || len(exec.queries) != 0 {
		t.Fatalf("missing installation acquired claim: err=%v queries=%#v", err, exec.queries)
	}
	if _, err := ReleaseClaimInInstallation(context.Background(), exec, "", token, DefaultReconcile); err == nil || len(exec.queries) != 0 {
		t.Fatalf("missing installation released claim: err=%v queries=%#v", err, exec.queries)
	}
}

func TestRenewAndReleaseRequireTheSameLiveOwnerAndRowVersion(t *testing.T) {
	token := ClaimToken{
		Target:     Target{Kind: TargetOperation, PublicID: "sop_11111111-1111-4111-8111-111111111111"},
		Owner:      "controller:pod-1",
		RowVersion: 9,
	}
	exec := &recordedExec{rows: 1}
	renewed, err := RenewClaimInInstallation(context.Background(), exec, "installation_test", token, validPolicy())
	if err != nil {
		t.Fatalf("RenewClaim returned error: %v", err)
	}
	if renewed.RowVersion != 10 {
		t.Fatalf("renewed row version = %d, want 10", renewed.RowVersion)
	}
	for _, required := range []string{
		"claim_expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)",
		"origin_installation_id = ? AND public_id = ? AND row_version = ? AND claim_owner = ?",
		"claim_expires_at > UTC_TIMESTAMP(6)",
	} {
		if !strings.Contains(exec.queries[0], required) {
			t.Fatalf("renew SQL missing %q: %s", required, exec.queries[0])
		}
	}

	exec = &recordedExec{rows: 1}
	version, err := ReleaseClaimInInstallation(context.Background(), exec, "installation_test", renewed, DefaultReconcile)
	if err != nil {
		t.Fatalf("ReleaseClaim returned error: %v", err)
	}
	if version != 11 {
		t.Fatalf("released row version = %d, want 11", version)
	}
	for _, required := range []string{
		"claim_owner = NULL, claim_expires_at = NULL",
		"next_reconcile_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)",
		"origin_installation_id = ? AND public_id = ? AND row_version = ? AND claim_owner = ?",
		"claim_expires_at > UTC_TIMESTAMP(6)",
	} {
		if !strings.Contains(exec.queries[0], required) {
			t.Fatalf("release SQL missing %q: %s", required, exec.queries[0])
		}
	}

	exec = &recordedExec{rows: 0}
	if _, err := RenewClaimInInstallation(context.Background(), exec, "installation_test", renewed, validPolicy()); !errors.Is(err, ErrClaimLost) {
		t.Fatalf("lost renew error = %v, want ErrClaimLost", err)
	}
	exec = &recordedExec{rows: 0}
	if _, err := ReleaseClaimInInstallation(context.Background(), exec, "installation_test", renewed, DefaultReconcile); !errors.Is(err, ErrClaimLost) {
		t.Fatalf("lost release error = %v, want ErrClaimLost", err)
	}
}

func TestClaimValidationRejectsUnregisteredTargetsAndUnsafeInputs(t *testing.T) {
	exec := &recordedExec{rows: 1}
	for _, test := range []struct {
		target  Target
		owner   string
		version uint64
	}{
		{Target{Kind: TargetKind("catalog"), PublicID: "scr_11111111-1111-4111-8111-111111111111"}, "controller:pod-1", 1},
		{Target{Kind: TargetBackup, PublicID: "sop_11111111-1111-4111-8111-111111111111"}, "controller:pod-1", 1},
		{Target{Kind: TargetBackup, PublicID: "sbk_11111111-1111-4111-8111-111111111111"}, "bad owner with spaces", 1},
		{Target{Kind: TargetBackup, PublicID: "sbk_11111111-1111-4111-8111-111111111111"}, "controller:pod-1", 0},
	} {
		if _, err := AcquireClaimInInstallation(context.Background(), exec, "installation_test", test.target, test.owner, test.version, validPolicy()); err == nil {
			t.Fatalf("unsafe claim input accepted: %#v", test)
		}
	}
	if len(exec.queries) != 0 {
		t.Fatalf("invalid claim inputs executed SQL: %#v", exec.queries)
	}
}
