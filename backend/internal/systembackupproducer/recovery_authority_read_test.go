package systembackupproducer

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type authorityReadFixture struct {
	db       *fakeDB
	allowed  bool
	badHash  bool
	checks   int
	prepared int
}

func (f *authorityReadFixture) PrepareRecoveryAuthorityRead(context.Context, RecoveryAuthorityReadRequest) (RecoveryAuthorityReadSession, error) {
	f.prepared++
	return f, nil
}
func (f *authorityReadFixture) LockManagerRead(_ context.Context, _ SQL, r RecoveryAuthorityReadRequest, _ *RecoveryDeploymentProposal, hash Hash) (RecoveryAuthorityReadAdmission, error) {
	f.db.events = append(f.db.events, "manager-read-lock")
	if f.badHash {
		hash = Hash(strings.Repeat("f", 64))
	}
	return RecoveryAuthorityReadAdmission{VerifiedRequestHash: hash,
		ManagerExpiresAt: Timestamp(f.db.now.Add(time.Minute).Format(timeLayout)), ReadAllowed: f.allowed}, nil
}
func (f *authorityReadFixture) RecheckManagerRead(_ context.Context, _ ReadSQL, _ RecoveryAuthorityReadRequest, _ time.Time) error {
	f.checks++
	if !f.allowed {
		return ErrGuardRequired
	}
	return nil
}

func setupRecoveryAuthorityRead(t *testing.T) (*RecoveryAuthorityManager, *RecoveryAuthorityReader, RecoveryAuthorityRequest, *recoveryAuthorityFixture, *authorityReadFixture, *fakeDB) {
	t.Helper()
	m, write, env, _, db := setupRecoveryAuthority(t)
	readEnv := &authorityReadFixture{db: db, allowed: true}
	reader, err := NewRecoveryAuthorityReader(m.db, m.scope, readEnv)
	if err != nil {
		t.Fatal(err)
	}
	reader.clock = func() time.Time { return db.now }
	return m, reader, write, env, readEnv, db
}

func TestRecoveryAuthorityReadCurrentState(t *testing.T) {
	m, reader, write, env, readEnv, db := setupRecoveryAuthorityRead(t)
	request := RecoveryAuthorityReadRequest{Scope: write.Fence.Scope, Nonce: "read-authority-1",
		BudgetUntil: Timestamp(db.now.Add(time.Minute).Format(timeLayout))}
	got, err := reader.Read(context.Background(), request)
	if err != nil || got.DeploymentFound || got.FenceFound {
		t.Fatal("missing state", got, err)
	}
	if _, err := m.Change(context.Background(), write); err != nil {
		t.Fatal(err)
	}
	db.events = nil
	got, err = reader.Read(context.Background(), request)
	if err != nil || !got.DeploymentFound || !got.FenceFound || got.Deployment.WorkloadIdentityHash != write.Fence.IdentityHash || got.Fence.Epoch != got.Deployment.Epoch || got.Fence.Revoked {
		t.Fatal("registered state", got, err)
	}
	parent, deployment, manager, fence := -1, -1, -1, -1
	for i, event := range db.events {
		switch event {
		case "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE":
			parent = i
		case recoveryDeploymentLockSQL:
			deployment = i
		case "manager-read-lock":
			manager = i
		case recoveryFenceSelect:
			fence = i
		}
		if strings.HasPrefix(event, "INSERT ") || strings.HasPrefix(event, "UPDATE ") || strings.HasPrefix(event, "DELETE ") {
			t.Fatal("read mutated state", event)
		}
	}
	if parent < 0 || deployment <= parent || manager <= deployment || fence <= manager {
		t.Fatal("wrong read lock order", db.events)
	}
	write.Fence.Operation, write.Fence.ExpectedEpoch, write.Fence.ExpectedRowVersion, write.ExpectedDeploymentVersion = "revoke", "1", "1", "1"
	env.next.Epoch, env.next.RowVersion, env.next.Enabled = "2", "2", false
	if _, err := m.Change(context.Background(), write); err != nil {
		t.Fatal(err)
	}
	got, err = reader.Read(context.Background(), request)
	if err != nil || !got.DeploymentFound || got.Deployment.Enabled || !got.Fence.Revoked || got.Fence.Epoch != "2" {
		t.Fatal("revoked state", got, err)
	}
	if readEnv.checks != 3 {
		t.Fatal("read final guard missing", readEnv.checks)
	}
}

func TestRecoveryAuthorityReadFailsClosed(t *testing.T) {
	for _, name := range []string{"cross_scope", "denied", "digest", "expired", "commit_unknown", "epoch_mismatch"} {
		t.Run(name, func(t *testing.T) {
			m, reader, write, env, readEnv, db := setupRecoveryAuthorityRead(t)
			request := RecoveryAuthorityReadRequest{Scope: write.Fence.Scope, Nonce: "read-authority-2",
				BudgetUntil: Timestamp(db.now.Add(time.Minute).Format(timeLayout))}
			if name == "epoch_mismatch" {
				if _, err := m.Change(context.Background(), write); err != nil {
					t.Fatal(err)
				}
				env.row.epoch++
			}
			switch name {
			case "cross_scope":
				request.Scope.Database = "other_database"
			case "denied":
				readEnv.allowed = false
			case "digest":
				readEnv.badHash = true
			case "expired":
				request.BudgetUntil = Timestamp(db.now.Add(-time.Second).Format(timeLayout))
			case "commit_unknown":
				db.commitError = true
			}
			got, err := reader.Read(context.Background(), request)
			if err == nil || !reflect.DeepEqual(got, RecoveryAuthorityObservation{}) {
				t.Fatal("authority escaped", name, got, err)
			}
			if name == "cross_scope" && readEnv.prepared != 0 {
				t.Fatal("cross-scope prepared management authority")
			}
			if name == "commit_unknown" && !errors.Is(err, ErrCommitUnknown) {
				t.Fatal("unknown read commit", err)
			}
		})
	}
}
