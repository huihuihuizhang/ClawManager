//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type dRecoveryFenceMySQLReadAuthority struct {
	allow       bool
	badHash     bool
	failRecheck bool
}

func (a *dRecoveryFenceMySQLReadAuthority) PrepareRecoveryFenceRead(context.Context, pd.RecoveryFenceReadRequest) (pd.RecoveryFenceReadSession, error) {
	return a, nil
}
func (*dRecoveryFenceMySQLReadAuthority) LockReadInstallation(context.Context, pd.SQL, pd.RecoveryFenceReadRequest) error {
	return nil
}
func (a *dRecoveryFenceMySQLReadAuthority) AuthorizeRead(ctx context.Context, tx pd.SQL, r pd.RecoveryFenceReadRequest, _ pd.Hash) (pd.RecoveryFenceReadAdmission, error) {
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return pd.RecoveryFenceReadAdmission{}, err
	}
	hash, err := pd.RecoveryFenceReadHash(r)
	if err != nil {
		return pd.RecoveryFenceReadAdmission{}, err
	}
	if a.badHash {
		hash = pd.Hash(strings.Repeat("f", 64))
	}
	return pd.RecoveryFenceReadAdmission{VerifiedRequestHash: hash, IdentityExpiresAt: systemExecutionStamp(now.Add(time.Minute)), ReadAllowed: a.allow}, nil
}
func (a *dRecoveryFenceMySQLReadAuthority) RecheckRead(context.Context, pd.ReadSQL, pd.RecoveryFenceReadRequest, pd.RecoveryFenceObservation, time.Time) error {
	if !a.allow || a.failRecheck {
		return pd.ErrGuardRequired
	}
	return nil
}

func TestDRecoveryFenceReadMySQL(t *testing.T) {
	ctx := context.Background()
	db, lost := dProducerMySQLDB(t)
	f := newDIntegrationFixtureWithDB(t, db)
	identity := pd.Hash(strings.Repeat("6", 64))
	management := &dRecoveryFenceMySQLAuthority{db: db, allow: true}
	manager, err := pd.NewRecoveryFenceManager(db, f.history.Scope, management)
	mustSQL(t, err)
	authority := &dRecoveryFenceMySQLReadAuthority{allow: true}
	reader, err := pd.NewRecoveryFenceReader(db, f.history.Scope, authority)
	mustSQL(t, err)
	var now time.Time
	mustSQL(t, db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now))
	request := pd.RecoveryFenceReadRequest{Scope: f.history.Scope, IdentityHash: identity, Nonce: "read-before-write", BudgetUntil: systemExecutionStamp(now.Add(90 * time.Second))}
	observation, err := reader.ReadRecoveryFence(ctx, request)
	mustSQL(t, err)
	if observation.Found || !reflect.DeepEqual(observation.Row, pd.RecoveryFenceRow{}) {
		t.Fatal("missing identity returned row", observation)
	}
	change := dRecoveryFenceRequest(f.history.Scope, identity)
	lost.Store(true)
	row, err := manager.ChangeFence(ctx, change)
	if !reflect.DeepEqual(row, pd.RecoveryFenceRow{}) || !errors.Is(err, pd.ErrCommitUnknown) {
		t.Fatal("unknown write returned row", row, err)
	}
	request.Nonce = "read-after-unknown-write"
	observation, err = reader.ReadRecoveryFence(ctx, request)
	mustSQL(t, err)
	if !observation.Found || observation.Row.IdentityHash != identity || observation.Row.Epoch != "1" || observation.Row.RowVersion != "1" || observation.Row.Revoked {
		t.Fatal("fresh read after lost acknowledgement", observation)
	}
	// The observation is current state, not proof that the earlier request was
	// the writer; the caller must not use it as a recovered mutation receipt.
	change.Operation, change.ExpectedEpoch, change.ExpectedRowVersion = "revoke", "1", "1"
	_, err = manager.ChangeFence(ctx, change)
	mustSQL(t, err)
	request.Nonce = "read-after-revoke"
	observation, err = reader.ReadRecoveryFence(ctx, request)
	mustSQL(t, err)
	if !observation.Found || !observation.Row.Revoked || observation.Row.Epoch != "2" || observation.Row.RowVersion != "2" {
		t.Fatal("revocation read", observation)
	}
	crossScope := request
	crossScope.Scope.Database = "different_database"
	if got, err := reader.ReadRecoveryFence(ctx, crossScope); !errors.Is(err, pd.ErrInvalid) || !reflect.DeepEqual(got, pd.RecoveryFenceObservation{}) {
		t.Fatal("cross-scope read", got, err)
	}
	authority.allow = false
	if got, err := reader.ReadRecoveryFence(ctx, request); !errors.Is(err, pd.ErrGuardRequired) || !reflect.DeepEqual(got, pd.RecoveryFenceObservation{}) {
		t.Fatal("denied read", got, err)
	}
	authority.allow, authority.badHash = true, true
	if got, err := reader.ReadRecoveryFence(ctx, request); !errors.Is(err, pd.ErrGuardRequired) || !reflect.DeepEqual(got, pd.RecoveryFenceObservation{}) {
		t.Fatal("unbound read digest", got, err)
	}
	authority.badHash, authority.failRecheck = false, true
	if got, err := reader.ReadRecoveryFence(ctx, request); !errors.Is(err, pd.ErrGuardRequired) || !reflect.DeepEqual(got, pd.RecoveryFenceObservation{}) {
		t.Fatal("read final guard", got, err)
	}
	authority.failRecheck = false
	var late time.Time
	mustSQL(t, db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&late))
	request.BudgetUntil = systemExecutionStamp(late.Add(-time.Second))
	if got, err := reader.ReadRecoveryFence(ctx, request); !errors.Is(err, pd.ErrExpired) || !reflect.DeepEqual(got, pd.RecoveryFenceObservation{}) {
		t.Fatal("expired read", got, err)
	}
	request.BudgetUntil = systemExecutionStamp(late.Add(time.Minute))
	lost.Store(true)
	if got, err := reader.ReadRecoveryFence(ctx, request); !errors.Is(err, pd.ErrCommitUnknown) || !reflect.DeepEqual(got, pd.RecoveryFenceObservation{}) {
		t.Fatal("unknown read commit exposed row", got, err)
	}
}
