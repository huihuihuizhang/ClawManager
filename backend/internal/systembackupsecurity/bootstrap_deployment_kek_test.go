package systembackupsecurity

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"

	reg "clawreef/internal/systembackupkekregistry"
)

// Synthetic ordering/refusal checks only; no provider or real SQL is used.
type deploymentKEKPreparation struct {
	prepare func(context.Context, *sql.DB, OfflineBootstrapGrant, BootstrapConfig) (reg.PreparedAdmission, error)
}

func (p *deploymentKEKPreparation) PrepareBootstrapKEK(ctx context.Context, db *sql.DB, grant OfflineBootstrapGrant, config BootstrapConfig) (reg.PreparedAdmission, error) {
	return p.prepare(ctx, db, grant, config)
}

func TestBootstrapCandidateAttemptKEKPreservesOriginalAttemptAndRefusesNewUse(t *testing.T) {
	for _, preparationError := range []error{errors.New("synthetic provider refusal"), nil} {
		t.Run(map[bool]string{true: "provider-refused", false: "nil-preparation"}[preparationError != nil], func(t *testing.T) {
			attempt, authority, state, db := beforeDatabaseAttempt(t, context.Background())
			op := attempt.state.authority.OperationPublicID
			originalSample := *attempt.state.authority.CapacityObservedAt
			opens, prepares := 0, 0
			kek := &deploymentKEKPreparation{prepare: func(ctx context.Context, received *sql.DB, grant OfflineBootstrapGrant, config BootstrapConfig) (reg.PreparedAdmission, error) {
				prepares++
				if opens != 1 || ctx != authority.preparedAt || ctx != attempt.state.ctx || received != db || grant != attempt.state.plan.grant || config.SHA256() != grant.ConfigSHA256 {
					t.Fatal("KEK preparation escaped original attempt context/database/mapping")
				}
				if len(state.queries) != 0 || len(state.base.committed) != 0 || attempt.state.authority.OperationPublicID != op || !attempt.state.authority.CapacityObservedAt.Equal(originalSample) {
					t.Fatal("SQL started or original operation/sample changed before KEK preparation")
				}
				return nil, preparationError
			}}
			if _, err := attempt.ApplyWithKEK(func() (*sql.DB, error) { opens++; return db, nil }, kek); err == nil {
				t.Fatal("failed or absent KEK preparation authorized new use", err)
			}
			if opens != 1 || prepares != 1 || len(state.queries) == 0 || len(state.base.committed) != 0 || db.Ping() == nil {
				t.Fatal("KEK refusal skipped original branch decision, leaked database or committed")
			}
			copy := *attempt
			if _, err := copy.ApplyWithKEK(func() (*sql.DB, error) { opens++; return db, nil }, kek); err != ErrRegistrationUnavailable || opens != 1 || prepares != 1 {
				t.Fatal("copied attempt repeated KEK preparation or database open", err)
			}
		})
	}
}

func TestBootstrapCandidateAttemptTypedNilKEKDoesNotOpenDatabase(t *testing.T) {
	attempt, _, state, _ := beforeDatabaseAttempt(t, context.Background())
	var kek *deploymentKEKPreparation
	if _, err := attempt.ApplyWithKEK(func() (*sql.DB, error) { t.Fatal("typed-nil KEK opened database"); return nil, nil }, kek); err != ErrRegistrationUnavailable || len(state.queries) != 0 {
		t.Fatal("typed-nil KEK accepted", err)
	}
}

func TestBootstrapDeploymentCandidatePassesCompiledKEKToOriginalAttempt(t *testing.T) {
	f := newDeploymentCandidateFixture(t)
	before := consumerIntegrationClone(f.sql.rows)
	prepares := 0
	f.deployment.kek = &deploymentKEKPreparation{prepare: func(ctx context.Context, _ *sql.DB, grant OfflineBootstrapGrant, config BootstrapConfig) (reg.PreparedAdmission, error) {
		prepares++
		if ctx != f.authority.preparedCtx || grant != f.deployment.grant || config.SHA256() != grant.ConfigSHA256 {
			t.Fatal("deployment lost original KEK attempt context or pins")
		}
		return nil, ErrRegistrationUnavailable
	}}
	if _, err := f.deployment.Apply(context.Background()); err != ErrRegistrationUnavailable || prepares != 1 || f.opens != 1 || f.authority.prepares != 1 {
		t.Fatal("deployment dropped KEK or re-prepared original authority", err, prepares, f.opens, f.authority.prepares)
	}
	if f.sql.reserves != 0 || f.sql.commits != 0 || !reflect.DeepEqual(before, f.sql.rows) {
		t.Fatal("missing KEK source reached fresh reservation or persistent writes")
	}
}
