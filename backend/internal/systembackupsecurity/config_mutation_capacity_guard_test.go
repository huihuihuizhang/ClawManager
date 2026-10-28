package systembackupsecurity

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

// Explicit synthetic reservation used by the SQL orchestration model only.
// The production source is ConfigMutationCapacity, with a five-second sample.
type mutationTestCapacity struct {
	tx      *sql.Tx
	until   time.Time
	recheck func() error
}

func (r *mutationTestCapacity) ValidUntil() time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.until
}
func (r *mutationTestCapacity) Recheck(ctx context.Context, tx *sql.Tx, _ time.Time) error {
	if r == nil || tx != r.tx || ctx.Err() != nil {
		return ErrRegistrationUnavailable
	}
	if r.recheck != nil {
		return r.recheck()
	}
	return nil
}

type mutationCapacityGuardAuthority struct {
	ConfigMutationAuthority
	edit func(ConfigMutationCapacityReservation) ConfigMutationCapacityReservation
}

func (a mutationCapacityGuardAuthority) Reserve(ctx context.Context, tx *sql.Tx, old, proposed ConfigValues, bytes int, now time.Time) (ConfigMutationCapacityReservation, error) {
	r, err := a.ConfigMutationAuthority.Reserve(ctx, tx, old, proposed, bytes, now)
	if err != nil {
		return nil, err
	}
	return a.edit(r), nil
}

func TestConfigMutationCapacityFinalGuardRollsBack(t *testing.T) {
	for _, name := range []string{"nil", "typed-nil", "expired-on-admission", "final-recheck-failed", "expires-during-final-recheck", "still-valid"} {
		t.Run(name, func(t *testing.T) {
			svc, actor, raw, state, _ := mutationTransactionFixture(t)
			svc.Authority = mutationCapacityGuardAuthority{svc.Authority, func(r ConfigMutationCapacityReservation) ConfigMutationCapacityReservation {
				switch name {
				case "nil":
					return nil
				case "typed-nil":
					return (*mutationTestCapacity)(nil)
				case "expired-on-admission":
					r.(*mutationTestCapacity).until = state.now
				case "final-recheck-failed":
					r.(*mutationTestCapacity).recheck = func() error { return errors.New("PRIVATE capacity final failure") }
				case "expires-during-final-recheck", "still-valid":
					r.(*mutationTestCapacity).until = state.now.Add(time.Second)
					r.(*mutationTestCapacity).recheck = func() error {
						state.now = r.ValidUntil()
						if name == "still-valid" {
							state.now = state.now.Add(-time.Microsecond)
						}
						return nil
					}
				}
				return r
			}}
			result, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "capacity-final", raw, nil)
			if name == "still-valid" {
				if err != nil || result.Version != 2 || state.data.active != 2 {
					t.Fatal("valid capacity window rejected", err)
				}
				return
			}
			mutationARequireRollback(t, state, result, err)
			if err != ErrRegistrationUnavailable {
				t.Fatal("private error escaped or incorrect category", err)
			}
		})
	}
}
