package systembackupsecurity

import (
	"context"
	"testing"
	"time"
)

type mutationResponseGuardSource struct {
	ConfigMutationResponses
	until time.Time
}
type mutationResponseGuardPrepared struct {
	PreparedConfigMutationOperationResponse
	until time.Time
}

func (p mutationResponseGuardPrepared) ValidUntil() time.Time { return p.until }
func (s mutationResponseGuardSource) Prepare(ctx context.Context, in ConfigMutationOperationPreparation) (PreparedConfigMutationOperationResponse, error) {
	p, err := s.ConfigMutationResponses.Prepare(ctx, in)
	if err != nil {
		return nil, err
	}
	return mutationResponseGuardPrepared{p, s.until}, nil
}
func TestConfigMutationResponseExpiryAfterLastCallbackRollsBack(t *testing.T) {
	for _, name := range []string{"expired-before-stage", "expires-in-last-capacity-check", "valid-boundary"} {
		t.Run(name, func(t *testing.T) {
			svc, actor, raw, state, _ := mutationTransactionFixture(t)
			until := state.now.Add(time.Second)
			if name == "expired-before-stage" {
				until = state.now
			}
			svc.Responses = mutationResponseGuardSource{svc.Responses, until}
			if name != "expired-before-stage" {
				svc.Authority = mutationCapacityGuardAuthority{svc.Authority, func(r ConfigMutationCapacityReservation) ConfigMutationCapacityReservation {
					r.(*mutationTestCapacity).recheck = func() error {
						state.now = until
						if name == "valid-boundary" {
							state.now = state.now.Add(-time.Microsecond)
						}
						return nil
					}
					return r
				}}
			}
			result, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "response-final-clock", raw, nil)
			if name == "valid-boundary" {
				if err != nil || result.Version != 2 || state.data.active != 2 {
					t.Fatal("valid response bound rejected", err)
				}
				return
			}
			mutationARequireRollback(t, state, result, err)
			if err != ErrRegistrationUnavailable {
				t.Fatal("response expiry decision", err)
			}
		})
	}
}
