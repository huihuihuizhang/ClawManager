package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"
)

type mutationReplayGuardResponses struct {
	ConfigMutationResponses
	wrap func(PreparedConfigMutationResponseRead) PreparedConfigMutationResponseRead
}

func (s mutationReplayGuardResponses) Read(ctx context.Context, in ConfigMutationResponseReplayPreparation) (PreparedConfigMutationResponseRead, error) {
	r, err := s.ConfigMutationResponses.Read(ctx, in)
	if err != nil {
		return nil, err
	}
	return s.wrap(r), nil
}

type mutationReplayGuardRead struct {
	PreparedConfigMutationResponseRead
	until time.Time
	after func()
}

func (r *mutationReplayGuardRead) ValidUntil() time.Time { return r.until }
func (r *mutationReplayGuardRead) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if err := r.PreparedConfigMutationResponseRead.Recheck(ctx, tx, now); err != nil {
		return err
	}
	if r.after != nil {
		r.after()
	}
	return nil
}
func TestConfigMutationReplayFinalReadCallbackCannotExtendOrOutliveGrant(t *testing.T) {
	for _, name := range []string{"already-expired", "extended-in-recheck", "expired-in-last-callback", "revoked-in-read-recheck", "valid-boundary"} {
		t.Run(name, func(t *testing.T) {
			svc, actor, raw, s, _ := mutationTransactionFixture(t)
			first, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "replay-first", raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			writes, prepares, strongCalls := len(s.data.writes), s.prepares, s.strongCalls
			until := s.now.Add(time.Second)
			if name == "already-expired" {
				until = s.now
			}
			svc.Responses = mutationReplayGuardResponses{svc.Responses, func(r PreparedConfigMutationResponseRead) PreparedConfigMutationResponseRead {
				guard := &mutationReplayGuardRead{PreparedConfigMutationResponseRead: r, until: until}
				guard.after = func() {
					switch name {
					case "extended-in-recheck":
						guard.until = until.Add(time.Second)
					case "expired-in-last-callback":
						s.now = until
					case "revoked-in-read-recheck":
						s.permissions["configure"] = false
					case "valid-boundary":
						s.now = until.Add(-time.Microsecond)
					}
				}
				return guard
			}}
			result, err := svc.ObserveCommitted(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "replay-final-clock", raw)
			if name == "valid-boundary" {
				if err != nil || !result.Replayed || !bytes.Equal(result.Response, first.Response) {
					t.Fatal("valid replay rejected", err)
				}
			} else if (name != "revoked-in-read-recheck" && err != ErrRegistrationUnavailable) || (name == "revoked-in-read-recheck" && err != ErrRegistrationPermission) || result.Replayed || result.Response != nil {
				t.Fatal("expired or extended replay succeeded", err)
			}
			if len(s.data.writes) != writes || s.prepares != prepares || s.strongCalls != strongCalls || s.data.active != 2 || len(s.data.rows) != 2 {
				t.Fatal("replay repeated write/provider preparation/proof consumption")
			}
		})
	}
}
