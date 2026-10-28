package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	dispatch "clawreef/internal/systembackupdispatch"
)

func relayDispatchInputs(c RelayPeerConfig) (dispatch.Authority, dispatch.JobBinding) {
	b := c.Binding
	return dispatch.Authority{InstallationID: string(b.Scope.Installation), TaskPublicID: b.TargetPublicID, TaskType: b.TargetType,
			RequestID: "synthetic-relay-request", ConfigVersion: uint64(b.ConfigVersion), ConfigSHA256: b.ConfigSHA256,
			AttemptNo: uint64(b.AttemptNo), Phase: b.Phase, ClaimOwner: "synthetic-controller", ClaimRowVersion: 3,
			MaintenanceOwner: "synthetic-gate", MaintenanceFencingToken: 7, DeadlineAt: time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute)},
		dispatch.JobBinding{JobUnitKey: b.JobUnitKey, Namespace: "synthetic", Name: "synthetic-job", UID: b.JobUID,
			Generation: uint64(b.JobGeneration), RelayIdentityRef: b.RelayIdentityRef, RelayIdentityVersion: b.RelayIdentityVersion,
			RelayBoundAt: b.RelayIdentityBoundAt, RelayExpiresAt: b.RelayIdentityExpiresAt}
}

func TestDispatchRelayUsesPublicBindingAndOriginalDeadline(t *testing.T) {
	a, f, c := relayPeerFixture(t)
	current, job := relayDispatchInputs(c)
	p, err := a.AuthenticateRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(p.Context(), time.Minute)
	defer cancel()
	tx := new(sql.Tx)
	check, facts, err := a.BindDispatch(ctx, tx, p, c.Binding.Scope, current, job, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil || !facts.ValidUntil.Equal(current.DeadlineAt) {
		t.Fatal("deadline not bounded", err)
	}
	again, err := check.RecheckDispatch(ctx, tx, c.Binding.Scope, current, job, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil || !again.ValidUntil.Equal(facts.ValidUntil) {
		t.Fatal("original deadline changed", err)
	}
	if _, err := json.Marshal(check); err == nil {
		t.Fatal("guard serialized")
	}
	if json.Unmarshal([]byte(`{}`), &DispatchRelayCheck{}) == nil {
		t.Fatal("JSON minted guard")
	}
	if f.db.begins != 0 {
		t.Fatal("bridge opened SQL")
	}
}

func TestDispatchRelayRejectsChangedClaimFenceAndJob(t *testing.T) {
	mutations := map[string]func(*dispatch.Authority, *dispatch.JobBinding){
		"owner":            func(a *dispatch.Authority, _ *dispatch.JobBinding) { a.ClaimOwner = "other" },
		"claim_version":    func(a *dispatch.Authority, _ *dispatch.JobBinding) { a.ClaimRowVersion++ },
		"fence":            func(a *dispatch.Authority, _ *dispatch.JobBinding) { a.MaintenanceFencingToken++ },
		"gate_owner":       func(a *dispatch.Authority, _ *dispatch.JobBinding) { a.MaintenanceOwner = "other" },
		"request":          func(a *dispatch.Authority, _ *dispatch.JobBinding) { a.RequestID = "other" },
		"deadline_extend":  func(a *dispatch.Authority, _ *dispatch.JobBinding) { a.DeadlineAt = a.DeadlineAt.Add(time.Second) },
		"deadline_shorten": func(a *dispatch.Authority, _ *dispatch.JobBinding) { a.DeadlineAt = a.DeadlineAt.Add(-time.Second) },
		"namespace":        func(_ *dispatch.Authority, j *dispatch.JobBinding) { j.Namespace = "other" },
		"job_name":         func(_ *dispatch.Authority, j *dispatch.JobBinding) { j.Name = "other" },
		"job_generation":   func(_ *dispatch.Authority, j *dispatch.JobBinding) { j.Generation++ },
		"relay":            func(_ *dispatch.Authority, j *dispatch.JobBinding) { j.RelayIdentityRef = "other" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			a, f, c := relayPeerFixture(t)
			current, job := relayDispatchInputs(c)
			p, err := a.AuthenticateRequest(f.request)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(p.Context(), time.Minute)
			defer cancel()
			tx := new(sql.Tx)
			now := time.Now().UTC().Truncate(time.Microsecond)
			check, _, err := a.BindDispatch(ctx, tx, p, c.Binding.Scope, current, job, now)
			if err != nil {
				t.Fatal(err)
			}
			next, nextJob := current, job
			mutate(&next, &nextJob)
			copy := *check
			if _, err := copy.RecheckDispatch(ctx, tx, c.Binding.Scope, next, nextJob, now); err != ErrAuth {
				t.Fatal(name, err)
			}
			if _, err := check.RecheckDispatch(ctx, tx, c.Binding.Scope, current, job, now); err != ErrAuth {
				t.Fatal("failure reset")
			}
		})
	}
}

type nilRelayContext struct{ context.Context }

func TestDispatchRelayRejectsOverflowAndInvalidContext(t *testing.T) {
	for _, name := range []string{"config_overflow", "attempt_overflow", "generation_overflow", "missing_claim", "expired", "nil_context"} {
		t.Run(name, func(t *testing.T) {
			a, f, c := relayPeerFixture(t)
			current, job := relayDispatchInputs(c)
			p, err := a.AuthenticateRequest(f.request)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(p.Context(), time.Minute)
			defer cancel()
			switch name {
			case "config_overflow":
				current.ConfigVersion = 1 << 63
			case "attempt_overflow":
				current.AttemptNo = 1 << 63
			case "generation_overflow":
				job.Generation = 1 << 63
			case "missing_claim":
				current.ClaimRowVersion = 0
			case "expired":
				current.DeadlineAt = time.Now().UTC().Truncate(time.Microsecond)
			case "nil_context":
				var absent *nilRelayContext
				ctx = absent
			}
			if _, _, err := a.BindDispatch(ctx, new(sql.Tx), p, c.Binding.Scope, current, job, time.Now().UTC().Truncate(time.Microsecond)); err != ErrAuth {
				t.Fatal(name, err)
			}
		})
	}
}
