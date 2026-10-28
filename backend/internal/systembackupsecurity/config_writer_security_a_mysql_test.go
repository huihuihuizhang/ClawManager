//go:build systembackup_mysql

package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Never infer database expiry from a host-side sleep. Each successful wait
// observes the actual DB UTC clock reaching the exact immutable bound.
func waitConfigWriterADBExpiry(ctx context.Context, until time.Time, sample func(context.Context) (time.Time, error)) error {
	if ctx == nil || ctx.Err() != nil || sample == nil || !configOperationResponseTime(until) {
		return ErrRegistrationUnavailable
	}
	var previous time.Time
	for {
		now, err := sample(ctx)
		if err != nil || ctx.Err() != nil || !configOperationResponseTime(now) || !previous.IsZero() && now.Before(previous) {
			return ErrRegistrationUnavailable
		}
		if !now.Before(until) {
			return nil
		}
		previous = now
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ErrRegistrationUnavailable
		}
	}
}

func configWriterASample(q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) func(context.Context) (time.Time, error) {
	return func(ctx context.Context) (time.Time, error) {
		var now time.Time
		err := q.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now)
		return now, err
	}
}

type configWriterAFinalWaitAuthority struct {
	ConfigMutationAuthority
	identity DatabaseIdentity
	until    time.Time
	observed bool
}

func (a *configWriterAFinalWaitAuthority) Authorize(ctx context.Context, tx *sql.Tx, actor RegistrationActor, installation string, current, proposed ConfigValues, risk ConfigMutationRisk, now time.Time) error {
	if err := a.ConfigMutationAuthority.Authorize(ctx, tx, actor, installation, current, proposed, risk, now); err != nil {
		return err
	}
	var active int64
	if tx.QueryRowContext(ctx, "SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=?", installation).Scan(&active) != nil {
		return ErrRegistrationUnavailable
	}
	if active == 2 {
		// Same transaction sees the new CAS value: this is genuinely after the
		// config/evidence/operation/nonce/result audit writes, before commit.
		if err := waitConfigWriterADBExpiry(ctx, a.until, configWriterASample(tx)); err != nil {
			return err
		}
		a.observed = true
	}
	return nil
}

func (a *configWriterAFinalWaitAuthority) Reserve(ctx context.Context, tx *sql.Tx, current, proposed ConfigValues, size int, now time.Time) (ConfigMutationCapacityReservation, error) {
	if _, err := a.ConfigMutationAuthority.Reserve(ctx, tx, current, proposed, size, now); err != nil {
		return nil, err
	}
	// Synthetic capacity is deliberately valid longer than the one-minute
	// actual issuer proof, so this test isolates proof/session expiry.
	return configWriterSyntheticCapacity{tx, a.identity, now.Add(2 * time.Minute)}, nil
}

func startAConfigWriterWorker(t *testing.T, ctx context.Context, f *configWriterMySQLFixture, key string, raw []byte) sessionProbeWorker {
	t.Helper()
	db, err := sql.Open("mysql", f.proof.cfg.FormatDSN())
	mysqlMust(t, err)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var id int64
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&id))
	work, cancel := context.WithTimeout(ctx, 25*time.Second)
	result, done := make(chan error, 1), make(chan struct{})
	svc := f.svc
	svc.DB = db
	go func() {
		defer close(done)
		out, err := svc.Mutate(work, f.proof.actor, ConfigUpdateEndpoint, key, "a-writer-row-wait", raw, nil)
		if !reflect.DeepEqual(out, ConfigMutationResult{}) {
			err = errors.New("failed writer worker returned nonempty result")
		}
		result <- err
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("writer security worker did not drain")
		}
		db.Close()
	})
	return sessionProbeWorker{id: id, result: result}
}

func runAConfigWriterSecurityCases(t *testing.T, parent context.Context, db *sql.DB, cfg *mysql.Config, identity DatabaseIdentity) {
	for _, name := range []string{"observed_session_lock_revocation", "observed_session_lock_expiry", "session_expires_after_cas", "proof_expires_after_cas", "revocation_during_unlocked_prepare", "rollback_reduction_requires_fresh_proof"} {
		if !t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(parent, 90*time.Second)
			defer cancel()
			p := newConfigProofMySQLFixture(t, ctx, db, cfg, identity)
			f := newConfigWriterMySQLFixture(t, p)
			key := "a_writer_security_key_012345"
			if name == "observed_session_lock_expiry" || name == "session_expires_after_cas" {
				var passwordHash string
				mysqlMust(t, db.QueryRowContext(ctx, "SELECT password_hash FROM users WHERE id=?", p.userID).Scan(&passwordHash))
				p.login(t, 5*time.Second, passwordHash)
			}
			raw := f.request(t, ConfigUpdateEndpoint, 1)
			before := f.counts(t)
			switch name {
			case "observed_session_lock_revocation", "observed_session_lock_expiry":
				block, err := db.BeginTx(ctx, nil)
				mysqlMust(t, err)
				defer block.Rollback()
				if name == "observed_session_lock_revocation" {
					changed, err := block.ExecContext(ctx, "UPDATE system_backup_v2_admin_sessions SET revoked=TRUE WHERE origin_installation_id=? AND session_sha256=?", p.installation, p.actor.Session)
					mysqlMust(t, err)
					if !configMutationOne(changed, nil) {
						t.Fatal("did not lock/revoke exactly one owned session")
					}
				} else {
					var session string
					mysqlMust(t, block.QueryRowContext(ctx, "SELECT session_sha256 FROM system_backup_v2_admin_sessions WHERE origin_installation_id=? AND session_sha256=? FOR UPDATE", p.installation, p.actor.Session).Scan(&session))
					if session != p.actor.Session || !configProofDBNow(t, ctx, db).Before(p.actor.SessionExpiresAt) {
						t.Fatal("session already expired before worker began")
					}
				}
				worker := startAConfigWriterWorker(t, ctx, f, key, raw)
				(sessionMySQLProbe{db: db, identity: identity}).waiting(t, ctx, worker, "system_backup_v2_admin_sessions")
				if name == "observed_session_lock_expiry" {
					mysqlMust(t, waitConfigWriterADBExpiry(ctx, p.actor.SessionExpiresAt, configWriterASample(db)))
				}
				mysqlMust(t, block.Commit())
				if err := sessionWorkerResult(t, ctx, worker); !errors.Is(err, ErrRegistrationPermission) {
					t.Fatalf("writer survived observed revoked/expired session lock: %v", err)
				}
			case "session_expires_after_cas", "proof_expires_after_cas":
				until := p.actor.SessionExpiresAt
				var proof *Proof
				if name == "proof_expires_after_cas" {
					f.readiness.risk.SecurityBoundary = true
					f.svc.Resolver = configWriterSyntheticResolver{readiness: f.readiness}
					request, err := DecodeConfigMutationRequest(ConfigUpdateEndpoint, raw)
					mysqlMust(t, err)
					issued, err := p.svc.VerifyConfigMutationAndIssue(ctx, p.actor, p.password, p.code(t), request, key)
					mysqlMust(t, err)
					until, err = time.Parse(time.RFC3339Nano, issued.Payload.ExpiresAt)
					mysqlMust(t, err)
					proof = &issued
				}
				if !configProofDBNow(t, ctx, db).Before(until) {
					t.Fatal("temporal bound expired before writer began")
				}
				authority := &configWriterAFinalWaitAuthority{ConfigMutationAuthority: f.svc.Authority, identity: identity, until: until}
				f.svc.Authority = authority
				out, err := f.svc.Mutate(ctx, p.actor, ConfigUpdateEndpoint, key, "a-writer-final-expiry", raw, proof)
				if !authority.observed || !reflect.DeepEqual(out, ConfigMutationResult{}) {
					t.Fatal("expiry not observed after actual SQL CAS or partial result released")
				}
				if proof == nil {
					if !errors.Is(err, ErrRegistrationPermission) {
						t.Fatalf("expired final session classification: %v", err)
					}
				} else {
					var failure *VerificationError
					if !errors.As(err, &failure) || failure == nil || failure.Code != FailureExpired {
						t.Fatalf("expired final proof classification: %v", err)
					}
				}
			case "revocation_during_unlocked_prepare":
				f.svc.Resolver = configWriterSyntheticResolver{readiness: f.readiness, prepare: func() {
					changed, err := db.ExecContext(ctx, "UPDATE system_backup_v2_admin_sessions SET revoked=TRUE WHERE origin_installation_id=? AND session_sha256=?", p.installation, p.actor.Session)
					mysqlMust(t, err)
					if !configMutationOne(changed, nil) {
						t.Fatal("prepare did not revoke exactly one owned session")
					}
				}}
				out, err := f.svc.Mutate(ctx, p.actor, ConfigUpdateEndpoint, key, "a-writer-prepare-revoke", raw, nil)
				if !errors.Is(err, ErrRegistrationPermission) || !reflect.DeepEqual(out, ConfigMutationResult{}) {
					t.Fatalf("prepare-time revocation survived new transaction: %v", err)
				}
			case "rollback_reduction_requires_fresh_proof":
				runAConfigWriterRollbackReduction(t, ctx, f, key)
				return
			}
			if !reflect.DeepEqual(before, f.counts(t)) {
				t.Fatal("rejected writer retained config/CAS/evidence/operation/nonce/audit effects")
			}
			t.Log("PASS writer security rejection: actual_db_observation=yes committed_mutation_effects=none")
		}) {
			return
		}
	}
}

func configWriterASecurityProposed(t *testing.T, proposed ConfigValues) ConfigValues {
	t.Helper()
	var config map[string]json.RawMessage
	mysqlMust(t, json.Unmarshal(proposed.CanonicalJSON(), &config))
	var durations map[string]json.RawMessage
	mysqlMust(t, json.Unmarshal(config["durations"], &durations))
	durations["retention_seconds"] = json.RawMessage(`5184000`)
	durations["evidence_retention_seconds"] = json.RawMessage(`5184000`)
	var err error
	config["durations"], err = json.Marshal(durations)
	mysqlMust(t, err)
	encoded, err := json.Marshal(config)
	mysqlMust(t, err)
	result, err := DecodeConfigValues(encoded)
	mysqlMust(t, err)
	return result
}

func runAConfigWriterRollbackReduction(t *testing.T, ctx context.Context, f *configWriterMySQLFixture, key string) {
	t.Helper()
	p := f.proof
	f.proposed = configWriterASecurityProposed(t, f.proposed)
	raw := f.request(t, ConfigUpdateEndpoint, 1)
	first, err := f.svc.Mutate(ctx, p.actor, ConfigUpdateEndpoint, key, "a-writer-retention-increase", raw, nil)
	mysqlMust(t, err)
	f.checkCommitted(t, first, ConfigUpdateEndpoint, key, raw, 2)
	rollback := f.request(t, ConfigRollbackEndpoint, 2)
	before := f.counts(t)
	out, err := f.svc.Mutate(ctx, p.actor, ConfigRollbackEndpoint, key+"_rollback", "a-writer-rollback-no-proof", rollback, nil)
	var auth *VerificationError
	if !errors.As(err, &auth) || auth == nil || auth.Code != FailureRequired || !reflect.DeepEqual(out, ConfigMutationResult{}) || !reflect.DeepEqual(before, f.counts(t)) {
		t.Fatal("rollback bypassed actual retention reduction/MFA or occupied a key", err)
	}
	// Refresh only this synthetic process's exact config pin after the known
	// successful update; keep the actual SQL MFA/session/RBAC implementation.
	tx, err := p.db.BeginTx(ctx, nil)
	mysqlMust(t, err)
	p.current, err = lockRegistrationConfig(ctx, tx, p.installation)
	mysqlMust(t, err)
	mysqlMust(t, tx.Rollback())
	pinned, ok := f.svc.Authority.(*PinnedConfigMutationAuthority)
	if !ok {
		t.Fatal("expected actual pinned authority")
	}
	current := configuredAuthority{database: p.identity, expected: p.current, PinnedRegistrationAuthority: PinnedRegistrationAuthority{InstallationID: p.installation, RegistryBytes: pinned.sources.RegistryBytes}}
	p.svc.Authorize = current.AuthorizeMFA
	request, err := DecodeConfigMutationRequest(ConfigRollbackEndpoint, rollback)
	mysqlMust(t, err)
	proof, err := p.svc.VerifyConfigMutationAndIssue(ctx, p.actor, p.password, p.code(t), request, key+"_rollback")
	mysqlMust(t, err)
	committed, err := f.svc.Mutate(ctx, p.actor, ConfigRollbackEndpoint, key+"_rollback", "a-writer-rollback-proof", rollback, &proof)
	mysqlMust(t, err)
	f.checkCommitted(t, committed, ConfigRollbackEndpoint, key+"_rollback", rollback, 3)
	if !reflect.DeepEqual(f.counts(t), []int64{3, 3, 3, 2, 2, 1, 4}) {
		t.Fatal("protected rollback did not append exactly one result/nonce/audit pair")
	}
	before = f.counts(t)
	replay, err := f.svc.Mutate(ctx, p.actor, ConfigRollbackEndpoint, key+"_rollback", "a-writer-rollback-replay", rollback, nil)
	mysqlMust(t, err)
	if !replay.Replayed || !bytes.Equal(replay.Response, committed.Response) || !reflect.DeepEqual(before, f.counts(t)) {
		t.Fatal("protected rollback replay consumed a new proof or rewrote SQL")
	}
}

func TestAConfigWriterSecurityClockSeed(t *testing.T) {
	base := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	for _, name := range []string{"sampled-expiry", "cancel-before", "cancel-during", "query-error", "clock-backwards", "zero-clock", "invalid-bound", "no-clock-progress", "rollback-fixture"} {
		t.Run(name, func(t *testing.T) {
			if name == "rollback-fixture" {
				current, err := DecodeConfigValues(bootstrapFixture(t))
				mysqlMust(t, err)
				raised := configWriterASecurityProposed(t, configWriterProposed(t, current))
				if !configMutationBaseRisk(raised, current).ProtectionReduction || configMutationBaseRisk(current, raised).ProtectionReduction {
					t.Fatal("real decoder/classifier fixture does not isolate rollback protection reduction")
				}
				return
			}
			budget := time.Second
			if name == "no-clock-progress" {
				budget = 30 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			calls, until := 0, base.Add(time.Second)
			if name == "cancel-before" {
				cancel()
			}
			if name == "invalid-bound" {
				until = time.Time{}
			}
			err := waitConfigWriterADBExpiry(ctx, until, func(context.Context) (time.Time, error) {
				calls++
				switch name {
				case "cancel-during":
					cancel()
					return until, nil
				case "query-error":
					return time.Time{}, errors.New("synthetic private clock error")
				case "zero-clock":
					return time.Time{}, nil
				case "clock-backwards":
					return base.Add(time.Duration(1-calls) * time.Second), nil
				case "no-clock-progress":
					return base, nil
				}
				return base.Add(time.Duration(calls-1) * time.Second), nil
			})
			if name == "sampled-expiry" {
				if err != nil || calls != 2 {
					t.Fatal("DB observation did not determine expiry", err)
				}
			} else if err != ErrRegistrationUnavailable {
				t.Fatal("no actual valid expiry observation accepted", err)
			}
		})
	}
}
