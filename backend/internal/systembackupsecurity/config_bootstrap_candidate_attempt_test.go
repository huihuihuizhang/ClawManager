package systembackupsecurity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// These use the real preparation/environment/transaction-owner code with the
// existing synthetic stage driver. They prove no real deployment authority,
// provider capability, MySQL gap lock or actual candidate consumption.
type beforeDatabaseAuthority struct {
	*candidateBridgeAuthority
	err        error
	sample     *time.Time
	preparedAt context.Context
}

func (a *beforeDatabaseAuthority) PrepareBootstrapCandidates(ctx context.Context, _ OfflineBootstrapGrant, _ BootstrapConfig, _ pd.BootstrapConsumptionRequest) (PreparedBootstrapCandidateAuthority, error) {
	a.state.phases = append(a.state.phases, "prepare")
	a.preparedAt = ctx
	if a.err != nil {
		return PreparedBootstrapCandidateAuthority{}, a.err
	}
	return PreparedBootstrapCandidateAuthority{Session: a.candidateBridgeAuthority, CapacityObservedAt: a.sample}, nil
}

func beforeDatabaseAttempt(t *testing.T, ctx context.Context) (*PreparedConfigBootstrapCandidateAttempt, *beforeDatabaseAuthority, *candidateBridgeState, *sql.DB) {
	t.Helper()
	p, state := candidateBridgeFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	authority := &beforeDatabaseAuthority{candidateBridgeAuthority: &candidateBridgeAuthority{state}, sample: &now}
	attempt, err := PrepareConfigBootstrapCandidateAttempt(ctx, p.grant, p.config.CanonicalJSON(), p.request.Candidates, authority, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(attempt.Close)
	return attempt, authority, state, p.db
}

func TestBootstrapCandidateAttemptPreparesBeforeDatabaseAndDoesNotRenew(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempt, authority, state, db := beforeDatabaseAttempt(t, parent)
	originalSample := *attempt.state.authority.CapacityObservedAt
	*authority.sample = originalSample.Add(time.Hour)
	if !attempt.state.authority.CapacityObservedAt.Equal(originalSample) {
		t.Fatal("preparation retained caller-owned capacity timestamp")
	}
	op := attempt.state.authority.OperationPublicID
	opens := 0
	_, err := attempt.Apply(func() (*sql.DB, error) {
		opens++
		if strings.Join(state.phases, ",") != "prepare" || authority.preparedAt != attempt.state.ctx || authority.preparedAt.Err() != nil {
			t.Fatal("database preceded preparation or context was replaced", state.phases)
		}
		return db, nil
	})
	// This stage-only driver has no C1 domain. A real D guard must fail closed;
	// the test must not turn its missing rows into a permissive authority.
	if err == nil || len(state.queries) == 0 || len(state.base.committed) != 0 {
		t.Fatal("unavailable SQL scope became candidate success", err, state.queries)
	}
	if opens != 1 || strings.Join(state.phases, ",") != "prepare" || attempt.state.authority.OperationPublicID != op || !attempt.state.authority.CapacityObservedAt.Equal(originalSample) {
		t.Fatal("database path renewed original preparation/op/sample")
	}
	if authority.preparedAt.Err() != context.Canceled || parent.Err() != nil {
		t.Fatal("attempt completion did not release only its own context")
	}
	if db.Ping() == nil {
		t.Fatal("Apply leaked its owned database")
	}
	copy := *attempt
	if _, err := copy.Apply(func() (*sql.DB, error) { opens++; return db, nil }); err != ErrRegistrationUnavailable || opens != 1 {
		t.Fatal("failed attempt reused through value copy", err, opens)
	}
}

func TestBootstrapCandidateAttemptPreparationFailureNeverNeedsDatabase(t *testing.T) {
	p, state := candidateBridgeFixture(t)
	authority := &beforeDatabaseAuthority{candidateBridgeAuthority: &candidateBridgeAuthority{state}, err: errors.New("PRIVATE original authority preparation")}
	attempt, err := PrepareConfigBootstrapCandidateAttempt(context.Background(), p.grant, p.config.CanonicalJSON(), p.request.Candidates, authority, false)
	if attempt != nil || err != ErrRegistrationUnavailable || strings.Contains(err.Error(), "PRIVATE") || len(state.queries) != 0 || strings.Join(state.phases, ",") != "prepare" {
		t.Fatal("failed independent preparation escaped or touched SQL", err, state.phases, state.queries)
	}
	var typedNil *candidateTypedNilContext
	if _, err = PrepareConfigBootstrapCandidateAttempt(typedNil, p.grant, p.config.CanonicalJSON(), p.request.Candidates, authority, false); err != ErrRegistrationUnavailable || len(state.phases) != 1 {
		t.Fatal("typed-nil context reached authority")
	}
	for _, invalid := range []time.Time{time.Time{}, time.Now().UTC().Truncate(time.Microsecond).Add(time.Nanosecond), time.Now().UTC().Truncate(time.Microsecond).In(time.FixedZone("not-UTC", 3600))} {
		authority.err, authority.sample = nil, &invalid
		if attempt, err = PrepareConfigBootstrapCandidateAttempt(context.Background(), p.grant, p.config.CanonicalJSON(), p.request.Candidates, authority, false); attempt != nil || err != ErrRegistrationUnavailable {
			t.Fatal("invalid prepared report sample reached database boundary", err)
		}
	}
}

func TestBootstrapCandidateAttemptCancellationAndConcurrentCopies(t *testing.T) {
	t.Run("canceled_before_open", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		attempt, _, _, _ := beforeDatabaseAttempt(t, ctx)
		cancel()
		if _, err := attempt.Apply(func() (*sql.DB, error) { t.Fatal("canceled attempt opened database"); return nil, nil }); err != ErrRegistrationUnavailable {
			t.Fatal(err)
		}
	})
	t.Run("shared_consumption", func(t *testing.T) {
		attempt, authority, _, _ := beforeDatabaseAttempt(t, context.Background())
		copy := *attempt
		entered, release := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		go func() {
			_, err := attempt.Apply(func() (*sql.DB, error) {
				close(entered)
				<-release
				return nil, errors.New("PRIVATE database unavailable")
			})
			done <- err
		}()
		<-entered
		_, err := copy.Apply(func() (*sql.DB, error) { t.Error("copy opened database twice"); return nil, nil })
		live := authority.preparedAt.Err() == nil
		close(release)
		winner := <-done
		if err != ErrRegistrationUnavailable || winner != ErrRegistrationUnavailable || !live {
			t.Fatal("losing copy canceled winner or leaked error", err, winner, live)
		}
		if _, err := json.Marshal(attempt); err == nil {
			t.Fatal("attempt serialized")
		}
	})
}

func TestBootstrapCandidateAttemptOpenerFailureClosesDatabaseAndSealsCopies(t *testing.T) {
	for _, mode := range []string{"database_and_error", "canceled_during_open", "nil_database"} {
		t.Run(mode, func(t *testing.T) {
			attempt, _, state, db := beforeDatabaseAttempt(t, context.Background())
			copy := *attempt
			opens := 0
			result, err := attempt.Apply(func() (*sql.DB, error) {
				opens++
				switch mode {
				case "database_and_error":
					return db, errors.New("PRIVATE opener diagnostic")
				case "canceled_during_open":
					attempt.Close()
					return db, nil
				default:
					return nil, nil
				}
			})
			if err != ErrRegistrationUnavailable || result != (ConfigBootstrapResult{}) || len(state.queries) != 0 || len(state.base.committed) != 0 || opens != 1 {
				t.Fatal("failed or canceled opener reached SQL", result, err, opens)
			}
			if mode != "nil_database" && db.PingContext(context.Background()) == nil {
				t.Fatal("failed opener leaked its database")
			}
			if _, err := copy.Apply(func() (*sql.DB, error) { opens++; return db, nil }); err != ErrRegistrationUnavailable || opens != 1 {
				t.Fatal("failed opener renewed through copied attempt", err, opens)
			}
		})
	}
}
