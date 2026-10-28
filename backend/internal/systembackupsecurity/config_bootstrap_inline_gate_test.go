package systembackupsecurity

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
)

// Actual service/fence composition with the synthetic SQL driver, not proof
// of InnoDB isolation, complete metadata visibility or production authority.
func TestBootstrapInlineCannotInitializeAfterC1StorageExists(t *testing.T) {
	for _, invisible := range []bool{false, true} {
		svc, grant, raw, state := bootstrapServiceFixture(t)
		if invisible {
			state.probeError = &mysqldriver.MySQLError{Number: 1142, Message: "PRIVATE hidden C1 table"}
		} else {
			state.coreTables = true
		}
		result, err := svc.Bootstrap(context.Background(), grant, raw)
		if err == nil || result != (ConfigBootstrapResult{}) || state.validated != 0 || len(state.committed) != 0 || len(state.pending) != 0 || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("C1 storage or incomplete visibility bypassed legacy fence", invisible, result, err)
		}
	}
}

func TestBootstrapInlineExactHistoryMayReadWithoutDomainButNeverWriteAgain(t *testing.T) {
	svc, grant, raw, state := bootstrapServiceFixture(t)
	first, err := svc.Bootstrap(context.Background(), grant, raw)
	if err != nil {
		t.Fatal(err)
	}
	state.coreTables = true // Later C1 enrollment; no domain at this scope.
	history, err := svc.Bootstrap(context.Background(), grant, raw)
	if err != nil || !history.Replayed || history.OperationPublicID != first.OperationPublicID || state.validated != 1 || len(state.committed) != 6 {
		t.Fatal("exact independent historical read changed legacy result", history, err)
	}
	state.matrix = "k3s-single-node"
	if _, err = svc.Bootstrap(context.Background(), grant, raw); err != ErrBootstrapExists || state.validated != 1 || len(state.committed) != 6 {
		t.Fatal("historical config accepted a different installation matrix", err)
	}
}

type finalInlineAdmission struct {
	syntheticBootstrapAdmission
	mode    string
	expires time.Time
}

func (a *finalInlineAdmission) Authorize(ctx context.Context, tx *sql.Tx, g OfflineBootstrapGrant, c BootstrapConfig, now time.Time) error {
	if err := a.syntheticBootstrapAdmission.Authorize(ctx, tx, g, c, now); err != nil {
		return err
	}
	if !a.expires.IsZero() && !now.Before(a.expires) {
		return ErrRegistrationPermission
	}
	if a.s.authorized == 2 {
		switch a.mode {
		case "revoked":
			return ErrRegistrationPermission
		case "config":
			a.s.config["change_reason"] = "PRIVATE changed after source callback"
		case "clock":
			a.s.sqlNow = now.Add(-time.Microsecond)
		case "schema":
			a.s.coreTables = true
		case "matrix":
			a.s.matrix = "k3s-single-node"
		}
	}
	return nil
}

func TestBootstrapInlineLateAuthorizationAndFixedChecksRollback(t *testing.T) {
	for _, mode := range []string{"revoked", "config", "clock", "schema", "matrix"} {
		t.Run(mode, func(t *testing.T) {
			svc, grant, raw, state := bootstrapServiceFixture(t)
			state.sqlNow = time.Now().UTC().Truncate(time.Microsecond)
			svc.Admission = &finalInlineAdmission{syntheticBootstrapAdmission: syntheticBootstrapAdmission{state}, mode: mode}
			result, err := svc.Bootstrap(context.Background(), grant, raw)
			if err == nil || result != (ConfigBootstrapResult{}) || state.authorized != 2 || state.validated != 1 || len(state.committed) != 0 || len(state.pending) != 0 || state.matrix != "" || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("late source/SQL mutation committed", mode, result, err, state.authorized, state.validated)
			}
		})
	}
}

func TestBootstrapInlineUsesFreshSQLTimeAfterInstallationWait(t *testing.T) {
	svc, grant, raw, state := bootstrapServiceFixture(t)
	start := time.Now().UTC().Truncate(time.Microsecond)
	state.sqlNow = start
	state.afterInstallation = func() { state.sqlNow = start.Add(10 * time.Second) }
	svc.Admission = &finalInlineAdmission{syntheticBootstrapAdmission: syntheticBootstrapAdmission{state}, expires: start.Add(5 * time.Second)}
	if _, err := svc.Bootstrap(context.Background(), grant, raw); err != ErrRegistrationPermission || state.validated != 0 || len(state.committed) != 0 {
		t.Fatal("grant check reused pre-lock SQL sample", err)
	}
}

type preparedInlineContextAdmission struct {
	syntheticBootstrapAdmission
	want context.Context
}

func (a *preparedInlineContextAdmission) Authorize(ctx context.Context, tx *sql.Tx, g OfflineBootstrapGrant, c BootstrapConfig, now time.Time) error {
	if ctx != a.want {
		return ErrRegistrationPermission
	}
	return a.syntheticBootstrapAdmission.Authorize(ctx, tx, g, c, now)
}

func (a *preparedInlineContextAdmission) ValidateAndReserve(ctx context.Context, tx *sql.Tx, g OfflineBootstrapGrant, c BootstrapConfig, now time.Time) error {
	if ctx != a.want {
		return ErrRegistrationPermission
	}
	return a.syntheticBootstrapAdmission.ValidateAndReserve(ctx, tx, g, c, now)
}

func TestBootstrapInlinePreparedKeepsOriginalBoundedContext(t *testing.T) {
	t.Run("same preparation and authorization context", func(t *testing.T) {
		svc, grant, raw, state := bootstrapServiceFixture(t)
		config, err := DecodeBootstrapConfig(raw)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		svc.Admission = &preparedInlineContextAdmission{syntheticBootstrapAdmission{state}, ctx}
		result, err := svc.bootstrapLegacyPrepared(ctx, grant, config)
		if err != nil || result.Replayed || state.authorized != 2 || state.validated != 1 || len(state.committed) != 6 {
			t.Fatal("prepared context was replaced or original checks bypassed", result, err)
		}
	})
	t.Run("unbounded context rejected before SQL", func(t *testing.T) {
		svc, grant, raw, state := bootstrapServiceFixture(t)
		config, err := DecodeBootstrapConfig(raw)
		if err != nil {
			t.Fatal(err)
		}
		result, err := svc.bootstrapLegacyPrepared(context.Background(), grant, config)
		if err != ErrRegistrationUnavailable || result != (ConfigBootstrapResult{}) || len(state.queries) != 0 || state.authorized != 0 || state.validated != 0 || len(state.committed) != 0 {
			t.Fatal("unbounded preparation entered SQL", result, err)
		}
	})
}
