package systembackupexecution

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

// Original separate-read composition retained ONLY as an equivalence baseline:
// current config/forward flag, separate effective row, then the unchanged
// generic identity's current account/status/profile/purpose checks.
func separateEffectiveBaseline(ctx context.Context, tx *sql.Tx, service *DeploymentService, a d.Authority, now time.Time) (c.ExecutionAuthorizationGuard, error) {
	if err := (deploymentAuthorization{Service: service}).check(ctx, tx, a); err != nil {
		return nil, err
	}
	var enabled bool
	if tx.QueryRowContext(ctx, "SELECT last_effective_enabled FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR SHARE", a.InstallationID).Scan(&enabled) != nil || !enabled {
		return nil, c.ErrExecutionAuthority
	}
	guard, err := service.Forward.AuthorizeExecution(ctx, tx, a, now)
	if err != nil {
		return nil, err
	}
	return separateEffectiveGuard{service: service, grant: guard}, nil
}

type separateEffectiveGuard struct {
	service *DeploymentService
	grant   c.ExecutionAuthorizationGuard
}

func (g separateEffectiveGuard) ValidUntil() time.Time { return g.grant.ValidUntil() }
func (g separateEffectiveGuard) RecheckExecution(ctx context.Context, tx *sql.Tx, a d.Authority, now time.Time) error {
	if err := (deploymentAuthorization{Service: g.service}).check(ctx, tx, a); err != nil {
		return err
	}
	var enabled bool
	if tx.QueryRowContext(ctx, "SELECT last_effective_enabled FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR SHARE", a.InstallationID).Scan(&enabled) != nil || !enabled {
		return c.ErrExecutionAuthority
	}
	return g.grant.RecheckExecution(ctx, tx, a, now)
}

func TestDeploymentEffectiveCurrentFactsMatchSeparateBaselineMySQL(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	for _, prepareAllowed := range []bool{false, true} {
		t.Run(map[bool]string{false: "capture-only", true: "prepare-and-capture"}[prepareAllowed], func(t *testing.T) {
			owner, service, _, _, a, _, _, _, refresh := newConsumerMySQLFixtureOptions(t, &consumerFixtureOptions{ConfigureGrant: func(grant *c.ExecutionGrant) {
				if prepareAllowed {
					grant.Actions = []string{"prepare", "capture"}
				}
			}})
			refresh()
			ctx := context.Background()
			for _, test := range []struct {
				name, status              string
				enabled, prepare, allowed bool
			}{
				{"capture", "capturing", true, false, true},
				{"disabled", "capturing", false, false, false},
				{"preparing", "preparing", true, true, prepareAllowed},
				{"ready", "ready_for_capture", true, true, prepareAllowed},
				{"acquiring", "acquiring_gate", true, true, prepareAllowed},
			} {
				t.Run(test.name, func(t *testing.T) {
					tx, err := owner.Gate.Authority.DB.BeginTx(ctx, nil)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback()
					if _, err = owner.Gate.Authority.Bind(ctx, tx, a); err != nil {
						t.Fatal("original gate/business locks", err)
					}
					if _, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_backups SET status=?", test.status); err != nil {
						t.Fatal(err)
					}
					if _, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_installation_state SET last_effective_enabled=?", test.enabled); err != nil {
						t.Fatal(err)
					}
					candidate := a
					if test.prepare {
						candidate.MaintenanceOwner = ""
						candidate.MaintenanceFencingToken = 0
					}
					var now time.Time
					if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
						t.Fatal("original SQL clock")
					}
					old, oldErr := separateEffectiveBaseline(ctx, tx, service, candidate, now)
					current, newErr := (deploymentAuthorization{Service: service}).AuthorizeExecution(ctx, tx, candidate, now)
					if (oldErr == nil) != test.allowed || (newErr == nil) != test.allowed {
						t.Fatal("batched current facts differ from original separate reads", test.allowed, oldErr, newErr)
					}
					if test.allowed {
						if !old.ValidUntil().Equal(current.ValidUntil()) || old.RecheckExecution(ctx, tx, candidate, now) != nil || current.RecheckExecution(ctx, tx, candidate, now) != nil {
							t.Fatal("original purpose/window/current guard changed")
						}
					}
				})
			}
		})
	}
}
