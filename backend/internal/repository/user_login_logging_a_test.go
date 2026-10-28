package repository_test

import (
	"bytes"
	"context"
	"database/sql"
	"log"
	"strings"
	"testing"
	"time"

	"clawreef/internal/repository"
	upper "github.com/upper/db/v4"
	"github.com/upper/db/v4/adapter/mysql"
)

// upper/db logs failed/slow SQL with arguments even at its default WARN level.
// The login CAS carries a password hash; it must not pass through that logger.
func TestLoginStateFailureNeverLogsCredentialSnapshot(t *testing.T) {
	for _, fault := range []string{"closed-pool", "cancelled-session"} {
		t.Run(fault, func(t *testing.T) {
			connector := &loginStateInitConnector{}
			pool := sql.OpenDB(connector)
			t.Cleanup(func() { pool.Close() })
			session, err := mysql.New(pool)
			if err != nil {
				t.Fatal("could not initialize offline adapter")
			}
			t.Cleanup(func() { session.Close() })
			beforeLogger := upper.LC().(interface{ Logger() upper.Logger }).Logger()
			beforeLevel := upper.LC().Level()
			var captured bytes.Buffer
			upper.LC().SetLogger(log.New(&captured, "", 0))
			upper.LC().SetLevel(upper.LogLevelDebug)
			t.Cleanup(func() { upper.LC().SetLogger(beforeLogger); upper.LC().SetLevel(beforeLevel) })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if fault == "closed-pool" {
				if err := pool.Close(); err != nil {
					t.Fatal("could not close fixture pool")
				}
			} else {
				cancel()
				session = session.WithContext(ctx)
			}
			beforeCalls := connector.calls.Load()
			state := repository.LoginState{UserID: 45, PasswordHash: "PRIVATE_CREDENTIAL_SNAPSHOT_A", AuthProvider: "local", ExpectedRole: "admin", Role: "admin", At: time.Now().UTC()}
			err = repository.NewUserRepository(session).(repository.LoginStateRepository).UpdateLoginState(state)
			if err == nil || err.Error() != "login state unavailable" || connector.calls.Load() != beforeCalls {
				t.Fatal("SQL/context failure was not rejected before driver access")
			}
			if strings.Contains(captured.String(), state.PasswordHash) || strings.Contains(err.Error(), state.PasswordHash) {
				t.Fatal("credential snapshot entered the SQL failure log or public error")
			}
		})
	}
}
