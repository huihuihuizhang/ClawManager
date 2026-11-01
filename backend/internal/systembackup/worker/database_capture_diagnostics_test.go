package worker

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	w "clawreef/internal/systembackupwire"
)

type databaseDiagnosticFailWriter struct{ err error }

func (v databaseDiagnosticFailWriter) Write([]byte) (int, error) { return 0, v.err }

func TestDatabaseFirstFailurePreservesLiveCallbackClockAndPrivacy(t *testing.T) {
	var output bytes.Buffer
	previous, flags := log.Writer(), log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	defer log.SetOutput(previous)
	defer log.SetFlags(flags)
	secret := "PRIVATE_SQL_ARGS_SOURCE_GRANT_TOKEN_BODY_MUST_NOT_APPEAR"
	type privateKey struct{}
	ctx, cancel := context.WithDeadline(context.WithValue(context.Background(), privateKey{}, secret), time.Now().Add(20*time.Second))
	var observed databaseCaptureFailure
	observed.observe("database-source-authorize", ctx, time.Now().Add(5*time.Second), time.Now().Add(time.Minute), time.Now())
	first := observed
	cancel() // WithDEK normally cancels its child when the callback returns.
	observed.observe("database-stream-or-staging", ctx, time.Time{}, time.Time{}, time.Now())
	observed.log(true, false)
	if observed != first || observed.context != "active" || !observed.keyKnown || !observed.contextKnown || !observed.sourceKnown || observed.keyRemaining <= 0 || observed.contextRemaining <= observed.keyRemaining || strings.Contains(output.String(), secret) || !strings.Contains(output.String(), "stage=database-source-authorize sentinel=database_rejected context=active") {
		t.Fatal("first failure/context or separate fixed clocks lost")
	}
}

type databaseDiagnosticNoConnect struct{ calls int }

func (v *databaseDiagnosticNoConnect) Connect(context.Context) (driver.Conn, error) {
	v.calls++
	return nil, errors.New("test forbids database I/O")
}
func (v *databaseDiagnosticNoConnect) Driver() driver.Driver { return v }
func (v *databaseDiagnosticNoConnect) Open(string) (driver.Conn, error) {
	v.calls++
	return nil, errors.New("test forbids database I/O")
}

func TestDatabaseFormalCallbackRecordsSourceRefusalBeforeAnyDatabaseIO(t *testing.T) {
	for _, mode := range []string{"source-authorize", "backend-capture"} {
		t.Run(mode, func(t *testing.T) { testDatabaseFormalCallbackBoundary(t, mode) })
	}
}

func testDatabaseFormalCallbackBoundary(t *testing.T, mode string) {
	i, env, key := formalInvocationFixture(t)
	i.Request.Operation = "capture-database"
	i.WorkspacePath = ""
	i.Request.Database = databaseRequestFixture(t).Request.Database
	i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
	i.Request.Files = nil
	connector := &databaseDiagnosticNoConnect{}
	env.Database = sql.OpenDB(connector)
	defer env.Database.Close()
	sourceChecks := 0
	secret := "PRIVATE_DATABASE_SOURCE_AUTHORIZATION_ERROR_MUST_NOT_APPEAR"
	env.SourceAuthorize = func(context.Context, Invocation) error {
		sourceChecks++
		if mode == "source-authorize" && sourceChecks == 2 {
			return errors.New(secret)
		}
		return nil
	}
	var output bytes.Buffer
	previous, flags := log.Writer(), log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	defer log.SetOutput(previous)
	defer log.SetFlags(flags)
	result, err := runFormalCapture(context.Background(), i, key, env)
	stage := "database-source-authorize"
	checksOK := sourceChecks == 2 && connector.calls == 0
	if mode == "backend-capture" {
		stage = "database-source-capture"
		checksOK = sourceChecks >= 2 && connector.calls == 1
	}
	if err == nil || result.Ciphertext.SHA256 != "" || !checksOK || key.calls != 1 || strings.Contains(output.String(), secret) || !strings.Contains(output.String(), "stage="+stage+" sentinel=database_rejected context=active") || !strings.Contains(output.String(), "callback_entered=true callback_succeeded=false") {
		t.Fatal("actual callback refusal lost or changed original source checks", sourceChecks, key.calls, connector.calls, output.String())
	}
}

func TestDatabaseCipherSinkDiagnosticPreservesOriginalChecksAndErrors(t *testing.T) {
	for _, mode := range []string{"healthy", "context", "key-before", "key-tail", "write"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			key := &formalKeyFixture{}
			var dst bytes.Buffer
			var writer io.Writer = &dst
			privateErr := errors.New("PRIVATE_DATABASE_WRITE_ERROR_MUST_NOT_APPEAR")
			want := ""
			switch mode {
			case "context":
				cancel()
				want = "database-cipher-sink-context"
			case "key-before":
				key.failAt = 1
				want = "database-cipher-sink-key-before"
			case "key-tail":
				key.failAt = 2
				want = "database-cipher-sink-key-tail"
			case "write":
				writer = databaseDiagnosticFailWriter{privateErr}
				want = "database-cipher-sink-write"
			}
			var stages []string
			sink := originalUseSink{ctx: ctx, job: key, dst: writer, onRejected: func(stage string, _ context.Context) { stages = append(stages, stage) }}
			n, err := sink.Write([]byte("opaque cipher DATA"))
			if mode == "healthy" {
				if err != nil || n == 0 || key.checks != 2 || len(stages) != 0 {
					t.Fatal("healthy sink check protocol changed")
				}
				return
			}
			if len(stages) != 1 || stages[0] != want {
				t.Fatal("wrong first sink boundary", stages)
			}
			if mode == "context" && err != context.Canceled || (mode == "key-before" || mode == "key-tail") && err != w.ErrStreamAuthority || mode == "write" && err != privateErr {
				t.Fatal("diagnostic changed original returned error")
			}
		})
	}
}

func TestDatabaseCaptureFailureDistinguishesActualContextFromKeyWindow(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	var observed databaseCaptureFailure
	observed.observe("database-dek-context", ctx, time.Now().Add(time.Minute), time.Now().Add(time.Hour), time.Now())
	if observed.context != "deadline" || observed.contextRemaining >= 0 || observed.keyRemaining <= 0 || observed.sourceRemaining <= observed.keyRemaining {
		t.Fatal("different original bounds collapsed")
	}
}
