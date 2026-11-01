package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

func TestDatabaseControlDiagnosticScopesOnlyOriginalDatabaseKeyCheck(t *testing.T) {
	for _, mode := range []string{"database-key-check", "database-other-action", "other-key-check"} {
		t.Run(mode, func(t *testing.T) {
			var output bytes.Buffer
			previous, flags := log.Writer(), log.Flags()
			log.SetOutput(&output)
			log.SetFlags(0)
			defer log.SetOutput(previous)
			defer log.SetFlags(flags)
			secret := "PRIVATE_SQL_ARGS_BODY_SOURCE_GRANT_TOKEN_MUST_NOT_APPEAR"
			req := worker.ControlRequest{Action: "key-check"}
			if mode != "other-key-check" {
				req.Invocation.Request.Database = &worker.DatabaseSpec{}
			}
			if mode == "database-other-action" {
				req.Action = "key-end"
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			guard, err := bindOriginalControlWorker(ctx, nil, c.SQLExecutionAuthority{}, d.Authority{TaskPublicID: secret, ClaimOwner: secret}, req)
			if err != c.ErrExecutionAuthority || guard != nil || strings.Contains(output.String(), secret) {
				t.Fatal("diagnostic changed rejection or exposed authority")
			}
			if mode == "database-key-check" {
				if !strings.Contains(output.String(), "stage=controller-key-check-bind boundary=bind-dependencies class=context_canceled") {
					t.Fatal("missing scoped fixed bind diagnostic")
				}
			} else if output.Len() != 0 {
				t.Fatal("diagnostic escaped database key-check scope")
			}
		})
	}
}

func TestDatabaseKeyUseDiagnosticUsesOriginalSQLClockWithoutPrivateRow(t *testing.T) {
	for _, mode := range []string{"original-expired", "execution-expired", "invalid-row", "unknown-row-field", "trailing-row", "current-shorter"} {
		t.Run(mode, func(t *testing.T) {
			var output bytes.Buffer
			previous, flags := log.Writer(), log.Flags()
			log.SetOutput(&output)
			log.SetFlags(0)
			defer log.SetOutput(previous)
			defer log.SetFlags(flags)
			now := time.Now().UTC()
			secret := "PRIVATE_SQL_ROW_NONCE_GRANT_TOKEN_MUST_NOT_APPEAR"
			original := worker.KeyUseLease{Nonce: secret, Until: now.Add(time.Minute)}
			current := worker.KeyUseLease{Until: now.Add(2 * time.Minute)}
			want := "original_key_window_expired"
			switch mode {
			case "original-expired":
				original.Until = now
			case "execution-expired":
				current.Until = now
				want = "current_execution_bound_expired"
			case "invalid-row", "unknown-row-field", "trailing-row":
				want = "original_key_record_unavailable"
			case "current-shorter":
				current.Until = now.Add(time.Second)
				want = "current_execution_bound_shorter"
			}
			raw, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "invalid-row" {
				raw = []byte(secret)
			}
			if mode == "unknown-row-field" {
				raw = append(raw[:len(raw)-1], []byte(`,"private_unknown":"`+secret+`"}`)...)
			}
			if mode == "trailing-row" {
				raw = append(raw, []byte(`{}`)...)
			}
			logOriginalDatabaseKeyUseRejection(now, current, raw)
			if strings.Contains(output.String(), secret) || !strings.Contains(output.String(), "reason="+want) {
				t.Fatal("original key SQL-clock reason missing or private row exposed")
			}
		})
	}
}
