package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	cd "clawreef/internal/systembackupcapturedescription"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	"github.com/go-sql-driver/mysql"
)

func TestDescriptionControlBindDiagnosticPreservesRejection(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := worker.ControlRequest{Action: "key-check"}
	request.Invocation.Request.Operation = cd.Operation
	request.Invocation.Request.CaptureDescription = &cd.Seed{}
	guard, err := bindOriginalControlWorker(ctx, nil, c.SQLExecutionAuthority{}, d.Authority{}, request)
	if guard != nil || err != c.ErrExecutionAuthority || !strings.Contains(output.String(), "[system-backup-description] stage=controller-key-check-bind boundary=bind-dependencies class=context_canceled") {
		t.Fatal("diagnostic changed original authority rejection", err, output.String())
	}
}

func TestDescriptionDiagnosticsNeverFormatPrivateErrorsOrRows(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	secret := "PRIVATE_SOURCE_AUTHORITY_SQL_TOKEN_BODY"
	cause := errors.Join(errors.New(secret), &mysql.MySQLError{Number: 3572, SQLState: [5]byte{'H', 'Y', '0', '0', '0'}, Message: secret})
	logOriginalDescriptionFailure("description-original-authority", context.Background(), time.Now().Add(time.Second), 17, 9, cause)
	if !strings.Contains(output.String(), "sql_number=3572 sql_state=HY000 claim_version=17 epoch=9") || strings.Contains(output.String(), secret) {
		t.Fatal("driver diagnostic leaked private text or lost original identity metadata")
	}
	output.Reset()
	now := time.Now().UTC()
	row, _ := json.Marshal(worker.KeyUseLease{Nonce: secret, Until: now.Add(time.Minute)})
	logOriginalDescriptionKeyUseRejection(now, worker.KeyUseLease{Until: now.Add(10 * time.Second)}, row)
	if !strings.Contains(output.String(), "reason=current_execution_bound_shorter") || strings.Contains(output.String(), secret) {
		t.Fatal("key-use diagnostic changed class or leaked a private row")
	}
}
