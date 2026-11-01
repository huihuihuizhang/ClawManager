package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
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
	k "clawreef/internal/systembackupkms"
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

// An error-only database/sql driver: every query returns a concrete driver
// failure, so no SQL fact, passed guard or source authority can be fabricated.
type descriptionErrorConnector struct {
	queries *int
	cause   error
}

func (d descriptionErrorConnector) Connect(context.Context) (driver.Conn, error) {
	return descriptionErrorConnection{d}, nil
}
func (d descriptionErrorConnector) Driver() driver.Driver { return d }
func (d descriptionErrorConnector) Open(string) (driver.Conn, error) {
	return d.Connect(context.Background())
}

type descriptionErrorConnection struct{ descriptionErrorConnector }

func (descriptionErrorConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("error-only fixture cannot prepare SQL")
}
func (descriptionErrorConnection) Close() error { return nil }
func (descriptionErrorConnection) Begin() (driver.Tx, error) {
	return descriptionErrorTransaction{}, nil
}
func (descriptionErrorConnection) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return descriptionErrorTransaction{}, nil
}
func (d descriptionErrorConnection) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	*d.queries += 1
	return nil, d.cause
}

type descriptionErrorTransaction struct{}

func (descriptionErrorTransaction) Commit() error {
	return errors.New("error-only fixture cannot commit")
}
func (descriptionErrorTransaction) Rollback() error { return nil }

func TestDescriptionAuthorityKeepsSingleLookupDriverFailure(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	secret := "PRIVATE_DRIVER_MESSAGE_AND_SQL_ARGUMENTS"
	calls := 0
	db := sql.OpenDB(descriptionErrorConnector{queries: &calls, cause: &mysql.MySQLError{Number: 3572, SQLState: [5]byte{'H', 'Y', '0', '0', '0'}, Message: secret}})
	defer db.Close()
	s := &DeploymentService{Runtime: &PublicCapture{Owner: &PublicJobOwner{Gate: c.SQLCaptureGate{Authority: c.SQLExecutionAuthority{DB: db}}}}}
	request := worker.ControlRequest{}
	request.Invocation.ProviderKey = &k.Access{}
	key := &request.Invocation.ProviderKey.Request.Context
	key.InstallationID, key.BackupPublicID, key.AttemptNo = "installation_description_data", "sbk_11111111-1111-4111-8111-111111111111", "1"
	request.Invocation.FormalCapture = &worker.FormalCaptureSpec{SourceConfigSHA256: strings.Repeat("e", 64)}
	lease := worker.Lease{ExpiresAt: time.Now().Add(time.Second), KeyUse: &worker.KeyUseLease{State: "using"}}
	authority, err := s.descriptionAuthority(context.Background(), request, lease)
	if err != c.ErrExecutionAuthority || authority != (d.Authority{}) || calls != 1 || strings.Contains(output.String(), secret) || !strings.Contains(output.String(), "stage=description-authority-current-locator class=authority_or_record sql_number=3572 sql_state=HY000") {
		t.Fatal("single original lookup rejection lost its driver code or changed authority", err, calls, output.String())
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
