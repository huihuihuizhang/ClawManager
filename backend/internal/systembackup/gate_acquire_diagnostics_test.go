package systembackup

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func TestGateAcquisitionBusyDiagnosticOmitsPrivateDriverMessage(t *testing.T) {
	var output bytes.Buffer
	previous, flags := log.Writer(), log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	defer log.SetOutput(previous)
	defer log.SetFlags(flags)
	secret := "PRIVATE_SQL_ARGS_OWNER_SCOPE_BODY_GRANT_TOKEN_MUST_NOT_APPEAR"
	for _, err := range []error{nil, errors.New(secret), fmt.Errorf("%s: %w", secret, &mysql.MySQLError{Number: 3572, SQLState: [5]byte{'H', 'Y', '0', '0', '0'}, Message: secret}), &mysql.MySQLError{Number: 3572, SQLState: [5]byte{'\n', '?', 'x', 0, '\r'}, Message: secret}} {
		logGateAcquisitionBusy("gate-row-nowait", err)
	}
	if strings.Contains(output.String(), secret) || !strings.Contains(output.String(), "reason=gate-row-nowait sql_number=3572 sql_state=HY000") {
		t.Fatal("gate acquisition diagnostic leaked private fields or lost fixed classification")
	}
	shape := regexp.MustCompile(`^\[system-backup-gate\] stage=begin-acquire-rejected reason=gate-row-nowait sql_number=(0|3572) sql_state=([A-Z0-9]{5})?$`)
	for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
		if !shape.MatchString(line) {
			t.Fatal("diagnostic formatter emitted non-fixed or unsafe fields")
		}
	}
}
