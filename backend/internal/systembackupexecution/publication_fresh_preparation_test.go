package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func TestPublicationPreparationAbsenceNeverAcceptsDriverFailure(t *testing.T) {
	cause := &mysql.MySQLError{Number: 3572, SQLState: [5]byte{'H', 'Y', '0', '0', '0'}}
	for _, failure := range []error{cause, errors.Join(sql.ErrNoRows, cause)} {
		queries := 0
		db := sql.OpenDB(descriptionErrorConnector{queries: &queries, cause: failure})
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		err = originalPublicationPreparationAbsentTx(context.Background(), tx, "installation_test", "sbk_11111111-2222-4333-8444-555555555555")
		tx.Rollback()
		db.Close()
		if !errors.Is(err, cause) || queries != 1 {
			t.Fatal("driver failure became proof of absent delegation", err, queries)
		}
	}
}

func TestPublicationConcurrentSQLTraceDistinguishesCallingExecution(t *testing.T) {
	trace := &aPublisherConcurrentSQLTrace{}
	end := trace.begin()
	if !trace.active() {
		t.Fatal("own live transaction not tracked")
	}
	other := make(chan bool, 1)
	go func() { other <- trace.active() }()
	if <-other || !trace.active() {
		t.Fatal("other execution was mistaken for own SQL transaction")
	}
	end()
	end()
	if trace.active() {
		t.Fatal("closed transaction remains active")
	}
}
