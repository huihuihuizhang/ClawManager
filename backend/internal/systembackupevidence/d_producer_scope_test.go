package systembackupevidence

import (
	"context"
	"database/sql"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

func TestDIntegrationDatabaseScope(t *testing.T) {
	command, err := pd.DecodeCommand(dIntegrationVector(t, "commands", "acquire"))
	if err != nil {
		t.Fatal(err)
	}
	actual := command.Scope
	actual.ServerUUID = "22222222-2222-4222-8222-222222222222"
	actual.Database = "dprod_0123456789abcdef0123456789abcdef"
	if actual.ServerUUID == command.Scope.ServerUUID || actual.Database == command.Scope.Database {
		t.Fatal("regression requires a database identity different from the vector")
	}
	d := &dIntegrationDB{systemPendingTestDB: &systemPendingTestDB{t: t, scope: actual, now: time.Now().UTC().Truncate(time.Microsecond)}}
	db := sql.OpenDB(d)
	t.Cleanup(func() { db.Close() })
	bound, err := dIntegrationDatabaseScope(context.Background(), db, command.Scope)
	if err != nil || bound != actual {
		t.Fatalf("fixture must bind connected database and retain installation: got %+v, err %v", bound, err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = dIntegrationDatabaseScope(context.Background(), db, command.Scope); err == nil {
		t.Fatal("failed identity lookup must not fall back to vector identity")
	}
}
