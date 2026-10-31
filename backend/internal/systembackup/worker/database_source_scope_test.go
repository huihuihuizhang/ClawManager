package worker

import (
	"testing"

	"clawreef/internal/systembackup/domain"
)

func TestFormalBusinessSourceScopeBindsOriginalSourceGrant(t *testing.T) {
	i := databaseRequestFixture(t)
	legacy, err := FormalSourceScopeSHA256(i, FormalSourceMount{})
	if err != nil || !validDatabaseRequest(i.Request) {
		t.Fatal("original database source shape", err)
	}
	i.Request.Database.SourceScope = domain.BusinessTableSourceScope
	finite, err := FormalSourceScopeSHA256(i, FormalSourceMount{})
	if err != nil || finite == legacy || !validDatabaseRequest(i.Request) {
		t.Fatal("finite scope not bound to independent source grant", err)
	}
	i.Request.Database.SourceScope = "unknown"
	if _, err := FormalSourceScopeSHA256(i, FormalSourceMount{}); err == nil || validDatabaseRequest(i.Request) {
		t.Fatal("unknown source role scope accepted")
	}
	i.Request.Database.SourceScope = domain.BusinessTableSourceScope
	i.Request.Operation = "restore-database"
	if validDatabaseRequest(i.Request) {
		t.Fatal("source capability leaked into restore")
	}
}
