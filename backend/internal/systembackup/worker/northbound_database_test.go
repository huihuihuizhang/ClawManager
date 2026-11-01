package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"clawreef/internal/systembackup/domain"
	resources "clawreef/internal/systembackupresources"
)

func TestNorthboundObservationCannotEnterCaptureVerifyOrPolicyJSON(t *testing.T) {
	ctx := context.Background()
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	observation := &resources.NorthboundTargetObservation{} // inert zero value, never a real observation
	for _, operation := range []string{"capture-database", "verify-database"} {
		r := databaseRequestFixture(t).Request
		r.Operation = operation
		if operation == "verify-database" {
			r.Database.Name = "cm_drill_northbound_test"
			r.ArtifactName = ""
			r.PolicyVersion = "owner-fixture"
		}
		if !validDatabaseRequest(r) {
			t.Fatal("negative case failed an unrelated request boundary")
		}
		db, e := OpenDatabase(r.Database, &DatabaseCredential{Username: "lazy_fixture", Password: []byte("owned-fixture")})
		if e != nil {
			t.Fatal(e)
		}
		checks := 0
		_, e = RunDatabase(ctx, r, DatabaseEnvironment{Database: db, Staging: root, Key: bytes.Repeat([]byte{95}, 32), NorthboundTarget: observation, Check: func(context.Context, string, Request) error { checks++; return nil }})
		db.Close()
		if !errors.Is(e, ErrRequest) || checks != 0 {
			t.Fatal("restore-only observation reached authority/SQL in wrong operation")
		}
	}
	raw, e := json.Marshal(domain.Policy{NorthboundTarget: observation})
	if e != nil || strings.Contains(string(raw), "Northbound") {
		t.Fatal("opaque observation entered serialized policy")
	}
	var decoded domain.Policy
	if json.Unmarshal([]byte(`{"NorthboundTarget":{},"northboundCandidate":{},"northboundScope":{"Database":"cm_drill_fake","ServerUUID":"fake"}}`), &decoded) != nil || decoded.NorthboundTarget != nil {
		t.Fatal("request JSON constructed an observation")
	}
}
