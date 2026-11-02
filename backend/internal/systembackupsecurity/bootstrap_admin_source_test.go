package systembackupsecurity

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

func TestBootstrapCurrentAdminUsesSameReadOnlyLockForLegacyAndCandidate(t *testing.T) {
	svc, grant, _, state := bootstrapServiceFixture(t)
	ctx := context.Background()
	tx, e := svc.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e := lockBootstrapCurrentAdmin(ctx, tx, grant); e != nil {
		t.Fatal("legacy current admin", e)
	}
	candidate := &configBootstrapCandidateSession{plan: &ConfigBootstrapCandidates{grant: grant}}
	if e := candidate.checkAdmin(ctx, tx); e != nil {
		t.Fatal("candidate current admin", e)
	}
	if len(state.queries) != 2 {
		t.Fatal("extra source query or omitted current source")
	}
	for _, q := range state.queries {
		if q != `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE` || strings.Contains(q, "password") {
			t.Fatal("administrator write privilege/credential read introduced")
		}
	}
	state.inactive = true
	if lockBootstrapCurrentAdmin(ctx, tx, grant) == nil || candidate.checkAdmin(ctx, tx) == nil {
		t.Fatal("revoked current admin reused either branch")
	}
	state.inactive = false
	state.grant.Username = "foreign"
	if lockBootstrapCurrentAdmin(ctx, tx, grant) == nil {
		t.Fatal("current actor username was not compared")
	}
}
