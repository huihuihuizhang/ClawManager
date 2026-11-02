package systembackupexecution

import (
	"context"
	"database/sql"
	"reflect"
	"regexp"
	"sort"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
)

// This is exclusively the fresh random database created in the independent
// fixture on its task-owned localhost TLS MySQL server. No production path,
// shared fixture, supplied schema or already-declared source is accepted.
func prepareSourceProtocolOriginalCollections(ctx context.Context, t *testing.T, f *dOriginalSixPartTask) {
	t.Helper()
	if f == nil || f.db == nil || f.server == "" || !regexp.MustCompile(`^ad_d_src_[a-f0-9]{16}$`).MatchString(f.database) {
		t.Fatal("independent fresh source schema required")
	}
	tx, err := f.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var server, database string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != f.server || database != f.database {
		t.Fatal("refusing collection setup on changed fixture SQL identity")
	}
	// Unknown source rows must fail construction instead of being deleted to
	// manufacture a successful empty observation. These sets have no seed DML.
	for table := range sourceProtocolCollectionDeclaration(true) {
		if table == "users" || table == "skill_hub_tags" {
			continue
		}
		var count int
		if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&count) != nil || count != 0 {
			t.Fatal("unexpected pre-declaration source rows", table)
		}
	}
	var userCount, userID int
	var username, email, role, provider string
	var active bool
	if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&userCount) != nil || userCount != 1 || tx.QueryRowContext(ctx, "SELECT id,username,email,role,is_active,auth_provider FROM users").Scan(&userID, &username, &email, &role, &active, &provider) != nil || userID != 1 || username != "admin" || email != "admin@clawreef.local" || role != "admin" || !active || provider != "local" {
		t.Fatal("fresh migration user seed differs from original migration contract")
	}
	var quotas, ownQuota int
	if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM user_quotas").Scan(&quotas) != nil || quotas != 1 || tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM user_quotas WHERE user_id=1").Scan(&ownQuota) != nil || ownQuota != 1 {
		t.Fatal("unexpected fresh migration quota seed")
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,tag_key FROM skill_hub_tags ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	expectedTags := []string{"productivity", "coding", "browser", "data", "communication", "automation", "research", "community", "admin-curated", "featured"}
	index := 0
	for rows.Next() {
		var id int
		var key string
		if rows.Scan(&id, &key) != nil || index >= len(expectedTags) || id != index+1 || key != expectedTags[index] {
			rows.Close()
			t.Fatal("unknown Skill tag rows in fresh fixture schema")
		}
		index++
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil || index != len(expectedTags) {
		t.Fatal("incomplete fresh migration Skill tag seed EOF")
	}
	// Only exact, independently checked migration seeds in this new database
	// are removed. This runs before scenario.seedSource/config/core/signatures.
	result, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id=1 AND username='admin' AND email='admin@clawreef.local' AND role='admin' AND is_active=TRUE AND auth_provider='local'")
	if err != nil {
		t.Fatal(err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		t.Fatal("exact fresh migration login seed was not removed")
	}
	for index, key := range expectedTags {
		result, err := tx.ExecContext(ctx, "DELETE FROM skill_hub_tags WHERE id=? AND tag_key=?", index+1, key)
		if err != nil {
			t.Fatal(err)
		}
		if count, err := result.RowsAffected(); err != nil || count != 1 {
			t.Fatal("exact fresh migration tag seed was not removed")
		}
	}
	for _, table := range []string{"users", "user_quotas", "skill_hub_tags"} {
		var count int
		if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&count) != nil || count != 0 {
			t.Fatal("fresh fixture seed or dependent quota remains", table)
		}
	}
	if tx.Commit() != nil {
		t.Fatal("fresh independent collection construction did not commit")
	}
}

// This fixed source declaration is not computed from observer output. Schema
// migration defaults must not silently add an extra declared login or keyset.
func sourceProtocolCollectionDeclaration(empty bool) map[string][]int {
	sets := map[string][]int{
		"users": {}, "instances": {}, "teams": {}, "team_members": {},
		"skills": {}, "skill_blobs": {}, "skill_versions": {}, "instance_skills": {},
		"skill_package_materialize_jobs": {}, "skill_scan_results": {}, "skill_hub_tags": {}, "skill_hub_tag_assignments": {},
	}
	if !empty {
		sets["users"], sets["instances"] = []int{42}, []int{107, 109}
		sets["teams"], sets["team_members"] = []int{120}, []int{121}
		sets["skills"], sets["skill_blobs"], sets["skill_versions"] = []int{111}, []int{112}, []int{113}
	}
	return sets
}

func verifySourceProtocolOriginalCollections(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, empty bool) map[string][]int {
	t.Helper()
	expected := sourceProtocolCollectionDeclaration(empty)
	names := make([]string, 0, len(expected))
	for name := range expected {
		names = append(names, name)
	}
	sort.Strings(names)
	// Independent control/test setup connection, not the observer's source
	// readers or returned DTO. Every SELECT consumes actual rows through EOF.
	for _, table := range names {
		rows, err := f.db.QueryContext(ctx, "SELECT id FROM `"+table+"` ORDER BY id")
		if err != nil {
			t.Fatal("independent original collection read", table, err)
		}
		actual := []int{}
		for rows.Next() {
			var id int
			if rows.Scan(&id) != nil || id <= 0 || len(actual) >= 100000 {
				rows.Close()
				t.Fatal("independent original collection shape", table)
			}
			actual = append(actual, id)
		}
		readErr, closeErr := rows.Err(), rows.Close()
		if readErr != nil || closeErr != nil || !reflect.DeepEqual(actual, expected[table]) {
			t.Fatal("actual original SQL collection differs from predeclared fixture", table, actual, expected[table])
		}
	}
	return expected
}

func assertSourceProtocolObservedCollections(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, empty bool, source b.SourceInventory) {
	t.Helper()
	expected := verifySourceProtocolOriginalCollections(ctx, t, f, empty)
	actual := sourceProtocolCollectionDeclaration(true)
	actual["users"] = append([]int{}, source.Users...)
	for _, value := range source.Instances {
		actual["instances"] = append(actual["instances"], value.ID)
	}
	if source.TeamFacts == nil || source.Skills == nil {
		t.Fatal("actual source omitted Teams/Skills original collections")
	}
	for _, value := range source.TeamFacts.Teams {
		actual["teams"] = append(actual["teams"], value.ID)
	}
	for _, value := range source.TeamFacts.Members {
		actual["team_members"] = append(actual["team_members"], value.ID)
	}
	seen := map[string]bool{}
	for _, table := range source.Skills.Tables {
		if _, exists := expected[table.Name]; !exists || table.Name == "users" || table.Name == "instances" || table.Name == "teams" || table.Name == "team_members" || seen[table.Name] {
			t.Fatal("unexpected/duplicate observed Skill collection", table.Name)
		}
		seen[table.Name] = true
		actual[table.Name] = append([]int{}, table.IDs...)
	}
	if len(seen) != 8 || !reflect.DeepEqual(actual, expected) {
		t.Fatal("observer SQL keysets differ from independent original SQL EOF", actual, expected)
	}
}
