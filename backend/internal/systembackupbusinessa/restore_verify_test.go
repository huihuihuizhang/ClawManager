package systembackupbusinessa

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestEnterpriseAuthRestoreSafetyRejectsInheritedEnvironmentPassword(t *testing.T) {
	for _, rule := range restoreSafetyRules {
		if rule.table != "enterprise_auth_settings" {
			continue
		}
		if !strings.Contains(rule.query, "ldap_bind_password_ciphertext IS NULL") ||
			!strings.Contains(rule.query, "BINARY ldap_bind_password_ciphertext<>BINARY ''") {
			t.Fatal("SQL NULL inherits LDAP_BIND_PASSWORD; restore safety must require an explicit empty override")
		}
		return
	}
	t.Fatal("missing enterprise auth restore safety rule")
}

func TestLLMModelRestoreSafetyRejectsBothCredentialSources(t *testing.T) {
	for _, rule := range restoreSafetyRules {
		if rule.table != "llm_models" {
			continue
		}
		if !strings.Contains(rule.query, "api_key IS NOT NULL") ||
			!strings.Contains(rule.query, "api_key_secret_ref IS NOT NULL") {
			t.Fatal("restored model still has a direct API key or resolvable Secret ref")
		}
		return
	}
	t.Fatal("missing llm model restore safety rule")
}

type restoreProofFixture struct {
	starts, rechecks int
	startErr, endErr error
	mutateExpected   bool
}

func (p *restoreProofFixture) VerifyReadOnlyTarget(_ context.Context, tx *sql.Tx, registry, schema string, expected SourceSnapshot, evidence string) error {
	p.starts++
	if tx == nil || !hashPattern.MatchString(registry) || !hashPattern.MatchString(schema) || evidence != "sev_restored" || len(expected.Tables) != 15 {
		return errors.New("unbound target proof")
	}
	if p.mutateExpected {
		expected.Tables[0].Rows = 999
	}
	return p.startErr
}

func (p *restoreProofFixture) RecheckReadOnlyTarget(_ context.Context, tx *sql.Tx, registry, schema, evidence string) error {
	p.rechecks++
	if tx == nil || !hashPattern.MatchString(registry) || !hashPattern.MatchString(schema) || evidence != "sev_restored" {
		return errors.New("unbound final target proof")
	}
	return p.endErr
}

func restoreFixture(t *testing.T) (*CaptureScope, SourceSnapshot) {
	t.Helper()
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := SourceSnapshot{CostAggregateSHA256: fixtureCostAggregateHash(t, 2), Tables: make([]TableCount, 0, 15)}
	for _, table := range scope.Tables() {
		snapshot.Tables = append(snapshot.Tables, TableCount{Table: table, Rows: 2})
	}
	return scope, snapshot
}

func TestSQLRestoreVerifierCountsAndInertStateInOneReadOnlyTransaction(t *testing.T) {
	scope, expected := restoreFixture(t)
	state, proof := &countState{}, &restoreProofFixture{mutateExpected: true}
	checks, err := (SQLRestoreVerifier{DB: countDB(t, state), Proof: proof}).VerifyRestoreTarget(context.Background(), scope, expected, "sev_restored")
	if err != nil || len(checks.Users) != 11 || len(checks.AIGateway) != 14 || proof.starts != 1 || proof.rechecks != 1 ||
		state.commits != 1 || state.rollbacks != 0 || len(state.queries) != 40 ||
		state.begin.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || !state.begin.ReadOnly {
		t.Fatalf("incomplete restore verification: %+v, %+v, %+v, %v", checks, state, proof, err)
	}
	for _, check := range allCategoryChecks(checks) {
		if check.Status != "passed" || check.FailureCategory != "none" || check.EvidenceRef == nil || *check.EvidenceRef != "sev_restored" {
			t.Fatalf("invalid restore check: %+v", check)
		}
	}
	if expected.Tables[0].Rows != 2 || checks.AIGateway[0].Expected["rows"] != int64(2) {
		t.Fatal("proof changed the verifier's authenticated expected count")
	}
	assertRestoreContractCheckIDs(t, checks)
}

func TestSQLRestoreVerifierMismatchAndFailureBoundaries(t *testing.T) {
	scope, expected := restoreFixture(t)
	for _, tc := range []struct {
		name, failure  string
		counts, safety map[string]int64
		wantMismatch   bool
	}{
		{name: "restored row count", counts: map[string]int64{"users": 3}, wantMismatch: true},
		{name: "active credential", safety: map[string]int64{"users": 1}, wantMismatch: true},
		{name: "active gateway model", safety: map[string]int64{"llm_models": 1}, wantMismatch: true},
		{name: "negative safety count", safety: map[string]int64{"users": -1}},
		{name: "engine unavailable", failure: "engine:users"},
		{name: "safety SQL unavailable", failure: "safety:users"},
		{name: "commit failed", failure: "commit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, proof := &countState{failure: tc.failure, counts: tc.counts, safety: tc.safety}, &restoreProofFixture{}
			checks, err := (SQLRestoreVerifier{DB: countDB(t, state), Proof: proof}).VerifyRestoreTarget(context.Background(), scope, expected, "sev_restored")
			if tc.wantMismatch {
				if !errors.Is(err, ErrRestoreNormalizationMismatch) || len(checks.Users) != 11 || len(checks.AIGateway) != 14 || state.commits != 1 {
					t.Fatalf("restore mismatch not reported: %+v, %v", checks, err)
				}
				if category, known := KnownVerificationFailureCategory(err); !known || category != "normalization_failed" {
					t.Fatalf("wrong restore failure category: %s, %v", category, known)
				}
				failed := 0
				for _, check := range allCategoryChecks(checks) {
					if check.Status == "failed" {
						failed++
						if check.FailureCategory != "normalization_failed" || check.CheckClassification == nil || *check.CheckClassification != "integrity" {
							t.Fatalf("wrong failed check: %+v", check)
						}
					}
				}
				if failed != 1 {
					t.Fatalf("expected exactly one failed check, got %d", failed)
				}
			} else if err == nil || !emptyCategoryChecks(checks) {
				t.Fatalf("SQL/commit failure returned partial checks: %+v, %v", checks, err)
			}
		})
	}
}

func TestSQLRestoreVerifierRequiresPinnedScopeAndTargetProof(t *testing.T) {
	scope, expected := restoreFixture(t)
	state := &countState{}
	db := countDB(t, state)
	for _, tc := range []struct {
		name     string
		scope    *CaptureScope
		expected SourceSnapshot
		proof    RestoreTargetReadProofVerifier
		evidence string
	}{
		{name: "missing scope", expected: expected, proof: &restoreProofFixture{}, evidence: "sev_restored"},
		{name: "missing proof", scope: scope, expected: expected, evidence: "sev_restored"},
		{name: "typed nil proof", scope: scope, expected: expected, proof: (*restoreProofFixture)(nil), evidence: "sev_restored"},
		{name: "unregistered evidence", scope: scope, expected: expected, proof: &restoreProofFixture{}, evidence: "bad"},
		{name: "incomplete expected", scope: scope, expected: SourceSnapshot{}, proof: &restoreProofFixture{}, evidence: "sev_restored"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checks, err := (SQLRestoreVerifier{DB: db, Proof: tc.proof}).VerifyRestoreTarget(context.Background(), tc.scope, tc.expected, tc.evidence)
			if err == nil || !emptyCategoryChecks(checks) || len(state.queries) != 0 {
				t.Fatalf("unbound target reached SQL: %+v, %v", checks, err)
			}
		})
	}
	proof := &restoreProofFixture{startErr: errors.New("B target proof rejected")}
	checks, err := (SQLRestoreVerifier{DB: db, Proof: proof}).VerifyRestoreTarget(context.Background(), scope, expected, "sev_restored")
	if err == nil || !emptyCategoryChecks(checks) || len(state.queries) != 0 || proof.rechecks != 0 {
		t.Fatalf("B proof failure reached data queries: %+v, %v", checks, err)
	}
	if category, known := KnownVerificationFailureCategory(err); known || category != "" {
		t.Fatalf("B proof error was reclassified: %s, %v", category, known)
	}
	state = &countState{}
	proof = &restoreProofFixture{endErr: errors.New("B final target proof rejected")}
	checks, err = (SQLRestoreVerifier{DB: countDB(t, state), Proof: proof}).VerifyRestoreTarget(context.Background(), scope, expected, "sev_restored")
	if err == nil || !emptyCategoryChecks(checks) || state.commits != 0 || proof.rechecks != 1 {
		t.Fatalf("final target proof returned checks: %+v, %v", checks, err)
	}
}

func assertRestoreContractCheckIDs(t *testing.T, checks CategoryChecks) {
	t.Helper()
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/verifier-contract.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	defs := document["$defs"].(map[string]any)
	for _, tc := range []struct {
		definition string
		checks     []Check
	}{
		{"AUsersRestoreCheck", checks.Users},
		{"AAIGatewayRestoreCheck", checks.AIGateway},
	} {
		choices := defs[tc.definition].(map[string]any)["allOf"].([]any)[1].(map[string]any)["oneOf"].([]any)
		want := make([]string, 0, len(tc.checks))
		for _, choice := range choices {
			for _, id := range choice.(map[string]any)["properties"].(map[string]any)["id"].(map[string]any)["enum"].([]any) {
				want = append(want, id.(string))
			}
		}
		got := make([]string, 0, len(tc.checks))
		for _, check := range tc.checks {
			got = append(got, check.ID)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s IDs drift from v12 contract: got %v, want %v", tc.definition, got, want)
		}
	}
}
