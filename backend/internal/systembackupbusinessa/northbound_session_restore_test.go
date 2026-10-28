package systembackupbusinessa

import (
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func sessionString(value string) *string     { return &value }
func sessionTime(value time.Time) *time.Time { return &value }

func sessionRestoreFixture(t *testing.T) (*UserRestoreBatch, NorthboundSessionRestoreSource, NorthboundSessionRestoreMapping, time.Time) {
	t.Helper()
	created := time.Date(2026, 9, 20, 1, 0, 0, 0, time.UTC)
	users, err := NormalizeUsersForRestore([]UserRestoreSource{{
		ID: 7, Username: "source", Email: "source@example.invalid", Role: "user", CreatedAt: created, UpdatedAt: created,
	}}, []UserRestoreMapping{{
		SourceID: 7, TargetID: 107, TargetUsername: "target", TargetEmail: "target@example.invalid",
	}})
	if err != nil {
		t.Fatal(err)
	}
	oldHash := strings.Repeat("a", 64)
	source := NorthboundSessionRestoreSource{
		ID: 18, SessionID: "nbs_source", UserID: 7,
		RefreshTokenHash: strings.Repeat("b", 64), PreviousRefreshTokenHash: &oldHash,
		RefreshTokenHistory: `["` + oldHash + `"]`,
		ScopesJSON:          `["lite-instances:read","pro-instances:read"]`,
		Status:              "active", AccessExpiresAt: created.Add(30 * time.Minute),
		RefreshExpiresAt: created.Add(time.Hour), LastUsedAt: sessionTime(created.Add(5 * time.Minute)),
		LastIP: sessionString("192.0.2.8"), UserAgent: sessionString("test-client"),
		CreatedAt: created, UpdatedAt: created.Add(5 * time.Minute),
	}
	mapping := NorthboundSessionRestoreMapping{SourceID: 18, TargetID: 118, TargetSessionID: "nbs_target"}
	return users, source, mapping, time.Date(2026, 10, 13, 4, 5, 6, 123456000, time.UTC)
}

func TestNormalizeNorthboundSessionForRestoreRevokesAndRemaps(t *testing.T) {
	users, source, mapping, targetNow := sessionRestoreFixture(t)
	row, err := NormalizeNorthboundSessionForRestore(users, source, mapping, targetNow)
	if err != nil {
		t.Fatal(err)
	}
	if row.ID != 118 || row.SessionID != "nbs_target" || row.UserID != 107 ||
		row.Status != "revoked" || row.RefreshTokenHash != source.RefreshTokenHash ||
		row.PreviousRefreshTokenHash == nil || *row.PreviousRefreshTokenHash != *source.PreviousRefreshTokenHash ||
		row.RefreshTokenHistory != source.RefreshTokenHistory || row.ScopesJSON != source.ScopesJSON ||
		row.RevokedAt == nil || !row.RevokedAt.Equal(row.AccessExpiresAt) ||
		!row.RefreshExpiresAt.Equal(row.AccessExpiresAt) || !row.AccessExpiresAt.Before(targetNow) ||
		!row.UpdatedAt.Equal(row.RevokedAt.UTC()) || row.LastUsedAt == nil || row.LastIP == nil || row.UserAgent == nil {
		t.Fatalf("restored session can resume or lost historical fields: %+v", row)
	}
	*source.PreviousRefreshTokenHash = strings.Repeat("c", 64)
	*source.LastIP = "203.0.113.9"
	*source.UserAgent = "changed-client"
	if *row.PreviousRefreshTokenHash != strings.Repeat("a", 64) || *row.LastIP != "192.0.2.8" || *row.UserAgent != "test-client" {
		t.Fatal("normalized row aliases mutable source pointers")
	}
	if row.Status == "active" && row.RefreshExpiresAt.After(targetNow) {
		t.Fatal("restored historical session can authenticate")
	}
}

func TestNewRuntimeScopesRestoreOnlyAsInactiveHistory(t *testing.T) {
	for _, scope := range []string{"lite-instances:delete", "pro-instances:delete", "owners:usage:read"} {
		t.Run(scope, func(t *testing.T) {
			users, source, mapping, now := sessionRestoreFixture(t)
			source.ScopesJSON = `["` + scope + `"]`
			row, err := NormalizeNorthboundSessionForRestore(users, source, mapping, now)
			if err != nil || row.Status != "revoked" || !row.AccessExpiresAt.Before(now) || !row.RefreshExpiresAt.Before(now) || row.ScopesJSON != source.ScopesJSON {
				t.Fatalf("scope restored as active session: %+v, %v", row, err)
			}
			policyUsers, policySource := callerPolicyRestoreFixture(t)
			policySource.ScopesJSON = source.ScopesJSON
			policy, err := NormalizeNorthboundCallerPolicyForRestore(policyUsers, policySource)
			if err != nil || policy.Enabled || policy.ScopesJSON != policySource.ScopesJSON {
				t.Fatalf("scope restored as active caller policy: %+v, %v", policy, err)
			}
		})
	}
}

func TestNormalizeNorthboundSessionForRestoreRejectsInvalidHistoryAndScope(t *testing.T) {
	users, source, mapping, targetNow := sessionRestoreFixture(t)
	for name, mutate := range map[string]func(*NorthboundSessionRestoreSource, *NorthboundSessionRestoreMapping, *time.Time){
		"wrong source mapping": func(_ *NorthboundSessionRestoreSource, m *NorthboundSessionRestoreMapping, _ *time.Time) {
			m.SourceID = 19
		},
		"missing target session": func(_ *NorthboundSessionRestoreSource, m *NorthboundSessionRestoreMapping, _ *time.Time) {
			m.TargetSessionID = ""
		},
		"missing user mapping": func(s *NorthboundSessionRestoreSource, _ *NorthboundSessionRestoreMapping, _ *time.Time) {
			s.UserID = 8
		},
		"invalid current hash": func(s *NorthboundSessionRestoreSource, _ *NorthboundSessionRestoreMapping, _ *time.Time) {
			s.RefreshTokenHash = "bad"
		},
		"invalid previous hash": func(s *NorthboundSessionRestoreSource, _ *NorthboundSessionRestoreMapping, _ *time.Time) {
			s.PreviousRefreshTokenHash = sessionString("bad")
		},
		"invalid history JSON": func(s *NorthboundSessionRestoreSource, _ *NorthboundSessionRestoreMapping, _ *time.Time) {
			s.RefreshTokenHistory = `{}`
		},
		"current hash in history": func(s *NorthboundSessionRestoreSource, _ *NorthboundSessionRestoreMapping, _ *time.Time) {
			s.RefreshTokenHistory = `["` + s.RefreshTokenHash + `"]`
		},
		"unknown scope": func(s *NorthboundSessionRestoreSource, _ *NorthboundSessionRestoreMapping, _ *time.Time) {
			s.ScopesJSON = `["admin:all"]`
		},
		"duplicate scope": func(s *NorthboundSessionRestoreSource, _ *NorthboundSessionRestoreMapping, _ *time.Time) {
			s.ScopesJSON = `["pro-instances:read","pro-instances:read"]`
		},
		"invalid scope JSON": func(s *NorthboundSessionRestoreSource, _ *NorthboundSessionRestoreMapping, _ *time.Time) {
			s.ScopesJSON = `null`
		},
		"future last use": func(s *NorthboundSessionRestoreSource, _ *NorthboundSessionRestoreMapping, now *time.Time) {
			s.LastUsedAt = sessionTime(now.Add(time.Hour))
		},
		"backward update": func(s *NorthboundSessionRestoreSource, _ *NorthboundSessionRestoreMapping, _ *time.Time) {
			s.UpdatedAt = s.CreatedAt.Add(-time.Second)
		},
		"target before source": func(_ *NorthboundSessionRestoreSource, _ *NorthboundSessionRestoreMapping, now *time.Time) {
			*now = source.UpdatedAt
		},
		"invalid status": func(s *NorthboundSessionRestoreSource, _ *NorthboundSessionRestoreMapping, _ *time.Time) {
			s.Status = "processing"
		},
	} {
		t.Run(name, func(t *testing.T) {
			gotSource, gotMapping, gotNow := source, mapping, targetNow
			mutate(&gotSource, &gotMapping, &gotNow)
			row, err := NormalizeNorthboundSessionForRestore(users, gotSource, gotMapping, gotNow)
			if !errors.Is(err, ErrNorthboundSessionRestore) || row.ID != 0 || row.RefreshTokenHash != "" {
				t.Fatalf("invalid session returned a writable row: %+v, %v", row, err)
			}
		})
	}
}

func TestNormalizeNorthboundSessionsForRestoreClosesBatch(t *testing.T) {
	users, source, mapping, targetNow := sessionRestoreFixture(t)
	otherSource, otherMapping := source, mapping
	otherSource.ID, otherSource.SessionID, otherSource.RefreshTokenHash = 19, "nbs_other", strings.Repeat("c", 64)
	otherSource.PreviousRefreshTokenHash = nil
	otherSource.RefreshTokenHistory = `[]`
	otherMapping.SourceID, otherMapping.TargetID, otherMapping.TargetSessionID = 19, 119, "nbs_other_target"
	sources := []NorthboundSessionRestoreSource{otherSource, source}
	mappings := []NorthboundSessionRestoreMapping{mapping, otherMapping}
	rows, err := NormalizeNorthboundSessionsForRestore(users, sources, mappings, targetNow)
	if err != nil || len(rows) != 2 || rows[0].ID != 118 || rows[1].ID != 119 || rows[1].UserID != 107 {
		t.Fatalf("closed session batch failed: %+v, %v", rows, err)
	}
	if _, err := NormalizeNorthboundSessionsForRestore(users, nil, nil, time.Time{}); !errors.Is(err, ErrNorthboundSessionRestore) {
		t.Fatalf("empty session batch accepted an unauthenticated target clock: %v", err)
	}
	for name, mutate := range map[string]func(*[]NorthboundSessionRestoreSource, *[]NorthboundSessionRestoreMapping){
		"missing mapping":     func(_ *[]NorthboundSessionRestoreSource, m *[]NorthboundSessionRestoreMapping) { *m = (*m)[:1] },
		"duplicate source ID": func(s *[]NorthboundSessionRestoreSource, _ *[]NorthboundSessionRestoreMapping) { (*s)[0].ID = 18 },
		"duplicate source session ID": func(s *[]NorthboundSessionRestoreSource, _ *[]NorthboundSessionRestoreMapping) {
			(*s)[0].SessionID = "NBS_SOURCE"
		},
		"duplicate source hash": func(s *[]NorthboundSessionRestoreSource, _ *[]NorthboundSessionRestoreMapping) {
			(*s)[0].RefreshTokenHash = source.RefreshTokenHash
		},
		"duplicate target ID": func(_ *[]NorthboundSessionRestoreSource, m *[]NorthboundSessionRestoreMapping) {
			(*m)[1].TargetID = 118
		},
		"duplicate target session ID": func(_ *[]NorthboundSessionRestoreSource, m *[]NorthboundSessionRestoreMapping) {
			(*m)[1].TargetSessionID = "NBS_TARGET"
		},
		"invalid later row": func(s *[]NorthboundSessionRestoreSource, _ *[]NorthboundSessionRestoreMapping) {
			(*s)[1].ScopesJSON = `["unknown"]`
		},
	} {
		t.Run(name, func(t *testing.T) {
			gotSources := append([]NorthboundSessionRestoreSource(nil), sources...)
			gotMappings := append([]NorthboundSessionRestoreMapping(nil), mappings...)
			mutate(&gotSources, &gotMappings)
			got, err := NormalizeNorthboundSessionsForRestore(users, gotSources, gotMappings, targetNow)
			if !errors.Is(err, ErrNorthboundSessionRestore) || got != nil {
				t.Fatalf("invalid session batch returned partial rows: %+v, %v", got, err)
			}
		})
	}
}

func TestNorthboundRestoreScopeAllowlistMatchesRuntime(t *testing.T) {
	raw, err := os.ReadFile("../northbound/types.go")
	if err != nil {
		t.Fatal(err)
	}
	ownerRoutes, err := os.ReadFile("../northbound/owner_team_routes.go")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, ownerRoutes...)
	pattern := regexp.MustCompile(`Scope[A-Za-z]+\s*=\s*"([^"]+)"`)
	actual := make(map[string]struct{})
	for _, match := range pattern.FindAllStringSubmatch(string(raw), -1) {
		actual[match[1]] = struct{}{}
	}
	if !reflect.DeepEqual(actual, northboundRestoreScopes) {
		t.Fatalf("runtime northbound scopes drifted from restore allowlist: runtime=%v restore=%v", actual, northboundRestoreScopes)
	}
	adminRaw, err := os.ReadFile("../services/northbound_admin_service.go")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(adminRaw), "var allowedNorthboundScopes = map[string]struct{}{")
	if start < 0 {
		t.Fatal("production caller scope allowlist missing")
	}
	block := string(adminRaw)[start:]
	end := strings.Index(block, "\n}")
	if end < 0 {
		t.Fatal("production caller scope allowlist not closed")
	}
	admin := make(map[string]struct{})
	for _, match := range regexp.MustCompile(`"([^"]+)"\s*:`).FindAllStringSubmatch(block[:end], -1) {
		admin[match[1]] = struct{}{}
	}
	if !reflect.DeepEqual(admin, northboundRestoreScopes) {
		t.Fatalf("production caller scopes drifted from restore allowlist: admin=%v restore=%v", admin, northboundRestoreScopes)
	}
}
