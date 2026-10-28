package systembackupbusinessa

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func callerInt(value int) *int { return &value }

func callerPolicyRestoreFixture(t *testing.T) (*UserRestoreBatch, NorthboundCallerPolicyRestoreSource) {
	t.Helper()
	when := time.Date(2026, 9, 20, 1, 0, 0, 0, time.UTC)
	users, err := NormalizeUsersForRestore([]UserRestoreSource{
		{ID: 7, Username: "caller", Email: "caller@example.invalid", Role: "user", CreatedAt: when, UpdatedAt: when},
		{ID: 8, Username: "actor", Email: "actor@example.invalid", Role: "admin", CreatedAt: when, UpdatedAt: when},
	}, []UserRestoreMapping{
		{SourceID: 7, TargetID: 107, TargetUsername: "target-caller", TargetEmail: "target-caller@example.invalid"},
		{SourceID: 8, TargetID: 108, TargetUsername: "target-actor", TargetEmail: "target-actor@example.invalid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return users, NorthboundCallerPolicyRestoreSource{
		UserID: 7, Enabled: true,
		ScopesJSON: `["lite-instances:read","pro-instances:create"]`,
		CreatedAt:  when, UpdatedAt: when.Add(time.Minute), UpdatedBy: callerInt(8),
	}
}

func TestNormalizeNorthboundCallerPolicyForRestoreDisablesAndRemaps(t *testing.T) {
	users, source := callerPolicyRestoreFixture(t)
	row, err := NormalizeNorthboundCallerPolicyForRestore(users, source)
	if err != nil {
		t.Fatal(err)
	}
	if row.UserID != 107 || row.Enabled || row.UpdatedBy == nil || *row.UpdatedBy != 108 ||
		row.ScopesJSON != source.ScopesJSON || len(row.Scopes) != 0 || row.Username != "" || row.Email != "" ||
		!row.CreatedAt.Equal(source.CreatedAt) || !row.UpdatedAt.Equal(source.UpdatedAt) {
		t.Fatalf("caller policy inherited execution or lost FK mapping: %+v", row)
	}
	*source.UpdatedBy = 7
	if *row.UpdatedBy != 108 {
		t.Fatal("target actor pointer aliases source")
	}
	source.Enabled, source.UpdatedBy, source.ScopesJSON = false, nil, `[]`
	row, err = NormalizeNorthboundCallerPolicyForRestore(users, source)
	if err != nil || row.UpdatedBy != nil || row.ScopesJSON != `[]` || row.Enabled {
		t.Fatalf("valid disabled caller policy rejected: %+v, %v", row, err)
	}
}

func TestNormalizeNorthboundCallerPolicyForRestoreRejectsUnsafeScopesAndReferences(t *testing.T) {
	users, source := callerPolicyRestoreFixture(t)
	for name, mutate := range map[string]func(*NorthboundCallerPolicyRestoreSource){
		"unknown caller": func(s *NorthboundCallerPolicyRestoreSource) { s.UserID = 99 },
		"unmapped actor": func(s *NorthboundCallerPolicyRestoreSource) { s.UpdatedBy = callerInt(99) },
		"invalid actor":  func(s *NorthboundCallerPolicyRestoreSource) { s.UpdatedBy = callerInt(0) },
		"unknown scope":  func(s *NorthboundCallerPolicyRestoreSource) { s.ScopesJSON = `["system-backup:admin"]` },
		"duplicate scope": func(s *NorthboundCallerPolicyRestoreSource) {
			s.ScopesJSON = `["lite-instances:read","lite-instances:read"]`
		},
		"malformed JSON":        func(s *NorthboundCallerPolicyRestoreSource) { s.ScopesJSON = `{}` },
		"enabled without scope": func(s *NorthboundCallerPolicyRestoreSource) { s.ScopesJSON = `[]` },
		"oversized JSON":        func(s *NorthboundCallerPolicyRestoreSource) { s.ScopesJSON = strings.Repeat(" ", 1<<16+1) },
		"missing created time":  func(s *NorthboundCallerPolicyRestoreSource) { s.CreatedAt = time.Time{} },
		"backward updated time": func(s *NorthboundCallerPolicyRestoreSource) { s.UpdatedAt = s.CreatedAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			gotSource := source
			mutate(&gotSource)
			row, err := NormalizeNorthboundCallerPolicyForRestore(users, gotSource)
			if !errors.Is(err, ErrNorthboundCallerPolicyRestore) || row.UserID != 0 || row.ScopesJSON != "" {
				t.Fatalf("invalid caller policy returned a writable row: %+v, %v", row, err)
			}
		})
	}
}

func TestNormalizeNorthboundCallerPoliciesForRestoreRejectsPartialBatch(t *testing.T) {
	users, source := callerPolicyRestoreFixture(t)
	second := source
	second.UserID, second.UpdatedBy = 8, nil
	sources := []NorthboundCallerPolicyRestoreSource{second, source}
	rows, err := NormalizeNorthboundCallerPoliciesForRestore(users, sources)
	if err != nil || len(rows) != 2 || rows[0].UserID != 107 || rows[1].UserID != 108 || rows[0].Enabled || rows[1].Enabled {
		t.Fatalf("closed caller-policy batch failed: %+v, %v", rows, err)
	}
	for name, mutate := range map[string]func(*[]NorthboundCallerPolicyRestoreSource){
		"duplicate user":      func(s *[]NorthboundCallerPolicyRestoreSource) { (*s)[1].UserID = 8 },
		"unknown later user":  func(s *[]NorthboundCallerPolicyRestoreSource) { (*s)[1].UserID = 99 },
		"invalid later scope": func(s *[]NorthboundCallerPolicyRestoreSource) { (*s)[1].ScopesJSON = `["unknown"]` },
	} {
		t.Run(name, func(t *testing.T) {
			gotSources := append([]NorthboundCallerPolicyRestoreSource(nil), sources...)
			mutate(&gotSources)
			got, err := NormalizeNorthboundCallerPoliciesForRestore(users, gotSources)
			if !errors.Is(err, ErrNorthboundCallerPolicyRestore) || got != nil {
				t.Fatalf("invalid caller-policy batch returned partial rows: %+v, %v", got, err)
			}
		})
	}
	if got, err := NormalizeNorthboundCallerPoliciesForRestore(nil, nil); !errors.Is(err, ErrNorthboundCallerPolicyRestore) || got != nil {
		t.Fatalf("missing user mapping admitted empty batch: %+v, %v", got, err)
	}
}
