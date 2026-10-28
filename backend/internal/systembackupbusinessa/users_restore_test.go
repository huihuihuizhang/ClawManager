package systembackupbusinessa

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"clawreef/internal/utils"
)

func TestNormalizeUserForRestoreSeversCredentialsAndRemapsIdentity(t *testing.T) {
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := created.Add(time.Hour)
	source := UserRestoreSource{ID: 7, Username: "source-admin", Email: "source@example.invalid", Role: "admin", CreatedAt: created, UpdatedAt: updated}
	mapping := UserRestoreMapping{SourceID: 7, TargetID: 107, TargetUsername: "restored-admin", TargetEmail: "restored@example.invalid"}
	row, err := NormalizeUserForRestore(source, mapping)
	if err != nil {
		t.Fatal(err)
	}
	if row.ID != 107 || row.Username != mapping.TargetUsername || row.Email != mapping.TargetEmail || row.Role != "admin" ||
		row.IsActive || row.AuthProvider != "local" || row.LoginAlias != nil || row.ExternalID != nil || row.LastLogin != nil ||
		row.PasswordHash != DisabledUserPasswordHash || row.CreatedAt != created || row.UpdatedAt != updated {
		t.Fatalf("normalized user violates isolated target rules: %+v", row)
	}
	if utils.VerifyPassword("source-password", row.PasswordHash) || utils.VerifyPassword("anything", row.PasswordHash) {
		t.Fatal("disabled placeholder unexpectedly authenticates")
	}
}

func TestNormalizeUserForRestoreRejectsUnboundOrInvalidIdentity(t *testing.T) {
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	source := UserRestoreSource{ID: 7, Username: "source", Email: "source@example.invalid", Role: "user", CreatedAt: created, UpdatedAt: created}
	mapping := UserRestoreMapping{SourceID: 7, TargetID: 107, TargetUsername: "restored", TargetEmail: "restored@example.invalid"}
	for name, mutate := range map[string]func(*UserRestoreSource, *UserRestoreMapping){
		"missing source ID":     func(s *UserRestoreSource, _ *UserRestoreMapping) { s.ID = 0 },
		"wrong source ID":       func(_ *UserRestoreSource, m *UserRestoreMapping) { m.SourceID = 8 },
		"missing target ID":     func(_ *UserRestoreSource, m *UserRestoreMapping) { m.TargetID = 0 },
		"target ID overflow":    func(_ *UserRestoreSource, m *UserRestoreMapping) { m.TargetID = math.MaxInt32 + 1 },
		"invalid source role":   func(s *UserRestoreSource, _ *UserRestoreMapping) { s.Role = "root" },
		"missing target email":  func(_ *UserRestoreSource, m *UserRestoreMapping) { m.TargetEmail = "" },
		"oversized target name": func(_ *UserRestoreSource, m *UserRestoreMapping) { m.TargetUsername = strings.Repeat("x", 256) },
		"control character":     func(_ *UserRestoreSource, m *UserRestoreMapping) { m.TargetUsername = "bad\nname" },
		"invalid UTF-8":         func(_ *UserRestoreSource, m *UserRestoreMapping) { m.TargetUsername = string([]byte{0xff}) },
		"missing source time":   func(s *UserRestoreSource, _ *UserRestoreMapping) { s.CreatedAt = time.Time{} },
		"backward source time":  func(s *UserRestoreSource, _ *UserRestoreMapping) { s.UpdatedAt = s.CreatedAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			gotSource, gotMapping := source, mapping
			mutate(&gotSource, &gotMapping)
			row, err := NormalizeUserForRestore(gotSource, gotMapping)
			if !errors.Is(err, ErrUserRestoreMapping) || row.ID != 0 || row.PasswordHash != "" {
				t.Fatalf("invalid identity returned a row: %+v, %v", row, err)
			}
		})
	}
}

func TestNormalizeUsersForRestoreRequiresClosedOneToOneMapping(t *testing.T) {
	when := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	sources := []UserRestoreSource{
		{ID: 8, Username: "source-eight", Email: "eight@example.invalid", Role: "user", CreatedAt: when, UpdatedAt: when},
		{ID: 7, Username: "source-seven", Email: "seven@example.invalid", Role: "admin", CreatedAt: when, UpdatedAt: when},
	}
	mappings := []UserRestoreMapping{
		{SourceID: 7, TargetID: 107, TargetUsername: "target-seven", TargetEmail: "target-seven@example.invalid"},
		{SourceID: 8, TargetID: 108, TargetUsername: "target-eight", TargetEmail: "target-eight@example.invalid"},
	}
	batch, err := NormalizeUsersForRestore(sources, mappings)
	if err != nil {
		t.Fatal(err)
	}
	rows := batch.Rows()
	if len(rows) != 2 || rows[0].ID != 107 || rows[1].ID != 108 {
		t.Fatalf("unexpected target ordering: %+v", rows)
	}
	rows[0].ID = 999
	if batch.Rows()[0].ID != 107 {
		t.Fatal("caller changed the normalized batch")
	}
	if id, ok := batch.TargetID(8); !ok || id != 108 {
		t.Fatal("dependent user reference did not resolve")
	}
	for name, modify := range map[string]func(*[]UserRestoreSource, *[]UserRestoreMapping){
		"missing mapping": func(_ *[]UserRestoreSource, m *[]UserRestoreMapping) { *m = (*m)[:1] },
		"extra mapping": func(_ *[]UserRestoreSource, m *[]UserRestoreMapping) {
			*m = append(*m, UserRestoreMapping{SourceID: 9, TargetID: 109})
		},
		"duplicate source row": func(s *[]UserRestoreSource, _ *[]UserRestoreMapping) { (*s)[1].ID = 8 },
		"duplicate mapping":    func(_ *[]UserRestoreSource, m *[]UserRestoreMapping) { (*m)[1].SourceID = 7 },
		"duplicate target ID":  func(_ *[]UserRestoreSource, m *[]UserRestoreMapping) { (*m)[1].TargetID = 107 },
		"invalid later source": func(s *[]UserRestoreSource, _ *[]UserRestoreMapping) { (*s)[1].Role = "root" },
	} {
		t.Run(name, func(t *testing.T) {
			copySources := append([]UserRestoreSource(nil), sources...)
			copyMappings := append([]UserRestoreMapping(nil), mappings...)
			modify(&copySources, &copyMappings)
			got, err := NormalizeUsersForRestore(copySources, copyMappings)
			if !errors.Is(err, ErrUserRestoreMapping) || got != nil {
				t.Fatalf("invalid batch was returned: %+v, %v", got, err)
			}
		})
	}
}
