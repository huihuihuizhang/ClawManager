package systembackupbusinessa

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func challengeRestoreFixture() (NorthboundChallengeRestoreSource, NorthboundChallengeRestoreMapping, time.Time) {
	created := time.Date(2026, 9, 20, 1, 0, 0, 0, time.UTC)
	return NorthboundChallengeRestoreSource{
			ID: 17, ChallengeID: "source-challenge", NonceHash: strings.Repeat("a", 64),
			KeyID: "northbound-login-v1", Status: "issued", ExpiresAt: created.Add(time.Hour),
			CreatedAt: created, UpdatedAt: created.Add(time.Minute),
		}, NorthboundChallengeRestoreMapping{
			SourceID: 17, TargetID: 117, TargetChallengeID: "target-challenge",
		}, time.Date(2026, 10, 13, 4, 5, 6, 123456000, time.UTC)
}

func TestNormalizeNorthboundChallengeForRestoreCannotResumeAuthentication(t *testing.T) {
	source, mapping, targetNow := challengeRestoreFixture()
	row, err := NormalizeNorthboundChallengeForRestore(source, mapping, targetNow)
	if err != nil {
		t.Fatal(err)
	}
	if row.ID != mapping.TargetID || row.ChallengeID != mapping.TargetChallengeID ||
		row.NonceHash != source.NonceHash || row.KeyID != source.KeyID || row.Status != "expired" ||
		row.SourceIP != nil || row.UsedAt == nil || !row.UsedAt.Equal(row.ExpiresAt) ||
		!row.ExpiresAt.Before(targetNow) || !row.UpdatedAt.Equal(row.ExpiresAt) ||
		!row.CreatedAt.Equal(source.CreatedAt) || source.Status != "issued" {
		t.Fatalf("challenge could resume or lost required SQL fields: %+v", row)
	}
	// The running service accepts only issued, unexpired challenges. A
	// historical nonce hash must not make the restored row usable again.
	if row.Status == "issued" && row.ExpiresAt.After(targetNow) {
		t.Fatal("restored challenge can be consumed")
	}
	source.Status = "processing" // This intermediate status occurs in production.
	if _, err := NormalizeNorthboundChallengeForRestore(source, mapping, targetNow); err != nil {
		t.Fatalf("existing processing row could not be made inert: %v", err)
	}
}

func TestNormalizeNorthboundChallengeForRestoreRejectsUnboundAndInvalidRows(t *testing.T) {
	source, mapping, targetNow := challengeRestoreFixture()
	for name, mutate := range map[string]func(*NorthboundChallengeRestoreSource, *NorthboundChallengeRestoreMapping, *time.Time){
		"missing source ID": func(s *NorthboundChallengeRestoreSource, _ *NorthboundChallengeRestoreMapping, _ *time.Time) {
			s.ID = 0
		},
		"wrong mapping": func(_ *NorthboundChallengeRestoreSource, m *NorthboundChallengeRestoreMapping, _ *time.Time) {
			m.SourceID = 18
		},
		"missing target ID": func(_ *NorthboundChallengeRestoreSource, m *NorthboundChallengeRestoreMapping, _ *time.Time) {
			m.TargetID = 0
		},
		"empty challenge ID": func(s *NorthboundChallengeRestoreSource, _ *NorthboundChallengeRestoreMapping, _ *time.Time) {
			s.ChallengeID = ""
		},
		"oversized target ID": func(_ *NorthboundChallengeRestoreSource, m *NorthboundChallengeRestoreMapping, _ *time.Time) {
			m.TargetChallengeID = strings.Repeat("x", 65)
		},
		"invalid target UTF-8": func(_ *NorthboundChallengeRestoreSource, m *NorthboundChallengeRestoreMapping, _ *time.Time) {
			m.TargetChallengeID = string([]byte{0xff})
		},
		"missing key": func(s *NorthboundChallengeRestoreSource, _ *NorthboundChallengeRestoreMapping, _ *time.Time) {
			s.KeyID = ""
		},
		"uppercase nonce hash": func(s *NorthboundChallengeRestoreSource, _ *NorthboundChallengeRestoreMapping, _ *time.Time) {
			s.NonceHash = strings.Repeat("A", 64)
		},
		"invalid nonce hash": func(s *NorthboundChallengeRestoreSource, _ *NorthboundChallengeRestoreMapping, _ *time.Time) {
			s.NonceHash = strings.Repeat("g", 64)
		},
		"unknown status": func(s *NorthboundChallengeRestoreSource, _ *NorthboundChallengeRestoreMapping, _ *time.Time) {
			s.Status = "active"
		},
		"missing source time": func(s *NorthboundChallengeRestoreSource, _ *NorthboundChallengeRestoreMapping, _ *time.Time) {
			s.CreatedAt = time.Time{}
		},
		"backward update": func(s *NorthboundChallengeRestoreSource, _ *NorthboundChallengeRestoreMapping, _ *time.Time) {
			s.UpdatedAt = s.CreatedAt.Add(-time.Minute)
		},
		"target clock before source": func(_ *NorthboundChallengeRestoreSource, _ *NorthboundChallengeRestoreMapping, now *time.Time) {
			*now = source.UpdatedAt
		},
		"target SQL time out of range": func(_ *NorthboundChallengeRestoreSource, _ *NorthboundChallengeRestoreMapping, now *time.Time) {
			*now = time.Date(999, 1, 1, 0, 0, 0, 0, time.UTC)
		},
	} {
		t.Run(name, func(t *testing.T) {
			gotSource, gotMapping, gotNow := source, mapping, targetNow
			mutate(&gotSource, &gotMapping, &gotNow)
			row, err := NormalizeNorthboundChallengeForRestore(gotSource, gotMapping, gotNow)
			if !errors.Is(err, ErrNorthboundChallengeRestore) || row.ID != 0 || row.NonceHash != "" {
				t.Fatalf("invalid challenge returned a writable row: %+v, %v", row, err)
			}
		})
	}
}

func TestNormalizeNorthboundChallengesForRestoreRequiresClosedMapping(t *testing.T) {
	source, mapping, targetNow := challengeRestoreFixture()
	second, secondMapping := source, mapping
	second.ID, second.ChallengeID = 18, "source-second"
	secondMapping.SourceID, secondMapping.TargetID, secondMapping.TargetChallengeID = 18, 118, "target-second"
	sources := []NorthboundChallengeRestoreSource{second, source}
	mappings := []NorthboundChallengeRestoreMapping{mapping, secondMapping}
	rows, err := NormalizeNorthboundChallengesForRestore(sources, mappings, targetNow)
	if err != nil || len(rows) != 2 || rows[0].ID != 117 || rows[1].ID != 118 || rows[1].Status != "expired" {
		t.Fatalf("closed challenge batch failed: %+v, %v", rows, err)
	}
	if empty, err := NormalizeNorthboundChallengesForRestore(nil, nil, targetNow); err != nil || len(empty) != 0 {
		t.Fatalf("empty but authenticated challenge set failed: %+v, %v", empty, err)
	}
	if empty, err := NormalizeNorthboundChallengesForRestore(nil, nil, time.Time{}); !errors.Is(err, ErrNorthboundChallengeRestore) || empty != nil {
		t.Fatalf("missing target clock admitted an empty set: %+v, %v", empty, err)
	}
	for name, mutate := range map[string]func(*[]NorthboundChallengeRestoreSource, *[]NorthboundChallengeRestoreMapping){
		"missing mapping": func(_ *[]NorthboundChallengeRestoreSource, m *[]NorthboundChallengeRestoreMapping) { *m = (*m)[:1] },
		"extra mapping": func(_ *[]NorthboundChallengeRestoreSource, m *[]NorthboundChallengeRestoreMapping) {
			*m = append(*m, NorthboundChallengeRestoreMapping{SourceID: 19, TargetID: 119, TargetChallengeID: "extra"})
		},
		"duplicate source ID": func(s *[]NorthboundChallengeRestoreSource, _ *[]NorthboundChallengeRestoreMapping) { (*s)[0].ID = 17 },
		"duplicate source challenge ID": func(s *[]NorthboundChallengeRestoreSource, _ *[]NorthboundChallengeRestoreMapping) {
			(*s)[0].ChallengeID = "SOURCE-CHALLENGE"
		},
		"duplicate mapping": func(_ *[]NorthboundChallengeRestoreSource, m *[]NorthboundChallengeRestoreMapping) {
			(*m)[1].SourceID = 17
		},
		"duplicate target ID": func(_ *[]NorthboundChallengeRestoreSource, m *[]NorthboundChallengeRestoreMapping) {
			(*m)[1].TargetID = 117
		},
		"duplicate target challenge ID": func(_ *[]NorthboundChallengeRestoreSource, m *[]NorthboundChallengeRestoreMapping) {
			(*m)[1].TargetChallengeID = "TARGET-CHALLENGE"
		},
		"invalid later source": func(s *[]NorthboundChallengeRestoreSource, _ *[]NorthboundChallengeRestoreMapping) {
			(*s)[1].Status = "active"
		},
	} {
		t.Run(name, func(t *testing.T) {
			gotSources := append([]NorthboundChallengeRestoreSource(nil), sources...)
			gotMappings := append([]NorthboundChallengeRestoreMapping(nil), mappings...)
			mutate(&gotSources, &gotMappings)
			got, err := NormalizeNorthboundChallengesForRestore(gotSources, gotMappings, targetNow)
			if !errors.Is(err, ErrNorthboundChallengeRestore) || got != nil {
				t.Fatalf("invalid challenge batch returned partial rows: %+v, %v", got, err)
			}
		})
	}
}
