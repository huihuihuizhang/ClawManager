package systembackupread

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestVerifyConfigBackfillSourceMatchesExistingRowWithoutCandidateColumn(t *testing.T) {
	f := configTestFixture(t)
	db := sql.OpenDB(configConnector{f})
	defer db.Close()
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	source := append([]byte(nil), f.row[6].([]byte)...)
	verified, err := r.VerifyConfigBackfillSource(context.Background(), 1, source)
	if err != nil || verified.installationID != "installation_test" || verified.version != 1 ||
		verified.configSHA256 != f.row[4] || f.rechecks != 1 {
		t.Fatal("accurate original source was not verified", err)
	}
	if raw, err := json.Marshal(verified); !errors.Is(err, ErrInvalid) || len(raw) != 0 {
		t.Fatal("backfill source escaped into a wire response", string(raw), err)
	}
	source[0] = 'x'
	if verified.canonical[0] != '{' {
		t.Fatal("verified source aliased the caller's mutable input")
	}
	wrong := strings.Replace(string(f.row[6].([]byte)), `"alert_profile":"production"`, `"alert_profile":"development"`, 1)
	if wrong == string(f.row[6].([]byte)) {
		t.Fatal("source mutation did not occur")
	}
	if _, err := r.VerifyConfigBackfillSource(context.Background(), 1, []byte(wrong)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("different but valid source was accepted for the stored hash", err)
	}
	for i, column := range configMaterializedColumns {
		if column != "parts_registry_sha256" {
			continue
		}
		prior := f.row[12+i]
		f.row[12+i] = strings.Repeat("0", 64)
		if _, err := r.VerifyConfigBackfillSource(context.Background(), 1, f.row[6].([]byte)); !errors.Is(err, ErrUnavailable) {
			t.Fatal("source disagreed with materialized registry", err)
		}
		f.row[12+i] = prior
		break
	}
}

func TestVerifyConfigBackfillSourceDeniesRevocationAndMissingRows(t *testing.T) {
	f := configTestFixture(t)
	db := sql.OpenDB(configConnector{f})
	defer db.Close()
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	source := f.row[6].([]byte)
	if _, err := r.VerifyConfigBackfillSource(context.Background(), 0, source); !errors.Is(err, ErrInvalid) || f.queries != 0 {
		t.Fatal("invalid version queried database", err)
	}
	f.deny = true
	if _, err := r.VerifyConfigBackfillSource(context.Background(), 1, source); !errors.Is(err, ErrDenied) || f.queries != 0 {
		t.Fatal("denied caller queried legacy config", err)
	}
	f.deny = false
	f.revoke = true
	if _, err := r.VerifyConfigBackfillSource(context.Background(), 1, source); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked candidate was verified", err)
	}
	f.revoke = false
	f.row = nil
	f.revoke = true
	if _, err := r.VerifyConfigBackfillSource(context.Background(), 1, source); !errors.Is(err, ErrDenied) {
		t.Fatal("revocation racing missing row became 404", err)
	}
	f.revoke = false
	if _, err := r.VerifyConfigBackfillSource(context.Background(), 1, source); !errors.Is(err, ErrNotFound) {
		t.Fatal("authorized missing config not distinguished", err)
	}
	f.queryError = true
	if _, err := r.VerifyConfigBackfillSource(context.Background(), 1, source); !errors.Is(err, ErrUnavailable) {
		t.Fatal("database failure became a valid backfill source", err)
	}
}
