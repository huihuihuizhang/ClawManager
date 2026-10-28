package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func configHistoryFixture(t *testing.T, count int) *configFixture {
	t.Helper()
	f := configTestFixture(t)
	f.rows = make([][]driver.Value, 0, count)
	for version := count; version >= 1; version-- {
		row := append([]driver.Value(nil), f.row...)
		row[2] = int64(version)
		row[10] = int64(count)
		f.rows = append(f.rows, row)
	}
	return f
}

func TestConfigVersionListPagesUseSignedStableCutoff(t *testing.T) {
	f := configHistoryFixture(t, 3)
	db := sql.OpenDB(configConnector{f})
	defer db.Close()
	service, err := NewService(db, f, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.ListConfigDTO(context.Background(), 2, "")
	if err != nil || len(first.Items) != 2 || first.Items[0].Version != 3 || first.Items[1].Version != 2 ||
		!first.Items[0].Active || first.Items[1].Active || first.NextCursor == nil ||
		first.Consistency != "stable_cutoff" || f.rechecks != 1 {
		t.Fatal("first config page was not stable and redacted", err)
	}
	encoded, err := json.Marshal(first)
	if err != nil || strings.Contains(string(encoded), "canonical_config_json") || strings.Contains(string(encoded), "config_sha256") {
		t.Fatal("internal config fields escaped in list", string(encoded), err)
	}
	newer := append([]driver.Value(nil), f.rows[0]...)
	newer[2] = int64(4)
	f.rows = append([][]driver.Value{newer}, f.rows...)
	second, err := service.ListConfigDTO(context.Background(), 2, *first.NextCursor)
	if err != nil || len(second.Items) != 1 || second.Items[0].Version != 1 || second.NextCursor != nil || f.rechecks != 2 {
		t.Fatal("continuation drifted into newer config", err)
	}
	if _, err := service.ListConfigDTO(context.Background(), 1, *first.NextCursor); !errors.Is(err, ErrInvalid) {
		t.Fatal("cursor accepted changed page limit", err)
	}
	tampered := *first.NextCursor + "x"
	if _, err := service.ListConfigDTO(context.Background(), 2, tampered); !errors.Is(err, ErrInvalid) {
		t.Fatal("tampered config cursor accepted", err)
	}
	foreign := configResourceFixture(t)
	foreign.installationID = "installation_other"
	foreignPage := ConfigPage{Items: []ConfigSnapshot{foreign}, InstallationID: foreign.installationID,
		CutoffVersion: 1, BeforeVersion: 1, HasMore: true}
	foreignToken, err := service.cursor.EncodeConfig(ConfigPageRequest{Limit: 1}, foreignPage)
	if err != nil {
		t.Fatal(err)
	}
	queries := f.queries
	if _, err := service.ListConfigDTO(context.Background(), 1, foreignToken); !errors.Is(err, ErrDenied) || f.queries != queries {
		t.Fatal("valid cursor from another installation queried config", err)
	}
	f.revoke = true
	if _, err := service.ListConfigDTO(context.Background(), 2, *first.NextCursor); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked continuation returned config", err)
	}
}

func TestConfigVersionListFailsClosedOnScopeAndCorruptRows(t *testing.T) {
	f := configHistoryFixture(t, 2)
	db := sql.OpenDB(configConnector{f})
	defer db.Close()
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ListConfigVersions(context.Background(), ConfigPageRequest{InstallationID: "installation_other", Limit: 1, CutoffVersion: 2, BeforeVersion: 2}); !errors.Is(err, ErrDenied) || f.queries != 0 {
		t.Fatal("cross-install config cursor queried rows", err)
	}
	f.rows[1][6] = nil
	if _, err := r.ListConfigVersions(context.Background(), ConfigPageRequest{Limit: 2}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("corrupt second row produced a partial config page", err)
	}
	f.rows = nil
	f.revoke = true
	if _, err := r.ListConfigVersions(context.Background(), ConfigPageRequest{Limit: 2}); !errors.Is(err, ErrDenied) {
		t.Fatal("revocation racing empty page returned success", err)
	}
	f.revoke = false
	page, err := r.ListConfigVersions(context.Background(), ConfigPageRequest{Limit: 2})
	if err != nil || page.Items == nil || len(page.Items) != 0 || page.HasMore {
		t.Fatal("authorized empty config list was malformed", err)
	}
	f.queryError = true
	if _, err := r.ListConfigVersions(context.Background(), ConfigPageRequest{Limit: 2}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("query failure became an empty config list", err)
	}
}

func TestConfigVersionListProjectionRejectsForgedPage(t *testing.T) {
	row := configResourceFixture(t)
	second := row
	second.version = 2
	page := ConfigPage{Items: []ConfigSnapshot{row, second}, InstallationID: row.installationID, CutoffVersion: 2}
	if _, err := ProjectConfigList(page, "", 2); !errors.Is(err, ErrUnavailable) {
		t.Fatal("ascending config versions were projected", err)
	}
}
