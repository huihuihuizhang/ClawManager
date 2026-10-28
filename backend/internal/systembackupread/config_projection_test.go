package systembackupread

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func configResourceFixture(t *testing.T) ConfigSnapshot {
	t.Helper()
	data, err := os.ReadFile("../../../contracts/system-backup/v12/admin-control-redacted-examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ConfigUpdateRequest struct {
			Config json.RawMessage `json:"config"`
		} `json:"config_update_request"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, fixture.ConfigUpdateRequest.Config); err != nil {
		t.Fatal(err)
	}
	raw := compact.Bytes()
	digest := sha256.Sum256(raw)
	return ConfigSnapshot{installationID: "installation_test", version: 1, rowVersion: 1, active: true,
		configSHA256: hex.EncodeToString(digest[:]), canonical: raw, createdBy: "42",
		createdAt: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)}
}

func TestConfigProjectionRulesMatchContract(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/admin-control-resources.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != configProjectionSchemaSHA256 {
		t.Fatal("ConfigValues contract changed; regenerate and review read projection rules")
	}
}

func TestProjectConfigResourceClosedShapeAndAuthorizedService(t *testing.T) {
	row := configResourceFixture(t)
	dto, err := ProjectConfigResource(row)
	if err != nil || dto.Version != 1 || dto.Active != true || dto.OriginInstallationID != "installation_test" {
		t.Fatal("valid config was not projected", err)
	}
	encoded, err := json.Marshal(dto)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil || len(body) != 10 || body["change_reason"] != nil {
		t.Fatal("invalid ConfigResource envelope", string(encoded), err)
	}
	for _, forbidden := range []string{"config_sha256", "canonical_config_json", "provider_uri", "credential", "secret"} {
		if strings.Contains(string(encoded), `"`+forbidden+`"`) {
			t.Fatal("raw or secret column escaped", forbidden)
		}
	}
	f := configTestFixture(t)
	f.row[4], f.row[5], f.row[6] = row.configSHA256, int64(len(row.canonical)), row.canonical
	db := sql.OpenDB(configConnector{f})
	defer db.Close()
	service, err := NewService(db, f, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReadActiveConfigDTO(context.Background()); err != nil || f.rechecks != 1 {
		t.Fatal("service skipped read authority or projection", err, f.rechecks)
	}
	f.revoke = true
	if _, err := service.ReadActiveConfigDTO(context.Background()); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked config projected", err)
	}
}

func TestHistoricalConfigResourceIsInactiveAndNeverEffective(t *testing.T) {
	f := configTestFixture(t)
	f.row[2] = int64(2)
	f.row[10] = int64(1)
	f.row[11] = true
	db := sql.OpenDB(configConnector{f})
	defer db.Close()
	service, err := NewService(db, f, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	dto, err := service.ReadConfigVersionDTO(context.Background(), 2)
	if err != nil || dto.Version != 2 || dto.Active || dto.EffectiveEnabled || f.rechecks != 1 {
		t.Fatal("historical resource reported active or effective", dto.Version, dto.Active, dto.EffectiveEnabled, err)
	}
	forged := configResourceFixture(t)
	forged.active = false
	forged.effective = true
	if _, err := ProjectConfigResource(forged); !errors.Is(err, ErrUnavailable) {
		t.Fatal("inactive resource projected as effective", err)
	}
}

func TestProjectConfigResourceRejectsMalformedValues(t *testing.T) {
	base := configResourceFixture(t)
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"unknown root", func(doc map[string]any) { doc["credential"] = "secret" }},
		{"unknown ref field", func(doc map[string]any) { doc["references"].([]any)[0].(map[string]any)["uri"] = "secret" }},
		{"out of range", func(doc map[string]any) { doc["capacity"].(map[string]any)["source_size_safety_factor"] = 3.0 }},
		{"bad heartbeat", func(doc map[string]any) {
			doc["durations"].(map[string]any)["controller_claim_heartbeat_seconds"] = 100.0
		}},
		{"missing ref", func(doc map[string]any) { doc["references"] = doc["references"].([]any)[1:] }},
		{"duplicate ref purpose", func(doc map[string]any) {
			refs := doc["references"].([]any)
			refs[1].(map[string]any)["purpose"] = refs[0].(map[string]any)["purpose"]
		}},
		{"shared signing identity", func(doc map[string]any) {
			refs := doc["references"].([]any)
			var signing map[string]any
			for _, value := range refs {
				item := value.(map[string]any)
				if item["purpose"] == "capture_signing" {
					signing = item
				}
			}
			signing["identity_hash"] = refs[0].(map[string]any)["identity_hash"]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(base.canonical, &doc); err != nil {
				t.Fatal(err)
			}
			tc.edit(doc)
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			row := base
			row.canonical = raw
			digest := sha256.Sum256(raw)
			row.configSHA256 = hex.EncodeToString(digest[:])
			if _, err := ProjectConfigResource(row); !errors.Is(err, ErrUnavailable) {
				t.Fatal("malformed config was projected", err)
			}
		})
	}
	decoder := json.NewDecoder(strings.NewReader(`{"enabled":false,"enabled":false}`))
	decoder.UseNumber()
	if _, err := configParseJSON(decoder, 0); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate JSON key accepted", err)
	}
}
