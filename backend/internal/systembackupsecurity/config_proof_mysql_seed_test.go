//go:build systembackup_mysql

package systembackupsecurity

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"clawreef/internal/systembackupcontroller"
)

// Detached seeds verify the exact formal table's required-column contract.
// The regular schema test compares this copy with published 065 byte-for-byte.
//
//go:embed testdata/config_proof_installation_schema_065.sql
var configProofInstallationSchema string

type configProofProbeInputs struct {
	Kind      string   `json:"kind"`
	Catalog   string   `json:"catalog_sha256"`
	Filenames []string `json:"filenames"`
}

func decodeConfigProofProbeInputs(raw []byte, digest string) (configProofProbeInputs, error) {
	var out configProofProbeInputs
	sum := sha256.Sum256(raw)
	if len(raw) < 100 || len(raw) > 65536 || hex.EncodeToString(sum[:]) != digest || !json.Valid(raw) || !providerJSONUnicode(raw) || !providerUniqueJSON(json.NewDecoder(bytes.NewReader(raw))) {
		return out, ErrConfigMutation
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || !providerFieldSet(fields, "kind", "catalog_sha256", "filenames") || json.Unmarshal(raw, &out) != nil || out.Kind != "a_config_proof_probe_inputs.v1" || out.Catalog != systembackupcontroller.ContractMigrationCatalogHash || len(out.Filenames) != systembackupcontroller.ContractMigrationCatalogFileCount || !sort.StringsAreSorted(out.Filenames) {
		return configProofProbeInputs{}, ErrConfigMutation
	}
	pattern := regexp.MustCompile(`^[0-9]{3}_[a-z0-9_]+\.sql$`)
	for n, name := range out.Filenames {
		if !pattern.MatchString(name) || n > 0 && out.Filenames[n-1] == name {
			return configProofProbeInputs{}, ErrConfigMutation
		}
	}
	return out, nil
}

// Detached Linux probes run this seed without a checkout or a database. It
// exercises capsule parsing and the exact code-generated configuration input.
func TestAConfigProofMySQLSeed(t *testing.T) {
	assertConfigProofInstallationStateSeed(t, configProofInstallationSchema)
	input := configProofProbeInputs{Kind: "a_config_proof_probe_inputs.v1", Catalog: systembackupcontroller.ContractMigrationCatalogHash}
	for n := 1; n <= systembackupcontroller.ContractMigrationCatalogFileCount; n++ {
		input.Filenames = append(input.Filenames, fmt.Sprintf("%03d_synthetic.sql", n))
	}
	encode := func(v any) ([]byte, string) {
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(raw)
		return raw, hex.EncodeToString(sum[:])
	}
	raw, digest := encode(input)
	if _, err := decodeConfigProofProbeInputs(raw, digest); err != nil {
		t.Fatal("valid capsule rejected", err)
	}
	for _, name := range []string{"kind", "catalog", "duplicate-file", "path", "unknown-field", "digest"} {
		t.Run(name, func(t *testing.T) {
			var doc map[string]any
			_ = json.Unmarshal(raw, &doc)
			switch name {
			case "kind":
				doc["kind"] = "arbitrary"
			case "catalog":
				doc["catalog_sha256"] = strings.Repeat("0", 64)
			case "duplicate-file":
				doc["filenames"].([]any)[1] = doc["filenames"].([]any)[0]
			case "path":
				doc["filenames"].([]any)[0] = "../001_secret.sql"
			case "unknown-field":
				doc["target"] = "production"
			}
			bad, hash := encode(doc)
			if name == "digest" {
				hash = strings.Repeat("0", 64)
			}
			if _, err := decodeConfigProofProbeInputs(bad, hash); err == nil {
				t.Fatal("unsafe capsule accepted")
			}
		})
	}
	for _, endpoint := range []string{ConfigUpdateEndpoint, ConfigRollbackEndpoint} {
		body := []byte(`{"expected_version":1,"change_reason":"synthetic rollback","rollback_from_version":1}`)
		if endpoint == ConfigUpdateEndpoint {
			body, _ = json.Marshal(map[string]any{"expected_version": 1, "change_reason": "synthetic update", "config": json.RawMessage(bootstrapFixture(t))})
		}
		request, err := DecodeConfigMutationRequest(endpoint, body)
		if err != nil {
			t.Fatal(err)
		}
		if digest, err := request.RequestHash("installation_config_proof_seed", "admin", "42"); err != nil || len(digest) != 64 {
			t.Fatal("standalone strict request", err)
		}
	}
}
