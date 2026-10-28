//go:build systembackup_mysql

package systembackupsecurity

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"

	"clawreef/internal/systembackupcontroller"
)

// Embed the exact LF-normalized candidate solely for detached seed tests.
// Both this copy and the actual runner proposal must match the compiled SHA.
//
//go:embed testdata/config_writer_candidate_081.sql
var configWriterCandidateFixture string

func TestDConfigWriterMySQLSeed(t *testing.T) {
	assertConfigProofInstallationStateSeed(t, configProofInstallationSchema)
	base := configProofProbeInputs{Kind: "a_config_proof_probe_inputs.v1", Catalog: systembackupcontroller.ContractMigrationCatalogHash}
	for n := 1; n <= systembackupcontroller.ContractMigrationCatalogFileCount; n++ {
		base.Filenames = append(base.Filenames, fmt.Sprintf("%03d_synthetic.sql", n))
	}
	baseRaw, err := json.Marshal(base)
	mysqlMust(t, err)
	input := configWriterProbeInputs{Kind: "d_config_writer_probe_inputs.v1", MigrationInputs: baseRaw, CandidateDDL: configWriterCandidateFixture, CandidateSHA256: configWriterCandidateSHA256}
	raw, err := json.Marshal(input)
	mysqlMust(t, err)
	if _, _, err := decodeConfigWriterProbeInputs(raw, registrationHash(string(raw))); err != nil {
		t.Fatal("valid detached writer capsule rejected", err)
	}
	for _, name := range []string{"kind", "ddl-bytes", "ddl-pin", "catalog", "unknown", "digest", "duplicate-field"} {
		t.Run(name, func(t *testing.T) {
			var fields map[string]any
			mysqlMust(t, json.Unmarshal(raw, &fields))
			switch name {
			case "kind":
				fields["kind"] = "production"
			case "ddl-bytes":
				fields["candidate_ddl"] = configWriterCandidateFixture + "\n"
			case "ddl-pin":
				fields["candidate_sha256"] = registrationHash("other")
			case "catalog":
				fields["migration_inputs"].(map[string]any)["catalog_sha256"] = registrationHash("other")
			case "unknown":
				fields["target"] = "production"
			}
			bad, err := json.Marshal(fields)
			mysqlMust(t, err)
			if name == "duplicate-field" {
				bad = append(append([]byte(`{"kind":"d_config_writer_probe_inputs.v1",`), bad[1:]...))
			}
			digest := registrationHash(string(bad))
			if name == "digest" {
				digest = registrationHash("other")
			}
			if _, _, err := decodeConfigWriterProbeInputs(bad, digest); err == nil {
				t.Fatal("unsafe capsule accepted")
			}
		})
	}
	// All live requests use generated fixtures, not files relative to a checkout.
	fixture := bootstrapFixture(t)
	current, err := DecodeConfigValues(fixture)
	mysqlMust(t, err)
	for _, endpoint := range []string{ConfigUpdateEndpoint, ConfigRollbackEndpoint} {
		f := configWriterMySQLFixture{current: current, proposed: configWriterProposed(t, current)}
		raw := f.request(t, endpoint, 1)
		request, err := DecodeConfigMutationRequest(endpoint, raw)
		mysqlMust(t, err)
		_, err = request.RequestHash("installation_writer_seed", "admin", "42")
		mysqlMust(t, err)
	}
}
