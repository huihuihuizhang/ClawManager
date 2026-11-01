package systembackupexecution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	ce "clawreef/internal/systembackupcontrolevidence"
	security "clawreef/internal/systembackupsecurity"
)

// Construct the FULL original ConfigValues before capture/authority creation.
// No admitted JSON/hash, old nonce or sealed record is rewritten afterwards.
func publicationOriginalFixtureConfig(t *testing.T, target PublicationTargetMaterials, catalog *PublicationCatalogMaterials) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "admin-control-redacted-examples.json"))
	if err != nil {
		t.Fatal(err)
	}
	var example struct {
		Request struct {
			Config map[string]json.RawMessage `json:"config"`
		} `json:"config_update_request"`
	}
	if json.Unmarshal(raw, &example) != nil || len(example.Request.Config) == 0 {
		t.Fatal("full original config fixture unavailable")
	}
	var capacity map[string]json.RawMessage
	if json.Unmarshal(example.Request.Config["capacity"], &capacity) != nil {
		t.Fatal("full original capacity fixture unavailable")
	}
	capacity["control_metadata_capacity_bytes"] = json.RawMessage(strconv.FormatInt(1<<30, 10))
	capacityRaw, err := ce.Canonical(capacity)
	if err != nil {
		t.Fatal(err)
	}
	example.Request.Config["capacity"] = capacityRaw
	example.Request.Config["enabled"] = json.RawMessage("true")
	refs := []security.BootstrapSecretRef{}
	if json.Unmarshal(example.Request.Config["references"], &refs) != nil {
		t.Fatal("full original purpose references unavailable")
	}
	for i, ref := range refs {
		switch ref.Purpose {
		case "artifact_write":
			refs[i].IdentityHash, refs[i].Version = target.WriteIdentityHash, target.WriteRefVersion
		case "artifact_read":
			refs[i].IdentityHash, refs[i].Version = target.ReadIdentityHash, target.ReadRefVersion
		case "artifact_ca":
			refs[i].IdentityHash, refs[i].Version = target.CAIdentityHash, target.CARefVersion
		case "catalog_read":
			if catalog != nil {
				refs[i].IdentityHash, refs[i].Version = catalog.ReadIdentityHash, catalog.ReadRefVersion
			}
		case "catalog_append":
			if catalog != nil {
				refs[i].IdentityHash, refs[i].Version = catalog.AppendIdentityHash, catalog.AppendRefVersion
			}
		}
	}
	refRaw, err := ce.Canonical(refs)
	if err != nil {
		t.Fatal(err)
	}
	example.Request.Config["references"] = refRaw
	snapshot, err := ce.Canonical(example.Request.Config)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
