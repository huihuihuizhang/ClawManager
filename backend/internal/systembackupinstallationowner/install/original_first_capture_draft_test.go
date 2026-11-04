package install

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	pd "clawreef/internal/systembackupproducer"
)

// Protocol comparison fixtures only: these tests create no installation,
// candidate approval, native provider observation or adoption result.
func firstCaptureSelectionFixture(t *testing.T) (*originalRequest, pd.BootstrapConsumptionRequest) {
	t.Helper()
	f := newAuthorityFixture(t)
	return firstCaptureSelectionFor(t, f)
}

func firstCaptureSelectionFor(t *testing.T, f *authorityFixture) (*originalRequest, pd.BootstrapConsumptionRequest) {
	t.Helper()
	r := &originalRequest{grant: f.grant, config: f.config}
	raw, e := os.ReadFile("../../../../contracts/system-backup/v12/producer-authority-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors struct {
		Positive []struct {
			ID    string
			Value json.RawMessage
		}
	}
	if json.Unmarshal(raw, &vectors) != nil {
		t.Fatal("original producer vectors")
	}
	var result pd.ResultRequest
	for _, vector := range vectors.Positive {
		if vector.ID == "unconfigured_artifact" && pd.DecodeRecord(vector.Value, &result) != nil {
			t.Fatal("original unconfigured result")
		}
	}
	if result.Admission.Unconfigured == nil {
		t.Fatal("missing original vector")
	}
	selected := pd.BootstrapConsumptionRequest{Scope: pd.Scope{ServerUUID: pd.ServerUUID(f.grant.ServerUUID), Database: pd.Database(f.grant.Database), Installation: pd.Installation(f.grant.InstallationID)}, OfflineGrantHash: pd.Hash(f.record.GrantSHA256), ConfigHash: pd.Hash(f.record.ConfigSHA256), RegistrySetHash: pd.Hash(f.record.RegistrySetSHA256), RefSetHash: pd.Hash(f.record.ReferenceSetSHA256), ActorID: pd.Counter(strconv.FormatInt(f.grant.UserID, 10)), Username: f.grant.Username, MatrixKey: f.grant.MatrixKey, Endpoint: f.record.Endpoint, IdempotencyKey: f.grant.IdempotencyKey}
	result.Scope = selected.Scope
	result.Evidence.OwnerID = selected.Scope.Installation
	result.Admission.Unconfigured.CandidateHash = selected.ConfigHash
	result.Admission.Unconfigured.RegistrySetHash = selected.RegistrySetHash
	result.Admission.Unconfigured.RefSetHash = selected.RefSetHash
	for _, ref := range f.config.References() {
		selected.Candidates = append(selected.Candidates, pd.BootstrapCandidateSelection{Purpose: ref.Purpose, ReferenceIdentityHash: pd.Hash(ref.IdentityHash), ReferenceVersion: pd.RefVersion(ref.Version), MappingHash: pd.Hash(strings.Repeat("c", 64)), Request: result, ResultVersion: "1"})
	}
	return r, selected
}

func TestOriginalFirstCaptureSelectionRequiresCompleteOriginalRequest(t *testing.T) {
	r, source := firstCaptureSelectionFixture(t)
	expected, e := pd.BootstrapConsumptionHash(source)
	if e != nil {
		t.Fatal(e)
	}
	got, e := originalFirstCaptureSelection(r, source)
	if e != nil || got.selection != string(expected) || got.grant != string(source.OfflineGrantHash) || got.registries != string(source.RegistrySetHash) || got.references != string(source.RefSetHash) {
		t.Fatal("original full selection rejected", e)
	}
	for _, tc := range []struct {
		name   string
		change func(*pd.BootstrapConsumptionRequest)
	}{
		{"missing_candidate", func(s *pd.BootstrapConsumptionRequest) { s.Candidates = s.Candidates[:len(s.Candidates)-1] }},
		{"duplicate_purpose", func(s *pd.BootstrapConsumptionRequest) { s.Candidates[1].Purpose = s.Candidates[0].Purpose }},
		{"wrong_installation", func(s *pd.BootstrapConsumptionRequest) { s.Scope.Installation = "installation_other" }},
		{"wrong_actor", func(s *pd.BootstrapConsumptionRequest) { s.ActorID = "8" }},
		{"wrong_username", func(s *pd.BootstrapConsumptionRequest) { s.Username += "-other" }},
		{"wrong_endpoint", func(s *pd.BootstrapConsumptionRequest) { s.Endpoint += "-other" }},
		{"wrong_matrix", func(s *pd.BootstrapConsumptionRequest) { s.MatrixKey = "k3s-cluster" }},
		{"wrong_idempotency", func(s *pd.BootstrapConsumptionRequest) { s.IdempotencyKey += "-other" }},
		{"wrong_offline_grant", func(s *pd.BootstrapConsumptionRequest) { s.OfflineGrantHash = pd.Hash(strings.Repeat("f", 64)) }},
		{"wrong_registry_set", func(s *pd.BootstrapConsumptionRequest) { s.RegistrySetHash = pd.Hash(strings.Repeat("f", 64)) }},
		{"wrong_reference_set", func(s *pd.BootstrapConsumptionRequest) { s.RefSetHash = pd.Hash(strings.Repeat("f", 64)) }},
		{"wrong_reference_identity", func(s *pd.BootstrapConsumptionRequest) {
			s.Candidates[0].ReferenceIdentityHash = pd.Hash(strings.Repeat("f", 64))
		}},
		{"wrong_reference_version", func(s *pd.BootstrapConsumptionRequest) { s.Candidates[0].ReferenceVersion = "other-version" }},
		{"missing_mapping", func(s *pd.BootstrapConsumptionRequest) { s.Candidates[0].MappingHash = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(source)
			var s pd.BootstrapConsumptionRequest
			if json.Unmarshal(raw, &s) != nil {
				t.Fatal("detached fixture")
			}
			tc.change(&s)
			if _, e := originalFirstCaptureSelection(r, s); e == nil {
				t.Fatal("changed source accepted")
			}
		})
	}
	t.Run("mapping_changes_selection_without_establishing_authority", func(t *testing.T) {
		raw, _ := json.Marshal(source)
		var s pd.BootstrapConsumptionRequest
		_ = json.Unmarshal(raw, &s)
		s.Candidates[0].MappingHash = pd.Hash(strings.Repeat("e", 64))
		changed, e := originalFirstCaptureSelection(r, s)
		if e != nil || changed.selection == got.selection {
			t.Fatal("full mapping association omitted")
		}
	})
	t.Run("candidate_order_uses_original_normalization", func(t *testing.T) {
		raw, _ := json.Marshal(source)
		var s pd.BootstrapConsumptionRequest
		_ = json.Unmarshal(raw, &s)
		for a, b := 0, len(s.Candidates)-1; a < b; a, b = a+1, b-1 {
			s.Candidates[a], s.Candidates[b] = s.Candidates[b], s.Candidates[a]
		}
		reordered, e := originalFirstCaptureSelection(r, s)
		if e != nil || reordered != got {
			t.Fatal("normalization changed")
		}
	})
}
