package systembackupbootstrapsecurity

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

func captureCandidateData(t *testing.T) CaptureCandidateRelationData {
	t.Helper()
	f := newFixture(t, nil, nil)
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "producer-authority-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Synthetic bool `json:"synthetic"`
		Positive  []struct {
			ID    string          `json:"id"`
			Value json.RawMessage `json:"value"`
		} `json:"positive"`
	}
	if json.Unmarshal(raw, &vectors) != nil || !vectors.Synthetic {
		t.Fatal("synthetic C1 fixtures unavailable")
	}
	var request pd.ResultRequest
	for _, v := range vectors.Positive {
		if v.ID == "unconfigured_signing" {
			request, err = pd.DecodeResult(v.Value)
		}
	}
	if err != nil || request.Admission.Unconfigured == nil {
		t.Fatal("original C1 signing vector unavailable", err)
	}
	hashes, err := ConfigCandidateHashes(f.config)
	if err != nil {
		t.Fatal(err)
	}
	request.Scope = pd.Scope{ServerUUID: pd.ServerUUID(f.grant.ServerUUID), Database: pd.Database(f.grant.Database), Installation: pd.Installation(f.grant.InstallationID)}
	request.Evidence.OwnerID = request.Scope.Installation
	request.Admission.Unconfigured.CandidateHash = pd.Hash(hashes.CandidateHash)
	request.Admission.Unconfigured.RegistrySetHash = pd.Hash(hashes.RegistrySetHash)
	request.Admission.Unconfigured.RefSetHash = pd.Hash(hashes.RefSetHash)
	digests, err := pd.ResultHashes(request)
	if err != nil {
		t.Fatal(err)
	}
	var pin sec.BootstrapSecretRef
	for _, p := range f.config.References() {
		if p.Purpose == "capture_signing" {
			pin = p
		}
	}
	descriptor, err := json.Marshal(map[string]string{
		"ref_kind": "signing_key", "purpose": "capture_certificate", "identity_hash": pin.IdentityHash,
		"identity_version": pin.Version, "provider_identity_hash": strings.Repeat("e", 64), "scope_hash": strings.Repeat("f", 64),
		"description_redacted": "SYNTHETIC_CAPTURE_DESCRIPTION", "algorithm": "EdDSA", "domain_separator": "clawmanager.system-backup.capture_certificate.v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt := pd.ReceiptRecord{Scope: request.Scope, ReceiptKeyHash: digests.Key, RequestHash: digests.Request, Request: request,
		ResultVersion: "1", CommittedAt: "2026-09-30T01:01:00.000001Z", RetentionExpiresAt: "2026-10-30T01:05:00.000001Z", ChargedBytes: "4096"}
	return CaptureCandidateRelationData{Grant: f.grant, Config: f.config, Admission: *request.Admission.Unconfigured, Target: request.Target,
		Descriptor: descriptor, DescriptorSHA256: sha(descriptor), MappingSHA256: strings.Repeat("9", 64),
		ExpectedDigests: digests, ResultVersion: "1", Receipt: receipt}
}

func captureCandidateReseal(t *testing.T, d *CaptureCandidateRelationData, replaceExpected bool) {
	t.Helper()
	h, err := pd.ResultHashes(d.Receipt.Request)
	if err != nil {
		t.Fatal("mutation must remain a structurally valid C1 result", err)
	}
	d.Receipt.Scope = d.Receipt.Request.Scope
	d.Receipt.ReceiptKeyHash, d.Receipt.RequestHash = h.Key, h.Request
	if replaceExpected {
		d.ExpectedDigests = h
	}
	if _, err = copyCandidateReceipt(d.Receipt); err != nil {
		t.Fatal("resealed mutation must remain a valid C1 receipt", err)
	}
}

func TestCandidateConfigHashesUseOriginalCanonicalArrayBytes(t *testing.T) {
	f := newFixture(t, nil, nil)
	h, err := ConfigCandidateHashes(f.config)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(f.config.CanonicalJSON(), &root) != nil {
		t.Fatal("canonical config unavailable")
	}
	if h.CandidateHash != f.config.SHA256() || h.RegistrySetHash != sha(root["registries"]) || h.RefSetHash != sha(root["references"]) {
		t.Fatal("canonical byte spans changed")
	}
	if h.RegistrySetHash == sha(append(append([]byte(nil), root["registries"]...), '\n')) || h.RefSetHash == sha(append(append([]byte(nil), root["references"]...), '\n')) {
		t.Fatal("newline was included in an array digest")
	}
	for _, field := range []string{"registries", "references"} {
		t.Run(field+"_original_order", func(t *testing.T) {
			var changed map[string]json.RawMessage
			_ = json.Unmarshal(f.config.CanonicalJSON(), &changed)
			var entries []json.RawMessage
			if json.Unmarshal(changed[field], &entries) != nil || len(entries) < 2 {
				t.Fatal("complete canonical array unavailable")
			}
			entries[0], entries[1] = entries[1], entries[0]
			changed[field], _ = json.Marshal(entries)
			raw, _ := json.Marshal(changed)
			config, err := sec.DecodeBootstrapConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			next, err := ConfigCandidateHashes(config)
			if err != nil || next.CandidateHash == h.CandidateHash {
				t.Fatal("original config order was silently normalized", err)
			}
			if field == "registries" && (next.RegistrySetHash == h.RegistrySetHash || next.RefSetHash != h.RefSetHash) || field == "references" && (next.RefSetHash == h.RefSetHash || next.RegistrySetHash != h.RegistrySetHash) {
				t.Fatal("changed array digest or unchanged other array digest lost")
			}
		})
	}
	if h, err := ConfigCandidateHashes(sec.BootstrapConfig{}); err == nil || h != (CandidateConfigDigests{}) {
		t.Fatal("zero config produced candidate digests")
	}
}

func TestCaptureCandidateRelationExactOriginalDataAndOwnedCopies(t *testing.T) {
	d := captureCandidateData(t)
	relation, err := NewCaptureCandidateRelation(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, authority := any(relation).(sec.BootstrapResourceValidator); authority {
		t.Fatal("relation matcher became bootstrap resource authority")
	}
	original, err := relation.Receipt()
	if err != nil || relation.CheckReceipt(d.Grant, d.Config, original) != nil {
		t.Fatal("exact original receipt mismatch", err)
	}
	if relation.Reference().Purpose != "capture_signing" || relation.MappingSHA256() != d.MappingSHA256 || relation.DescriptorSHA256() != d.DescriptorSHA256 {
		t.Fatal("complete original association lost")
	}
	// The reference is a distinct logical key from the producer target. The
	// original trusted mapping, not guessed equal hashes, associates them.
	if relation.Reference().IdentityHash == string(original.Request.Target.IdentityHash) {
		t.Fatal("fixture must distinguish reference and producer target identity")
	}
	selection, err := relation.Selection()
	if err != nil || selection.Purpose != "capture_signing" || selection.MappingHash != pd.Hash(d.MappingSHA256) || selection.ReferenceIdentityHash != pd.Hash(relation.Reference().IdentityHash) || selection.ReferenceVersion != pd.RefVersion(relation.Reference().Version) || selection.ResultVersion != original.ResultVersion || !reflect.DeepEqual(selection.Request, original.Request) {
		t.Fatal("D selection lost complete purpose/ref/mapping/result association", err)
	}
	selection.Request.Target.ResultSlots[0] = "kek"
	*selection.Request.Evidence.ImmutableVersion = "mutated-selection-copy"
	d.Target.ResultSlots[0] = "kek"
	d.Receipt.Request.Target.ResultSlots[0] = "kek"
	d.Receipt.Request.Admission.Unconfigured.PolicyHash = pd.Hash(strings.Repeat("a", 64))
	*d.Receipt.Request.Evidence.ImmutableVersion = "caller-mutated-object"
	for i := range d.Descriptor {
		d.Descriptor[i] = 'x'
	}
	returned, err := relation.Receipt()
	if err != nil || !reflect.DeepEqual(returned, original) {
		t.Fatal("caller aliases changed frozen original data", err)
	}
	returned.Request.Target.ResultSlots[0] = "kek"
	*returned.Request.Evidence.ImmutableVersion = "changed-owned-copy"
	next, err := relation.Receipt()
	if err != nil || !reflect.DeepEqual(next, original) {
		t.Fatal("getter returned borrowed nested state", err)
	}
}

func TestCaptureCandidateRelationRejectsResealedReplacement(t *testing.T) {
	mutations := map[string]func(*pd.ResultRequest){
		"database": func(r *pd.ResultRequest) { r.Scope.Database = "different_db" },
		"server":   func(r *pd.ResultRequest) { r.Scope.ServerUUID = "22222222-2222-4333-8444-555555555555" },
		"installation": func(r *pd.ResultRequest) {
			r.Scope.Installation = "installation_other"
			r.Evidence.OwnerID = r.Scope.Installation
		},
		"deployment": func(r *pd.ResultRequest) { r.Admission.Unconfigured.DeploymentAdmissionID = "another_deployment" },
		"config":     func(r *pd.ResultRequest) { r.Admission.Unconfigured.CandidateHash = pd.Hash(strings.Repeat("a", 64)) },
		"registries": func(r *pd.ResultRequest) { r.Admission.Unconfigured.RegistrySetHash = pd.Hash(strings.Repeat("a", 64)) },
		"references": func(r *pd.ResultRequest) { r.Admission.Unconfigured.RefSetHash = pd.Hash(strings.Repeat("a", 64)) },
		"policy":     func(r *pd.ResultRequest) { r.Admission.Unconfigured.PolicyHash = pd.Hash(strings.Repeat("a", 64)) },
		"channel": func(r *pd.ResultRequest) {
			r.Admission.Unconfigured.ChannelProfileHash = pd.Hash(strings.Repeat("a", 64))
		},
		"target":              func(r *pd.ResultRequest) { r.Target.IdentityHash = pd.Hash(strings.Repeat("b", 64)) },
		"profile":             func(r *pd.ResultRequest) { r.Target.EvaluatorProfileHash = pd.Hash(strings.Repeat("b", 64)) },
		"scope":               func(r *pd.ResultRequest) { r.Target.ProbeScopeHash = pd.Hash(strings.Repeat("b", 64)) },
		"target_version":      func(r *pd.ResultRequest) { r.Target.RefVersion = "new-provider-v2" },
		"grant":               func(r *pd.ResultRequest) { r.GrantID = "other_grant" },
		"generation":          func(r *pd.ResultRequest) { r.GrantGeneration = "2" },
		"epoch":               func(r *pd.ResultRequest) { r.DomainEpoch = "2" },
		"run":                 func(r *pd.ResultRequest) { r.RunID = "other_run" },
		"target_generation":   func(r *pd.ResultRequest) { r.TargetGeneration = "2" },
		"request_key":         func(r *pd.ResultRequest) { r.RequestKey = "another-request-key" },
		"input":               func(r *pd.ResultRequest) { r.InputHash = pd.Hash(strings.Repeat("a", 64)) },
		"manifest":            func(r *pd.ResultRequest) { r.Evidence.ManifestHash = pd.Hash(strings.Repeat("d", 64)) },
		"content":             func(r *pd.ResultRequest) { r.Evidence.ContentHash = pd.Hash(strings.Repeat("d", 64)) },
		"object":              func(r *pd.ResultRequest) { r.Evidence.ObjectHash = pd.Hash(strings.Repeat("d", 64)) },
		"object_version":      func(r *pd.ResultRequest) { *r.Evidence.ImmutableVersion = "other-object-v2" },
		"evidence_version":    func(r *pd.ResultRequest) { r.ExpectedEvidenceVersion = "4" },
		"observation_renewal": func(r *pd.ResultRequest) { r.ObservationExpiresAt = "2026-09-30T01:06:00.000001Z" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			d := captureCandidateData(t)
			relation, err := NewCaptureCandidateRelation(d)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&d.Receipt.Request)
			captureCandidateReseal(t, &d, false)
			if _, err = NewCaptureCandidateRelation(d); !errors.Is(err, sec.ErrRegistrationUnavailable) {
				t.Fatal("recomputed digest replaced original mapped candidate", err)
			}
			if err = relation.CheckReceipt(d.Grant, d.Config, d.Receipt); !errors.Is(err, sec.ErrRegistrationUnavailable) {
				t.Fatal("resealed replacement changed immutable relation", err)
			}
		})
	}
}

func TestCaptureCandidateRelationRejectsSelfConsistentWrongPurposeAndBindings(t *testing.T) {
	for name, mutate := range map[string]func(*CaptureCandidateRelationData){
		"config_even_when_expected_resealed": func(d *CaptureCandidateRelationData) {
			d.Receipt.Request.Admission.Unconfigured.CandidateHash = pd.Hash(strings.Repeat("a", 64))
			d.Admission = *d.Receipt.Request.Admission.Unconfigured
		},
		"scope_even_when_expected_resealed": func(d *CaptureCandidateRelationData) { d.Receipt.Request.Scope.Database = "other_database" },
		"target_not_original_profile": func(d *CaptureCandidateRelationData) {
			d.Receipt.Request.Target.EvaluatorProfileHash = pd.Hash(strings.Repeat("a", 64))
		},
		"degraded_signing": func(d *CaptureCandidateRelationData) {
			d.Receipt.Request.Results.Dependency.Observations[0].Status = "degraded"
			d.Receipt.Request.Results.Dependency.Observations[0].Reason = "signing_key_unavailable"
		},
		"committed_at_observation_expiry": func(d *CaptureCandidateRelationData) { d.Receipt.CommittedAt = d.Receipt.Request.ObservationExpiresAt },
		"committed_before_observation":    func(d *CaptureCandidateRelationData) { d.Receipt.CommittedAt = "2026-09-30T00:59:59.000001Z" },
		"mapped_result_version": func(d *CaptureCandidateRelationData) {
			d.Receipt.Request.ExpectedResultVersion = "1"
			d.Receipt.ResultVersion = "2"
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := captureCandidateData(t)
			mutate(&d)
			captureCandidateReseal(t, &d, true)
			if _, err := NewCaptureCandidateRelation(d); !errors.Is(err, sec.ErrRegistrationUnavailable) {
				t.Fatal("self-consistent hash bypassed purpose/config/original relation", err)
			}
		})
	}
	for _, purpose := range []string{"acceptance_record", "catalog_record", "strong_auth_issuer"} {
		t.Run(purpose+"_not_capture", func(t *testing.T) {
			d := captureCandidateData(t)
			var fields map[string]string
			_ = json.Unmarshal(d.Descriptor, &fields)
			fields["purpose"] = purpose
			d.Descriptor, _ = json.Marshal(fields)
			d.DescriptorSHA256 = sha(d.Descriptor)
			if _, err := NewCaptureCandidateRelation(d); !errors.Is(err, sec.ErrRegistrationUnavailable) {
				t.Fatal("another signing purpose became capture", err)
			}
		})
	}
}

func TestCaptureCandidateRelationOriginalGrantAndOutputBoundary(t *testing.T) {
	d := captureCandidateData(t)
	r, err := NewCaptureCandidateRelation(d)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*sec.OfflineBootstrapGrant){
		"actor":    func(g *sec.OfflineBootstrapGrant) { g.UserID++ },
		"username": func(g *sec.OfflineBootstrapGrant) { g.Username = "other-admin" },
		"key":      func(g *sec.OfflineBootstrapGrant) { g.IdempotencyKey = "another-bootstrap-key" },
		"reason":   func(g *sec.OfflineBootstrapGrant) { g.ChangeReason = "different reason" },
		"matrix":   func(g *sec.OfflineBootstrapGrant) { g.MatrixKey = "k3s-cluster" },
	} {
		t.Run(name, func(t *testing.T) {
			g := d.Grant
			change(&g)
			if r.CheckReceipt(g, d.Config, d.Receipt) == nil {
				t.Fatal("changed original full grant semantics accepted")
			}
		})
	}
	for name, change := range map[string]func(*pd.ReceiptRecord){
		"committed_at": func(v *pd.ReceiptRecord) { v.CommittedAt = "2026-09-30T01:02:00.000001Z" },
		"retention":    func(v *pd.ReceiptRecord) { v.RetentionExpiresAt = "2026-10-29T01:05:00.000001Z" },
		"charged":      func(v *pd.ReceiptRecord) { v.ChargedBytes = "8192" },
	} {
		t.Run("complete_receipt_"+name, func(t *testing.T) {
			v, err := r.Receipt()
			if err != nil {
				t.Fatal(err)
			}
			change(&v)
			if _, err := copyCandidateReceipt(v); err != nil {
				t.Fatal("receipt metadata mutation must remain structurally valid", err)
			}
			if r.CheckReceipt(d.Grant, d.Config, v) == nil {
				t.Fatal("unchanged request digest hid a changed complete receipt")
			}
		})
	}
	for _, v := range []any{d, &d, *r, r} {
		printed := fmt.Sprintf("%v %#v %+v", v, v, v)
		for _, secret := range []string{d.Grant.Username, d.Grant.IdempotencyKey, d.Grant.ConfigSHA256, "SYNTHETIC_CAPTURE_DESCRIPTION"} {
			if strings.Contains(printed, secret) {
				t.Fatal("relation formatting exposed original mapping data")
			}
		}
		if out, err := json.Marshal(v); err == nil || bytes.Contains(out, []byte(d.Grant.Username)) {
			t.Fatal("relation JSON exposed original mapping data")
		}
	}
	for _, empty := range []*CaptureCandidateRelation{nil, {}} {
		if empty.CheckReceipt(d.Grant, d.Config, d.Receipt) == nil {
			t.Fatal("zero relation accepted")
		}
		if _, err := empty.Receipt(); err == nil {
			t.Fatal("zero relation issued data")
		}
		if _, err := empty.Selection(); err == nil {
			t.Fatal("zero relation issued D selection")
		}
	}
}
