package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	reg "clawreef/internal/systembackupkekregistry"
	security "clawreef/internal/systembackupsecurity"
	wire "clawreef/internal/systembackupwire"
)

// Exact public payload DATA. It is never a cleanup/eligibility/signing grant.
func acceptancePayloadData(t *testing.T) publicationAcceptancePayload {
	t.Helper()
	reasons, _ := ce.Canonical([]string{"eligible"})
	return publicationAcceptancePayload{Version: "system-backup-acceptance.v1", Backup: "sbk_11111111-1111-4111-8111-111111111111", Attempt: 1, ManifestSHA256: hash([]byte("manifest DATA")), MarkerSHA256: hash([]byte("marker DATA")), CleanupID: "sev_named_cleanup_DATA", CleanupSHA256: hash([]byte("cleanup DATA")), Accepted: true, Reasons: []string{"eligible"}, ReasonsSHA256: hash(reasons), DecisionAt: time.Now().UTC().Format(time.RFC3339Nano), ConfigVersion: 3, Key: security.PublicationSigningKey{Purpose: "acceptance_record", KeyID: "acceptance_record-content-fixture", KeyVersion: "v1"}}
}

func TestPublicationAcceptanceStrictPublicPayload(t *testing.T) {
	p := acceptancePayloadData(t)
	raw, _ := ce.Canonical(p)
	if _, err := decodePublicationAcceptancePayload(raw); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"schema", "backup", "attempt", "unsafe-integer", "cleanup", "purpose", "time", "reason-hash", "reason-order", "true-reasons", "false-eligible", "unknown", "legacy", "duplicate", "alias"} {
		t.Run(mode, func(t *testing.T) {
			q := p
			switch mode {
			case "schema":
				q.Version = "legacy"
			case "backup":
				q.Backup = "sbk_other:task"
			case "attempt":
				q.Attempt = 0
			case "unsafe-integer":
				q.ConfigVersion = 9007199254740992
			case "cleanup":
				q.CleanupSHA256 = ""
			case "purpose":
				q.Key.Purpose = "capture_certificate"
			case "time":
				q.DecisionAt = "not-time"
			case "reason-hash":
				q.ReasonsSHA256 = hash([]byte("wrong reasons DATA"))
			case "reason-order":
				q.Accepted = false
				q.Reasons = []string{"target_risk", "attestation_invalid"}
				r, _ := ce.Canonical(q.Reasons)
				q.ReasonsSHA256 = hash(r)
			case "true-reasons":
				q.Reasons = []string{"target_risk"}
				r, _ := ce.Canonical(q.Reasons)
				q.ReasonsSHA256 = hash(r)
			case "false-eligible":
				q.Accepted = false
			}
			body, _ := ce.Canonical(q)
			if mode == "unknown" || mode == "legacy" || mode == "alias" {
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(body, &fields)
				key := "unexpected"
				if mode == "legacy" {
					key = "identity"
				}
				if mode == "alias" {
					key = "Backup_Public_ID"
				}
				fields[key] = json.RawMessage(`"named DATA"`)
				body, _ = ce.Canonical(fields)
			}
			if mode == "duplicate" {
				body = []byte(strings.TrimSuffix(string(body), "}") + `,"schema_version":"system-backup-acceptance.v1"}`)
			}
			if _, err := decodePublicationAcceptancePayload(body); err == nil {
				t.Fatal("accepted malformed public payload", mode)
			}
		})
	}
	negative := p
	negative.Accepted = false
	negative.Reasons = []string{"target_risk"}
	reasons, _ := ce.Canonical(negative.Reasons)
	negative.ReasonsSHA256 = hash(reasons)
	raw, _ = ce.Canonical(negative)
	if _, err := decodePublicationAcceptancePayload(raw); err != nil {
		t.Fatal("schema-valid negative local decision rejected", err)
	}
}

func TestPublicationAcceptanceSignedBytesBindOriginalPayloadAndPurpose(t *testing.T) {
	p := acceptancePayloadData(t)
	installation := "installation_acceptance_content_DATA"
	keys := []security.ArtifactSigningPublicKey{}
	var signing ed25519.PrivateKey
	for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, security.ArtifactSigningPublicKey{InstallationID: installation, Purpose: purpose, KeyID: purpose + "-content-fixture", KeyVersion: "v1", PublicKey: public, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)})
		if purpose == "acceptance_record" {
			signing = private
		} else {
			clear(private)
		}
	}
	defer clear(signing)
	history, err := security.NewArtifactSigningKeyHistory(installation, keys)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := ce.Canonical(p)
	header, _ := ce.Canonical(map[string]string{"alg": "EdDSA", "key_version": p.Key.KeyVersion, "kid": p.Key.KeyID, "purpose": "acceptance_record", "typ": "clawmanager.system-backup.acceptance.v1"})
	encoded := base64.RawURLEncoding.EncodeToString(header)
	signature := ed25519.Sign(signing, []byte(encoded+"."+base64.RawURLEncoding.EncodeToString(payload)))
	raw, _ := ce.Canonical(map[string]any{"payload": json.RawMessage(payload), "signature": map[string]string{"algorithm": "EdDSA", "domain_separator": "clawmanager.system-backup.acceptance.v1", "key_id": p.Key.KeyID, "key_purpose": "acceptance_record", "key_version": p.Key.KeyVersion, "protected_header": encoded, "value": base64.RawURLEncoding.EncodeToString(signature)}})
	task := security.ArtifactSigningTask{BackupPublicID: p.Backup, AttemptNo: 1}
	if sha, err := verifyPublicationAcceptanceRecord(raw, payload, history, task); err != nil || sha != hash(raw) {
		t.Fatal("valid public content signature", err)
	}
	changed := p
	changed.ManifestSHA256 = hash([]byte("other manifest DATA"))
	other, _ := ce.Canonical(changed)
	if _, err = verifyPublicationAcceptanceRecord(raw, other, history, task); err == nil {
		t.Fatal("signature adopted another prepared payload")
	}
	corrupt := bytes.Replace(raw, []byte(encoded), []byte(encoded+"x"), 1)
	if _, err = verifyPublicationAcceptanceRecord(corrupt, payload, history, task); err == nil {
		t.Fatal("bad protected header accepted")
	}
	task.AttemptNo++
	if _, err = verifyPublicationAcceptanceRecord(raw, payload, history, task); err == nil {
		t.Fatal("cross-attempt signature accepted")
	}
}

func TestPublicationAcceptanceRejectsMissingTypedProof(t *testing.T) {
	ctx := context.Background()
	for _, signed := range []*publicationSignedAcceptance{nil, {}, {prepared: &preparedPublicationAcceptance{}}} {
		if err := signed.recheckTx(ctx, nil, nil, c.ClaimToken{}, 1, PublicationTargetMaterials{}, publicationJSONIntent{}); err == nil {
			t.Fatal("untyped acceptance admitted")
		}
		if err := signed.verifyBytes(ctx); err == nil {
			t.Fatal("missing actual producer admitted")
		}
	}
	for _, accepted := range []*publicationAcceptedObject{nil, {}, {signed: &publicationSignedAcceptance{prepared: &preparedPublicationAcceptance{}}}} {
		if err := accepted.recheckTx(ctx, nil); err == nil {
			t.Fatal("unknown publication manufactured accepted object")
		}
	}
}

func TestPublicationAcceptanceCurrentKEKBindingComparison(t *testing.T) {
	// Typed facts DATA only. This pure comparison never supplies SQL authority
	// or substitutes for the registry's actual core/hash/revocation read.
	raw := []byte(`{"description_redacted":"named provenance","purpose":"unwrap"}`)
	expected := reg.Binding{InstallationID: "installation_comparison_DATA", ConfigRef: reg.ReferencePin{IdentityHash: hash([]byte("KEK identity DATA")), Version: "registry-r1"}, Key: wire.KeyBinding{Provider: "vault-transit", IdentityHash: hash([]byte("KEK identity DATA")), RegistryVersion: "registry-r1", ProviderKeyID: "original-key-DATA", ProviderVersion: "7"}, Provider: reg.ProviderBinding{Endpoint: "https://provider.example.invalid", KeyName: "original-key-DATA", ProviderIdentityHash: hash([]byte("provider DATA")), ScopeHash: hash([]byte("scope DATA")), CAPEMSHA256: hash([]byte("CA DATA"))}, GenerateRef: reg.TypedReference{RawJSON: raw, SHA256: hash(raw)}, UnwrapRef: reg.TypedReference{RawJSON: raw, SHA256: hash(raw)}}
	fingerprint, err := reg.BindingFingerprint(expected)
	if err != nil {
		t.Fatal(err)
	}
	facts := reg.BindingFacts{Binding: expected, BindingSHA256: fingerprint, RowVersion: 1}
	if err := validateAcceptanceCurrentKEKBinding(facts, expected); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"version", "fingerprint", "installation", "config-ref", "provider", "key", "reference", "unwrap"} {
		t.Run(mode, func(t *testing.T) {
			q := facts
			switch mode {
			case "version":
				q.RowVersion = 0
			case "fingerprint":
				q.BindingSHA256 = hash([]byte("wrong fingerprint"))
			case "installation":
				q.Binding.InstallationID += "-other"
			case "config-ref":
				q.Binding.ConfigRef.Version += "-other"
			case "provider":
				q.Binding.Provider.Endpoint += "/other"
			case "key":
				q.Binding.Key.ProviderKeyID += "-other"
			case "reference":
				q.Binding.UnwrapRef = reg.TypedReference{RawJSON: []byte(`{"purpose":"other"}`), SHA256: hash([]byte(`{"purpose":"other"}`))}
			case "unwrap":
				q.UnwrapRevoked = &reg.Revocation{Purpose: reg.UnwrapRevocation}
			}
			if err := validateAcceptanceCurrentKEKBinding(q, expected); err == nil {
				t.Fatal("invalid current comparison accepted", mode)
			}
		})
	}
	// Generation revocation does not revoke retained-artifact unwrap, and a
	// legitimate current RV is not forced back to the pre-revocation RV.
	facts.RowVersion++
	facts.GenerateRevoked = &reg.Revocation{Purpose: reg.GenerateRevocation}
	if err := validateAcceptanceCurrentKEKBinding(facts, expected); err != nil {
		t.Fatal("Generate invalidation confused with Unwrap", err)
	}
	changed := []byte(`{"description_redacted":"changed provenance","purpose":"unwrap"}`)
	facts.Binding.UnwrapRef = reg.TypedReference{RawJSON: changed, SHA256: hash(changed)}
	if err := validateAcceptanceCurrentKEKBinding(facts, expected); err != nil {
		t.Fatal("allowed redacted description confused with security rebinding", err)
	}
}

func TestPublicationAcceptanceCurrentKEKReadRejectsMissingTransaction(t *testing.T) {
	if err := acceptanceCurrentKEKBindingTx(nil, nil, reg.Binding{}); err == nil {
		t.Fatal("missing original transaction admitted current KEK")
	}
	if err := acceptanceCurrentKEKBindingTx(context.Background(), nil, reg.Binding{InstallationID: "installation_DATA"}); err == nil {
		t.Fatal("nil transaction admitted current KEK")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := acceptanceCurrentKEKBindingTx(ctx, nil, reg.Binding{InstallationID: "installation_DATA"}); err == nil {
		t.Fatal("canceled current check admitted KEK")
	}
}
