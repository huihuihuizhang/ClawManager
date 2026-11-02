package systembackupexecution

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
)

// Closed canonical decision DATA, never a committed evidence/current proof.
func publicationDecisionData(t *testing.T) publicationDecisionPreimage {
	t.Helper()
	r, _ := ce.Canonical([]string{"eligible"})
	installation, backup := "installation_decision_DATA", "sbk_11111111-1111-4111-8111-111111111111"
	return publicationDecisionPreimage{Version: "system-backup-publication-eligibility-decision.v1", Installation: installation, Backup: backup, Attempt: 1, ConfigVersion: 2, ConfigSHA256: hash([]byte("config DATA")), OriginalSHA256: hash([]byte("original DATA")), ManifestSHA256: hash([]byte("manifest DATA")), MarkerSHA256: hash([]byte("marker DATA")), IndexSHA256: hash([]byte("index DATA")), CaptureSHA256: hash([]byte("certificate DATA")), AcceptanceSHA256: hash([]byte("complete signed acceptance DATA")), RegistrationID: publicationCatalogRecordID(installation, backup, 1), RegistrationSHA: hash([]byte("complete signed registration DATA")), CleanupID: "sev_original_cleanup_DATA", CleanupSHA256: hash([]byte("cleanup DATA")), Eligible: true, Reasons: []string{"eligible"}, ReasonsSHA256: hash(r), DecisionAt: "2026-11-02T01:02:03.123456Z"}
}

func TestPublicationDecisionCanonicalPreimage(t *testing.T) {
	p := publicationDecisionData(t)
	raw, _ := ce.Canonical(p)
	if _, at, err := decodePublicationDecision(raw); err != nil || at.Nanosecond() != 123456000 {
		t.Fatal("exact original JCS preimage", err)
	}
	for _, mode := range []string{"schema", "installation", "backup", "attempt", "config", "unsafe-attempt", "unsafe-config", "checksum", "registration-id", "cleanup", "eligible", "reasons", "reason-hash", "time", "nanoseconds", "offset-alias", "extra", "legacy", "alias", "duplicate", "missing"} {
		t.Run(mode, func(t *testing.T) {
			q := p
			switch mode {
			case "schema":
				q.Version = "legacy"
			case "installation":
				q.Installation = ""
			case "backup":
				q.Backup = "other-task"
			case "attempt":
				q.Attempt = 0
			case "config":
				q.ConfigVersion = 0
			case "unsafe-attempt":
				q.Attempt = 9007199254740992
			case "unsafe-config":
				q.ConfigVersion = 9007199254740992
			case "checksum":
				q.RegistrationSHA = ""
			case "registration-id":
				q.RegistrationID = "scr_wrong"
			case "cleanup":
				q.CleanupID = "other_cleanup"
			case "eligible":
				q.Eligible = false
			case "reasons":
				q.Reasons = []string{"target_risk"}
				r, _ := ce.Canonical(q.Reasons)
				q.ReasonsSHA256 = hash(r)
			case "reason-hash":
				q.ReasonsSHA256 = hash([]byte("different array DATA"))
			case "time":
				q.DecisionAt = "not-time"
			case "nanoseconds":
				q.DecisionAt = "2026-11-02T01:02:03.123456789Z"
			case "offset-alias":
				q.DecisionAt = "2026-11-02T01:02:03.123456+00:00"
			}
			body, _ := ce.Canonical(q)
			if mode == "extra" || mode == "legacy" || mode == "alias" || mode == "missing" {
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(body, &fields)
				switch mode {
				case "extra":
					fields["claim"] = json.RawMessage(`"caller DATA"`)
				case "legacy":
					fields["signing_key"] = json.RawMessage(`"legacy DATA"`)
				case "alias":
					fields["Decision_At"] = json.RawMessage(`"aliased DATA"`)
				case "missing":
					delete(fields, "eligible")
				}
				body, _ = ce.Canonical(fields)
			}
			if mode == "duplicate" {
				body = []byte(strings.TrimSuffix(string(body), "}") + `,"eligible":true}`)
			}
			if _, _, err := decodePublicationDecision(body); err == nil {
				t.Fatal("malformed preimage accepted", mode)
			}
		})
	}
	for _, checksum := range []string{p.ReasonsSHA256, p.AcceptanceSHA256, p.RegistrationSHA} {
		if hash(raw) == checksum {
			t.Fatal("decision hash aliased another checksum")
		}
	}
}

func TestPublicationDecisionClockAndStableIdentity(t *testing.T) {
	at := time.Date(2026, 11, 2, 1, 2, 3, 123456000, time.UTC)
	if !publicationDecisionClockValid(at, at, at, at) {
		t.Fatal("equal original SQL microsecond boundary rejected")
	}
	for _, values := range [][4]time.Time{{at, at.Add(time.Microsecond), at, at}, {at, at, at.Add(time.Microsecond), at}, {at, at, at, at.Add(-time.Microsecond)}, {at.Add(time.Nanosecond), at, at, at.Add(time.Second)}, {{}, at, at, at}, {at, {}, at, at}, {at, at, {}, at}, {at, at, at, {}}} {
		if publicationDecisionClockValid(values[0], values[1], values[2], values[3]) {
			t.Fatal("invalid decision/signature/SQL time ordering accepted")
		}
	}
	identity := []byte(`["original-publication-eligibility-decision.v1","installation_one","sbk_original",1]`)
	base := publicationDecisionID("installation_one", "sbk_original", 1)
	if base != "sev_pub_decision_"+hash(identity) || len(base) > 128 {
		t.Fatal("stable decision identity recipe drifted")
	}
	seen := map[string]bool{base: true}
	for _, id := range []string{publicationDecisionID("installation_two", "sbk_original", 1), publicationDecisionID("installation_one", "sbk_other", 1), publicationDecisionID("installation_one", "sbk_original", 2), catalogSigningID("installation_one", "sbk_original", 1), acceptanceSigningID("installation_one", "sbk_original", 1)} {
		if seen[id] {
			t.Fatal("different original scope aliases decision")
		}
		seen[id] = true
	}
}

func TestPublicationDecisionRejectsUnboundProof(t *testing.T) {
	ctx := context.Background()
	for _, p := range []*preparedPublicationDecision{nil, {}, {registered: &publicationRegisteredObject{}}} {
		if result, err := p.Persist(ctx); err == nil || result != nil {
			t.Fatal("unbound initializer returned evidence")
		}
		if result, err := p.Query(ctx); err == nil || result != nil {
			t.Fatal("unbound query returned evidence")
		}
	}
	for _, p := range []*publicationDecisionEvidence{nil, {}, {registered: &publicationRegisteredObject{}}} {
		if err := p.recheckTx(ctx, nil); err == nil {
			t.Fatal("non-persisted decision manufactured authority")
		}
	}
	var service *DeploymentService
	if p, err := service.prepareOriginalPublicationDecision(ctx, nil); err == nil || p != nil {
		t.Fatal("nil service prepared decision")
	}
	if p, err := service.queryOriginalPublicationDecision(ctx, nil); err == nil || p != nil {
		t.Fatal("nil service queried decision")
	}
	raw, _ := ce.Canonical(publicationDecisionData(t))
	if err := validateDecisionOriginal(raw, nil, time.Now()); err == nil {
		t.Fatal("canonical content alone granted original evidence")
	}
}
