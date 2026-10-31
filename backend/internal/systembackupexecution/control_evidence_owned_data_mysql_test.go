package systembackupexecution

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	security "clawreef/internal/systembackupsecurity"
)

// This proves original DDL/capacity/inline registration and complete DATA
// coverage for ordinary 25-workspace report shapes. The comparison values are
// explicitly synthetic; this does NOT replace the concrete owned readers or
// prove that these named business parts were actually captured.
func TestAControlEvidenceOwnedReportTwentyFivePartActualDDLDataRegistration(t *testing.T) {
	f := newAControlEvidenceSourceFixture(t)
	h, s, ctx := f.x.history, f.x.history.service, context.Background()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	baseEntries := []ce.RegisteredEvidence{}
	for _, ref := range f.locator.Evidence {
		entry, err := ce.LoadRegisteredSQL(ctx, tx, f.expected.Scope, ref)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		baseEntries = append(baseEntries, entry)
	}
	tx.Rollback()
	base, err := ce.Rebuild(ctx, f.locator, baseEntries)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(base.SidecarJSON)
	defer clear(base.ProofsJSON)
	basis := ce.OwnedReportBasis{CaptureContextSHA256: hash([]byte("named 25-part DATA fixture context")), Parts: []ce.OwnedPartBasis{}}
	policy := ce.FinalizationPolicy{Version: ce.FinalizationPolicyVersion, ChecksVersion: ce.OwnedChecksVersion, CaptureContextSHA256: basis.CaptureContextSHA256, Parts: []ce.FinalizationPart{}}
	for index := 0; index < 25; index++ {
		part := fmt.Sprintf("instance_%06d_workspace", index+1)
		p := ce.OwnedPartBasis{Part: part, Operation: "capture-workspace", InvocationSHA256: hash([]byte(part + " invocation")), CandidateSHA256: hash([]byte(part + " candidate")), ResultSHA256: hash([]byte(part + " result")), ResultEvidenceRef: "sev_original_" + part, CiphertextSHA256: hash([]byte(part + " C stream")), EnvelopeSHA256: hash([]byte(part + " envelope")), CiphertextBytes: 8765}
		basis.Parts = append(basis.Parts, p)
		policy.Parts = append(policy.Parts, ce.FinalizationPart{Part: p.Part, Operation: p.Operation, InvocationSHA256: p.InvocationSHA256})
	}
	seed, err := ce.RequireOwnedFinalization(f.locator, policy)
	if err != nil {
		t.Fatal(err)
	}
	var observed time.Time
	if h.db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&observed) != nil {
		t.Fatal("actual SQL observation clock")
	}
	owners := []ce.OwnedReports{}
	for _, owner := range []string{"B", "C", "D"} {
		category := map[string]string{"B": "instances", "C": "artifact", "D": "control_plane"}[owner]
		attempt := f.expected.Attempt
		required, err := ce.RequiredOwnerChecks(owner, basis)
		if err != nil {
			t.Fatal(err)
		}
		sort.Slice(required, func(i, j int) bool { return required[i].ID < required[j].ID })
		reports := []ce.RegisteredEvidence{}
		for offset := 0; offset < len(required); offset += 10 {
			report := ce.VerifierReport{Version: "system-backup-verifier-result.v1", TargetType: "backup", Target: f.expected.Backup, Attempt: &attempt, Category: category, Mode: "backup_validate", Checks: []ce.VerifierCheck{}}
			end := offset + 10
			if end > len(required) {
				end = len(required)
			}
			for _, check := range required[offset:end] {
				ref := check.ResultEvidenceRef
				report.Checks = append(report.Checks, ce.VerifierCheck{ID: check.ID, Status: "passed", Expected: check.Expected, Actual: check.Expected, Evidence: &ref, Failure: "none"})
			}
			raw, err := ce.Canonical(report)
			if err != nil {
				t.Fatal(err)
			}
			reports = append(reports, ce.RegisteredEvidence{PublicID: fmt.Sprintf("sev_owned_data_%s_%d", owner, offset), SHA256: hash(raw), OwnerType: "backup", OwnerID: f.expected.Backup, Type: "verifier_report", Payload: raw})
		}
		owners = append(owners, ce.OwnedReports{Owner: owner, ObservedAt: observed, Basis: basis, Reports: reports})
	}
	complete, err := ce.AssembleFinalized(ctx, seed, base, observed, owners)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(complete.Prepared.SidecarJSON)
	defer clear(complete.Prepared.ProofsJSON)
	seal, err := ce.SealFinalizedSource(ctx, seed, complete.Prepared.Locator, complete.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	all := append(append([]ce.RegisteredEvidence{}, complete.Evidence...), seal.LocatorChunks...)
	all = append(all, seal.Seal)
	aRefreshControlSourceCapacity(t, f)
	tx, err = h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	guard, err := h.owner.Gate.Authority.Bind(ctx, tx, f.in.Authority)
	if err != nil {
		t.Fatal("actual preparing original guard", err)
	}
	total := 0
	for _, entry := range all {
		total += len(entry.Payload)
		if len(entry.Payload) > 8192 {
			t.Fatal("inline limit changed")
		}
	}
	if err = (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).ReserveExecutionPayload(ctx, tx, 1<<30, total); err != nil {
		t.Fatal("original metadata reservation", err)
	}
	if err = ce.RegisterSQL(ctx, tx, f.expected.Scope, all, observed.Add(time.Hour)); err != nil {
		t.Fatal("actual bounded owned reports registration", err)
	}
	if err = guard.Recheck(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, err = h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	loaded := []ce.RegisteredEvidence{}
	chunks := 0
	for _, ref := range complete.Prepared.Locator.Evidence {
		entry, err := ce.LoadRegisteredSQL(ctx, tx, f.expected.Scope, ref)
		if err != nil {
			t.Fatal("actual original immutable readback", err)
		}
		var kind struct {
			Version string `json:"schema_version"`
		}
		json.Unmarshal(entry.Payload, &kind)
		if kind.Version == "system-backup-control-owned-basis-chunk.v1" {
			chunks++
		}
		loaded = append(loaded, entry)
	}
	if chunks != 4 {
		t.Fatal("25-part coverage was truncated", chunks)
	}
	sealRead, err := ce.LoadRegisteredSQL(ctx, tx, f.expected.Scope, ce.EvidenceRef{PublicID: seal.Seal.PublicID, SHA256: seal.Seal.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	locatorChunks := []ce.RegisteredEvidence{}
	for _, chunk := range seal.LocatorChunks {
		entry, readErr := ce.LoadRegisteredSQL(ctx, tx, f.expected.Scope, ce.EvidenceRef{PublicID: chunk.PublicID, SHA256: chunk.SHA256})
		if readErr != nil {
			t.Fatal(readErr)
		}
		locatorChunks = append(locatorChunks, entry)
	}
	final, err := ce.ReadFinalizedSourceSeal(seed, sealRead, locatorChunks...)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := ce.VerifyFinalized(ctx, seed, final, loaded)
	if err != nil || verified.SidecarSHA256 != complete.Prepared.SidecarSHA256 {
		t.Fatal("registered complete reconstruction", err)
	}
	clear(verified.SidecarJSON)
	clear(verified.ProofsJSON)
	for index, entry := range loaded {
		var kind struct {
			Version string `json:"schema_version"`
		}
		json.Unmarshal(entry.Payload, &kind)
		if kind.Version == "system-backup-control-owned-basis-chunk.v1" {
			missing := append(append([]ce.RegisteredEvidence{}, loaded[:index]...), loaded[index+1:]...)
			if _, err = ce.VerifyFinalized(ctx, seed, final, missing); err == nil {
				t.Fatal("missing original basis chunk repaired")
			}
			break
		}
	}
}
