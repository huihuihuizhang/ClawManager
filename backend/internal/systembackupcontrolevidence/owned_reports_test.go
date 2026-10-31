package systembackupcontrolevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// Protocol DATA only. Actual comparison producers must read original owned
// payloads and SQL; these synthetic envelopes grant no task/Generate permission.
func ownedReportFixture(t *testing.T, counts ...int) (ProposedSource, CaptureLocator, []OwnedReports) {
	t.Helper()
	base, err := Assemble(context.Background(), protocolSnapshot(t, 121))
	if err != nil {
		t.Fatal(err)
	}
	basis := OwnedReportBasis{CaptureContextSHA256: SHA256([]byte("original frozen capture context")), Parts: []OwnedPartBasis{}}
	policy := FinalizationPolicy{Version: FinalizationPolicyVersion, ChecksVersion: OwnedChecksVersion, CaptureContextSHA256: basis.CaptureContextSHA256, Parts: []FinalizationPart{}}
	parts := []string{"business_sql", "source_redis"}
	if len(counts) == 1 {
		parts = []string{}
		for index := 0; index < counts[0]; index++ {
			parts = append(parts, fmt.Sprintf("instance_%06d_workspace", index+1))
		}
	}
	for index, part := range parts {
		op := "capture-database"
		if index == 1 {
			op = "capture-source-redis"
		}
		if len(counts) == 1 {
			op = "capture-workspace"
		}
		p := OwnedPartBasis{Part: part, Operation: op, InvocationSHA256: SHA256([]byte(part + " invocation")), CandidateSHA256: SHA256([]byte(part + " candidate")), ResultSHA256: SHA256([]byte(part + " result")), ResultEvidenceRef: "sev_original_" + part, CiphertextSHA256: SHA256([]byte(part + " cipher")), EnvelopeSHA256: SHA256([]byte(part + " envelope")), CiphertextBytes: 123}
		basis.Parts = append(basis.Parts, p)
		policy.Parts = append(policy.Parts, FinalizationPart{p.Part, p.Operation, p.InvocationSHA256})
	}
	seed, err := RequireOwnedFinalization(base.Prepared.Locator, policy)
	if err != nil {
		t.Fatal(err)
	}
	owners := []OwnedReports{}
	for _, name := range []string{"B", "C", "D"} {
		category := map[string]string{"B": "instances", "C": "artifact", "D": "control_plane"}[name]
		attempt := base.Prepared.Attempt
		required, err := RequiredOwnerChecks(name, basis)
		if err != nil {
			t.Fatal(err)
		}
		sort.Slice(required, func(i, j int) bool { return required[i].ID < required[j].ID })
		reports := []RegisteredEvidence{}
		for offset := 0; offset < len(required); offset += 10 {
			report := VerifierReport{Version: "system-backup-verifier-result.v1", TargetType: "backup", Target: base.Prepared.Backup, Attempt: &attempt, Category: category, Mode: "backup_validate", Checks: []VerifierCheck{}}
			end := offset + 10
			if end > len(required) {
				end = len(required)
			}
			for _, check := range required[offset:end] {
				ref := check.ResultEvidenceRef
				report.Checks = append(report.Checks, VerifierCheck{ID: check.ID, Status: "passed", Expected: check.Expected, Actual: bytes.Clone(check.Expected), Evidence: &ref, Failure: "none"})
			}
			entry, err := registered(base.Prepared.Scope, report)
			if err != nil {
				t.Fatal(err)
			}
			reports = append(reports, entry)
		}
		owners = append(owners, OwnedReports{Owner: name, ObservedAt: base.Prepared.Locator.End.Add(time.Second), Basis: basis, Reports: reports})
	}
	return base, seed, owners
}

func TestOwnedReportBasisChunksPreserveTwentyFiveOriginalPartIdentities(t *testing.T) {
	base, seed, owners := ownedReportFixture(t, 25)
	complete, err := AssembleFinalized(context.Background(), seed, base.Prepared, base.Prepared.Locator.Generated.Add(2*time.Second), owners)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyFinalized(context.Background(), seed, complete.Prepared.Locator, complete.Evidence); err != nil {
		t.Fatal(err)
	}
	chunks := 0
	for _, entry := range complete.Evidence {
		if len(entry.Payload) > 8192 {
			t.Fatal("original SQL inline bound exceeded")
		}
		var kind struct {
			Version string `json:"schema_version"`
		}
		json.Unmarshal(entry.Payload, &kind)
		if kind.Version == "system-backup-control-owned-basis-chunk.v1" {
			chunks++
		}
	}
	if chunks != 4 {
		t.Fatal("twenty-five parts were truncated or repeated", chunks)
	}
}

func TestOwnedReportsPreserveHistoricalCutoffAndBindLaterOriginalResults(t *testing.T) {
	ctx := context.Background()
	base, seed, owners := ownedReportFixture(t)
	complete, err := AssembleFinalized(ctx, seed, base.Prepared, base.Prepared.Locator.Generated.Add(2*time.Second), owners)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := VerifyFinalized(ctx, seed, complete.Prepared.Locator, complete.Evidence)
	if err != nil || !bytes.Equal(rebuilt.SidecarJSON, complete.Prepared.SidecarJSON) || !bytes.Equal(rebuilt.ProofsJSON, complete.Prepared.ProofsJSON) {
		t.Fatal("complete bound reconstruction", err)
	}
	var before, after Sidecar
	json.Unmarshal(base.Prepared.SidecarJSON, &before)
	json.Unmarshal(complete.Prepared.SidecarJSON, &after)
	if !after.Start.Equal(before.Start) || !after.End.Equal(before.End) || !after.Generated.After(before.Generated) || after.Groups["event"].Count != 121 {
		t.Fatal("historical window changed")
	}
	for _, name := range []string{"A", "B", "C", "D"} {
		if after.Owners[name].Status != "complete" {
			t.Fatal("missing actual envelope", name)
		}
	}
	seal, err := SealFinalizedSource(ctx, seed, complete.Prepared.Locator, complete.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	locator, err := ReadFinalizedSourceSeal(seed, seal.Seal, seal.LocatorChunks...)
	if err != nil || locator.SidecarSHA256 != complete.Prepared.SidecarSHA256 {
		t.Fatal("original source seal", err)
	}
	if _, err = Rebuild(ctx, seed, base.Evidence); err == nil {
		t.Fatal("v2 treated base snapshot as complete source")
	}
	if _, err = ReadFinalizedSourceSeal(base.Prepared.Locator, seal.Seal, seal.LocatorChunks...); err == nil {
		t.Fatal("v1 silently adopted v2 finalization")
	}
}

func TestOwnedReportsRejectMissingFailedCrossScopeAndChangedFrozenBasis(t *testing.T) {
	for _, mode := range []string{"missing-owner", "failed-check", "mismatched-check", "self-equal-wrong-violations", "unknown-check-id", "cross-attempt", "unbound-evidence", "missing-part", "different-owner-basis", "wrong-frozen-context", "after-generation", "before-cutoff", "raw-string"} {
		t.Run(mode, func(t *testing.T) {
			base, seed, owners := ownedReportFixture(t)
			var report VerifierReport
			json.Unmarshal(owners[0].Reports[0].Payload, &report)
			switch mode {
			case "missing-owner":
				owners = owners[:2]
			case "failed-check":
				report.Checks[0].Status = "failed"
			case "mismatched-check":
				report.Checks[0].Actual = json.RawMessage(`{"count":2}`)
			case "self-equal-wrong-violations":
				for index := range report.Checks {
					if strings.HasSuffix(report.Checks[index].ID, ".domain_violations") {
						report.Checks[index].Expected = json.RawMessage(`{"violations":1}`)
						report.Checks[index].Actual = bytes.Clone(report.Checks[index].Expected)
					}
				}
			case "unknown-check-id":
				report.Checks[0].ID = "instances.synthetic_passed_check"
			case "cross-attempt":
				attempt := uint64(99)
				report.Attempt = &attempt
			case "unbound-evidence":
				ref := "sev_unrelated_original"
				report.Checks[0].Evidence = &ref
			case "missing-part":
				report.Checks = report.Checks[:1]
			case "different-owner-basis":
				owners[0].Basis.CaptureContextSHA256 = SHA256([]byte("different original context"))
			case "wrong-frozen-context":
				for index := range owners {
					owners[index].Basis.CaptureContextSHA256 = SHA256([]byte("all agree on wrong original context"))
				}
			case "after-generation":
				owners[0].ObservedAt = base.Prepared.Locator.Generated.Add(time.Hour)
			case "before-cutoff":
				owners[0].ObservedAt = base.Prepared.Locator.End.Add(-time.Second)
			case "raw-string":
				report.Checks[0].Expected = json.RawMessage(`{"value":"private arbitrary text"}`)
				report.Checks[0].Actual = bytes.Clone(report.Checks[0].Expected)
			}
			if mode != "missing-owner" {
				entry, err := registered(base.Prepared.Scope, report)
				if err != nil {
					t.Fatal(err)
				}
				owners[0].Reports = []RegisteredEvidence{entry}
			}
			if mode == "wrong-frozen-context" {
				// Recompute every D comparison consistently with the malicious
				// common basis. The separately frozen source seed must still reject.
				required, _ := RequiredOwnerChecks("D", owners[2].Basis)
				values := map[string]json.RawMessage{}
				for _, check := range required {
					values[check.ID] = check.Expected
				}
				for index, entry := range owners[2].Reports {
					var changed VerifierReport
					json.Unmarshal(entry.Payload, &changed)
					for checkIndex := range changed.Checks {
						value := values[changed.Checks[checkIndex].ID]
						changed.Checks[checkIndex].Expected = value
						changed.Checks[checkIndex].Actual = bytes.Clone(value)
					}
					updated, err := registered(base.Prepared.Scope, changed)
					if err != nil {
						t.Fatal(err)
					}
					owners[2].Reports[index] = updated
				}
			}
			assemblySeed := seed
			if mode == "wrong-frozen-context" {
				raw, _ := json.Marshal(seed)
				assemblySeed = CaptureLocator{}
				json.Unmarshal(raw, &assemblySeed)
				assemblySeed.Finalization.CaptureContextSHA256 = owners[0].Basis.CaptureContextSHA256
			}
			complete, err := AssembleFinalized(context.Background(), assemblySeed, base.Prepared, base.Prepared.Locator.Generated.Add(2*time.Second), owners)
			if mode == "wrong-frozen-context" {
				if err != nil {
					t.Fatal("well-formed data basis should still require concrete original seed", err)
				}
				if _, err = VerifyFinalized(context.Background(), seed, complete.Prepared.Locator, complete.Evidence); err == nil {
					t.Fatal("agreed but wrong basis bypassed original seed")
				}
				return
			}
			if err == nil {
				t.Fatal("invalid owned comparison admitted")
			}
		})
	}
}

func TestOwnedReportSelfEqualCiphertextBytesCannotChooseItsOwnExpectedCount(t *testing.T) {
	base, seed, owners := ownedReportFixture(t)
	changedCount := false
	for index, entry := range owners[1].Reports {
		var report VerifierReport
		if json.Unmarshal(entry.Payload, &report) != nil {
			t.Fatal("C report fixture")
		}
		for checkIndex := range report.Checks {
			check := &report.Checks[checkIndex]
			if strings.HasSuffix(check.ID, ".ciphertext_bytes") {
				check.Expected, check.Actual = json.RawMessage(`{"bytes":999}`), json.RawMessage(`{"bytes":999}`)
				changedCount = true
			}
		}
		updated, err := registered(base.Prepared.Scope, report)
		if err != nil {
			t.Fatal(err)
		}
		owners[1].Reports[index] = updated
	}
	if !changedCount {
		t.Fatal("missing concrete C byte comparisons")
	}
	if _, err := AssembleFinalized(context.Background(), seed, base.Prepared, base.Prepared.Locator.Generated.Add(2*time.Second), owners); err == nil {
		t.Fatal("self-equal but wrong C byte count bypassed compiled original-basis policy")
	}
}
