package systembackupresources

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func assertResourceChecksPassed(t *testing.T, checks []ResourcesCheck) {
	t.Helper()
	if len(checks) != 12 {
		t.Fatal("incomplete resources comparison", len(checks))
	}
	for _, check := range checks {
		if check.Status != "passed" || check.FailureCategory != "none" {
			t.Fatal("proof changed the validated comparison", check)
		}
	}
	if checks[len(checks)-1].Expected["max_id"] != int64(7) || checks[len(checks)-1].Actual["max_id"] != int64(7) {
		t.Fatal("proof changed the compared audit cutoff")
	}
}
func TestResourcesCaptureProofCannotChangeValidatedInputs(t *testing.T) {
	for _, mode := range []string{"unchanged", "source_rows", "dump_rows", "source_identity", "dump_identity", "source_cutoff", "dump_cutoff", "proof_error", "proof_error_canceled", "proof_canceled"} {
		t.Run(mode, func(t *testing.T) {
			source, dump := verifierEvidence(), verifierEvidence()
			wantSource, wantDump := verifierEvidence(), verifierEvidence()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			proofErr := errors.New("capture authority rejected")
			calls := 0
			proof := completionCaptureProof(func(_ context.Context, s, d CaptureSnapshotEvidence) error {
				calls++
				if !reflect.DeepEqual(s, wantSource) || !reflect.DeepEqual(d, wantDump) {
					t.Fatal("proof received altered claims")
				}
				switch mode {
				case "source_rows":
					s.Snapshot.Tables[1].Rows = 900
				case "dump_rows":
					d.Snapshot.Tables[1].Rows = 900
				case "source_identity":
					s.Snapshot.Tables[0].Table = "not_a_resource"
				case "dump_identity":
					d.Snapshot.Tables[0].Table = "not_a_resource"
				case "source_cutoff":
					*s.Snapshot.AuditMaxID = 900
				case "dump_cutoff":
					*d.Snapshot.AuditMaxID = 900
				case "proof_error", "proof_error_canceled", "proof_canceled":
					s.Snapshot.Tables[1].Rows = 900
					*d.Snapshot.AuditMaxID = 900
					if mode != "proof_error" {
						cancel()
					}
					if mode != "proof_canceled" {
						return proofErr
					}
				}
				return nil
			})
			checks, err := VerifyBackupSnapshot(ctx, frozenRegistryBytes(t), source, dump, proof)
			if calls != 1 {
				t.Fatal("proof repeated", calls)
			}
			switch mode {
			case "proof_error", "proof_error_canceled":
				if !errors.Is(err, proofErr) || checks != nil || !strings.Contains(err.Error(), "resources capture proof:") {
					t.Fatal("proof error lost", checks, err)
				}
			case "proof_canceled":
				if !errors.Is(err, context.Canceled) || checks != nil {
					t.Fatal("canceled proof released a comparison", checks, err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				assertResourceChecksPassed(t, checks)
			}
			if !reflect.DeepEqual(source, wantSource) || !reflect.DeepEqual(dump, wantDump) {
				t.Fatal("proof argument mutation escaped into caller data")
			}
		})
	}
}
func TestResourcesCaptureProofInputsStaySeparate(t *testing.T) {
	for _, mode := range []string{"shared_caller_storage", "retained_source", "retained_dump"} {
		t.Run(mode, func(t *testing.T) {
			source, dump := verifierEvidence(), verifierEvidence()
			if mode == "shared_caller_storage" {
				dump = source
			}
			wantSource, wantDump := verifierEvidence(), verifierEvidence()
			independent := true
			calls := 0
			retained := func() {}
			proof := completionCaptureProof(func(_ context.Context, s, d CaptureSnapshotEvidence) error {
				calls++
				if mode == "shared_caller_storage" {
					s.Snapshot.Tables[1].Rows = 901
					*s.Snapshot.AuditMaxID = 901
					independent = reflect.DeepEqual(d, wantDump)
				} else if mode == "retained_source" {
					retained = func() { s.Snapshot.Tables[1].Rows = 902; *s.Snapshot.AuditMaxID = 902 }
				} else {
					retained = func() { d.Snapshot.Tables[1].Rows = 902; *d.Snapshot.AuditMaxID = 902 }
				}
				return nil
			})
			checks, err := VerifyBackupSnapshot(context.Background(), frozenRegistryBytes(t), source, dump, proof)
			if err != nil || calls != 1 {
				t.Fatal("proof failed or repeated", err, calls)
			}
			retained()
			if !independent {
				t.Fatal("source and dump proof arguments share storage")
			}
			assertResourceChecksPassed(t, checks)
			if !reflect.DeepEqual(source, wantSource) || !reflect.DeepEqual(dump, wantDump) {
				t.Fatal("retained proof input altered caller data")
			}
		})
	}
}
func TestResourcesCaptureProofCannotHideOriginalMismatches(t *testing.T) {
	for _, mode := range []string{"rows", "audit", "external_rows", "external_audit"} {
		t.Run(mode, func(t *testing.T) {
			source, dump := verifierEvidence(), verifierEvidence()
			wantID, key, wantExpected, wantActual := "resources.table_count.egress_private_exceptions", "rows", int64(1), int64(2)
			if strings.HasSuffix(mode, "rows") {
				dump.Snapshot.Tables[1].Rows = 2
			} else {
				*dump.Snapshot.AuditMaxID = 8
				wantID, key, wantExpected, wantActual = "resources.audit_cutoff", "max_id", 7, 8
			}
			calls := 0
			proof := completionCaptureProof(func(_ context.Context, s, d CaptureSnapshotEvidence) error {
				calls++
				switch mode {
				case "rows":
					d.Snapshot.Tables[1].Rows = s.Snapshot.Tables[1].Rows
				case "audit":
					*d.Snapshot.AuditMaxID = *s.Snapshot.AuditMaxID
				// These writes intentionally use a separately captured caller reference.
				// The verifier cannot stop that write; its frozen comparison must survive.
				case "external_rows":
					dump.Snapshot.Tables[1].Rows = source.Snapshot.Tables[1].Rows
				case "external_audit":
					*dump.Snapshot.AuditMaxID = *source.Snapshot.AuditMaxID
				}
				return nil
			})
			checks, err := VerifyBackupSnapshot(context.Background(), frozenRegistryBytes(t), source, dump, proof)
			if err != nil || calls != 1 || len(checks) != 12 {
				t.Fatal("mismatch comparison failed", err, calls, len(checks))
			}
			failed := 0
			for _, check := range checks {
				if check.Status == "failed" {
					failed++
					if check.ID != wantID || check.Expected[key] != wantExpected || check.Actual[key] != wantActual || check.FailureCategory != "validation_failed" || check.CheckClassification == nil || *check.CheckClassification != "integrity" {
						t.Fatal("wrong original mismatch", check)
					}
				}
			}
			if failed != 1 {
				t.Fatal("proof callback hid an original capture mismatch", mode, failed)
			}
			if mode == "rows" && dump.Snapshot.Tables[1].Rows != 2 || mode == "audit" && *dump.Snapshot.AuditMaxID != 8 {
				t.Fatal("proof mutated caller mismatch data")
			}
		})
	}
}
func TestResourcesCaptureProofEmptyAuditPreservesNull(t *testing.T) {
	source, dump := verifierEvidence(), verifierEvidence()
	source.Snapshot.Tables[0].Rows = 0
	dump.Snapshot.Tables[0].Rows = 0
	source.Snapshot.AuditMaxID = nil
	dump.Snapshot.AuditMaxID = nil
	calls := 0
	proof := completionCaptureProof(func(_ context.Context, s, d CaptureSnapshotEvidence) error {
		calls++
		if s.Snapshot.AuditMaxID != nil || d.Snapshot.AuditMaxID != nil {
			t.Fatal("empty audit cutoff invented")
		}
		s.Snapshot.AuditMaxID = new(int64)
		*s.Snapshot.AuditMaxID = 903
		return nil
	})
	checks, err := VerifyBackupSnapshot(context.Background(), frozenRegistryBytes(t), source, dump, proof)
	if err != nil || calls != 1 || len(checks) != 12 || source.Snapshot.AuditMaxID != nil || dump.Snapshot.AuditMaxID != nil {
		t.Fatal("empty audit comparison changed", err, calls, len(checks))
	}
	for _, check := range checks {
		if check.Status != "passed" {
			t.Fatal("empty audit mismatch invented", check)
		}
	}
	if checks[len(checks)-1].Expected["max_id"] != nil || checks[len(checks)-1].Actual["max_id"] != nil {
		t.Fatal("empty audit cutoff no longer null")
	}
}
