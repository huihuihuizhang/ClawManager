package systembackupbusinessa

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
)

func emptyCategoryChecks(checks CategoryChecks) bool {
	return len(checks.Users) == 0 && len(checks.AIGateway) == 0
}

func allCategoryChecks(checks CategoryChecks) []Check {
	return append(append([]Check(nil), checks.Users...), checks.AIGateway...)
}

func assertContractCheckIDs(t *testing.T, checks CategoryChecks) {
	t.Helper()
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/verifier-contract.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	defs := document["$defs"].(map[string]any)
	for _, tc := range []struct {
		definition string
		checks     []Check
	}{
		{"AUsersBackupCheck", checks.Users},
		{"AAIGatewayBackupCheck", checks.AIGateway},
	} {
		definition := defs[tc.definition].(map[string]any)
		choices := definition["allOf"].([]any)[1].(map[string]any)["oneOf"].([]any)
		want := make([]string, 0, len(tc.checks))
		for _, rawChoice := range choices {
			ids := rawChoice.(map[string]any)["properties"].(map[string]any)["id"].(map[string]any)["enum"].([]any)
			for _, id := range ids {
				want = append(want, id.(string))
			}
		}
		got := make([]string, 0, len(tc.checks))
		for _, check := range tc.checks {
			got = append(got, check.ID)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s IDs drift from v12 contract: got %v, want %v", tc.definition, got, want)
		}
	}
}

type proofFixture struct {
	calls int
	err   error
}

func (p *proofFixture) VerifyCapture(_ context.Context, source, dump CaptureEvidence) error {
	p.calls++
	if source.EvidenceRef == "" || dump.EvidenceRef == "" {
		return errors.New("unbound evidence")
	}
	return p.err
}

func captureFixture(t *testing.T) (CaptureEvidence, CaptureEvidence) {
	t.Helper()
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	allowlist := scope.Tables()
	snapshot := SourceSnapshot{CostAggregateSHA256: fixtureCostAggregateHash(t, 2), Tables: make([]TableCount, 0, len(allowlist))}
	for _, table := range allowlist {
		snapshot.Tables = append(snapshot.Tables, TableCount{Table: table, Rows: 2})
	}
	source := CaptureEvidence{RegistrySHA256: scope.RegistrySHA256(), SchemaSHA256: scope.SchemaSHA256(),
		CheckpointHash: strings.Repeat("a", 64), CaptureContextHash: strings.Repeat("b", 64),
		EvidenceRef: "sev_source", Snapshot: snapshot}
	dump := source
	dump.EvidenceRef = "sev_dump"
	dump.Snapshot.Tables = append([]TableCount(nil), source.Snapshot.Tables...)
	return source, dump
}

func TestVerifyBackupSnapshotRequiresProofAndCompleteCounts(t *testing.T) {
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	source, dump := captureFixture(t)
	if checks, err := VerifyBackupSnapshot(context.Background(), scope, source, dump, nil); !errors.Is(err, ErrCaptureEvidenceIncomplete) || !emptyCategoryChecks(checks) {
		t.Fatalf("missing proof admitted: %v, %v", checks, err)
	}
	if category, known := KnownVerificationFailureCategory(ErrCaptureEvidenceIncomplete); !known || category != "evidence_incomplete" {
		t.Fatalf("missing proof category=%s known=%v", category, known)
	}
	var typedNil *proofFixture
	if checks, err := VerifyBackupSnapshot(context.Background(), scope, source, dump, typedNil); err == nil || !emptyCategoryChecks(checks) {
		t.Fatalf("typed nil proof admitted: %v, %v", checks, err)
	}
	proof := &proofFixture{}
	checks, err := VerifyBackupSnapshot(context.Background(), scope, source, dump, proof)
	if err != nil || len(checks.Users) != 8 || len(checks.AIGateway) != 12 || proof.calls != 1 {
		t.Fatalf("valid snapshot rejected: %v, %v", checks, err)
	}
	assertContractCheckIDs(t, checks)
	for _, check := range allCategoryChecks(checks) {
		if check.Status != "passed" || check.FailureCategory != "none" || check.EvidenceRef == nil || *check.EvidenceRef != "sev_dump" ||
			check.SkipReason != nil || check.WarningCode != nil || check.CheckClassification != nil {
			t.Fatalf("unexpected check: %+v", check)
		}
		var shape map[string]any
		raw, err := json.Marshal(check)
		if err != nil || json.Unmarshal(raw, &shape) != nil || len(shape) != 9 {
			t.Fatalf("check does not match v12 required field shape: %s, %v", raw, err)
		}
	}
	for _, check := range checks.Users {
		if !strings.HasPrefix(check.ID, "users.") {
			t.Fatalf("users check escaped category: %s", check.ID)
		}
	}
	for _, check := range checks.AIGateway {
		if !strings.HasPrefix(check.ID, "ai_gateway.") {
			t.Fatalf("AI Gateway check escaped category: %s", check.ID)
		}
	}
	dump.Snapshot.Tables[len(dump.Snapshot.Tables)-1].Rows = 3
	checks, err = VerifyBackupSnapshot(context.Background(), scope, source, dump, proof)
	if !errors.Is(err, ErrSnapshotMismatch) || len(checks.Users) != 8 || checks.Users[7].Status != "failed" ||
		checks.Users[7].FailureCategory != "validation_failed" || checks.Users[7].CheckClassification == nil ||
		*checks.Users[7].CheckClassification != "integrity" {
		t.Fatalf("count mismatch not reported: %v, %v", checks, err)
	}
	if category, known := KnownVerificationFailureCategory(err); !known || category != "validation_failed" {
		t.Fatalf("mismatch category=%s known=%v", category, known)
	}
	dump.Snapshot.Tables[len(dump.Snapshot.Tables)-1].Rows = 2
	dump.CheckpointHash = strings.Repeat("c", 64)
	checks, err = VerifyBackupSnapshot(context.Background(), scope, source, dump, proof)
	if !errors.Is(err, ErrSnapshotMismatch) || checks.Users[0].Status != "failed" || checks.AIGateway[0].Status != "failed" {
		t.Fatalf("checkpoint mismatch not rejected: %v, %v", checks, err)
	}
	proof.err = errors.New("capture certificate rejected")
	if checks, err := VerifyBackupSnapshot(context.Background(), scope, source, dump, proof); err == nil || !emptyCategoryChecks(checks) {
		t.Fatalf("proof failure returned checks: %v, %v", checks, err)
	} else if category, known := KnownVerificationFailureCategory(err); known || category != "" {
		t.Fatalf("B proof cause was reclassified: %s known=%v", category, known)
	}
}

func TestVerifyBackupSnapshotRejectsUnboundInputsBeforeProof(t *testing.T) {
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	source, dump := captureFixture(t)
	for _, tc := range []struct {
		name string
		edit func(*CaptureEvidence, *CaptureEvidence)
		want error
	}{
		{"missing table", func(_ *CaptureEvidence, d *CaptureEvidence) { d.Snapshot.Tables = d.Snapshot.Tables[:14] }, ErrInvalidSnapshot},
		{"negative count", func(_ *CaptureEvidence, d *CaptureEvidence) { d.Snapshot.Tables[0].Rows = -1 }, ErrInvalidSnapshot},
		{"wrong order", func(_ *CaptureEvidence, d *CaptureEvidence) {
			d.Snapshot.Tables[0], d.Snapshot.Tables[1] = d.Snapshot.Tables[1], d.Snapshot.Tables[0]
		}, ErrInvalidSnapshot},
		{"missing evidence", func(_ *CaptureEvidence, d *CaptureEvidence) { d.EvidenceRef = "" }, ErrCaptureEvidenceIncomplete},
		{"invalid evidence", func(_ *CaptureEvidence, d *CaptureEvidence) { d.EvidenceRef = "../../escape" }, ErrInvalidSnapshot},
		{"invalid checkpoint", func(s *CaptureEvidence, _ *CaptureEvidence) { s.CheckpointHash = "not-a-hash" }, ErrInvalidSnapshot},
		{"wrong registry", func(_ *CaptureEvidence, d *CaptureEvidence) { d.RegistrySHA256 = strings.Repeat("c", 64) }, ErrInvalidSnapshot},
		{"wrong schema", func(s *CaptureEvidence, _ *CaptureEvidence) { s.SchemaSHA256 = strings.Repeat("c", 64) }, ErrInvalidSnapshot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, d := captureFixture(t)
			tc.edit(&s, &d)
			proof := &proofFixture{}
			if checks, err := VerifyBackupSnapshot(context.Background(), scope, s, d, proof); !errors.Is(err, tc.want) || !emptyCategoryChecks(checks) || proof.calls != 0 {
				t.Fatalf("invalid evidence reached proof: %v, %v, calls=%d", checks, err, proof.calls)
			}
		})
	}
	proof := &proofFixture{}
	if checks, err := VerifyBackupSnapshot(context.Background(), nil, source, dump, proof); err == nil || !emptyCategoryChecks(checks) || proof.calls != 0 {
		t.Fatalf("draft registry reached proof: %v, %v", checks, err)
	}
	if checks, err := VerifyBackupSnapshot(nil, scope, source, dump, proof); err == nil || !emptyCategoryChecks(checks) || proof.calls != 0 {
		t.Fatalf("nil context reached proof: %v, %v", checks, err)
	}
}

func TestVerifyBusinessMetadataRequiresCompleteAuthenticatedCapture(t *testing.T) {
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	source, dump := captureFixture(t)
	proof := &proofFixture{}
	metadata, err := VerifyBusinessMetadata(context.Background(), scope, source, dump, proof)
	if err != nil || proof.calls != 1 {
		t.Fatalf("valid capture metadata rejected: %+v, %v", metadata, err)
	}
	if !reflect.DeepEqual(metadata.Statistics, []CategoryStatistics{
		{Category: "users", Objects: 6, Rows: 12},
		{Category: "ai_gateway", Objects: 9, Rows: 18},
	}) || !reflect.DeepEqual(metadata.EvidenceIDs, []string{"sev_source", "sev_dump"}) ||
		metadata.RegistrySHA256 != scope.RegistrySHA256() || metadata.SchemaSHA256 != scope.SchemaSHA256() ||
		metadata.CheckpointHash != source.CheckpointHash || len(metadata.Checks.Users) != 8 || len(metadata.Checks.AIGateway) != 12 {
		t.Fatalf("incomplete or cross-category metadata: %+v", metadata)
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]any
	if err := json.Unmarshal(raw, &shape); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"status", "part", "bytes", "eligible"} {
		if _, present := shape[forbidden]; present {
			t.Fatalf("metadata claimed unavailable part fact %s", forbidden)
		}
	}
	dump.Snapshot.Tables[0].Rows++
	if result, err := VerifyBusinessMetadata(context.Background(), scope, source, dump, proof); !errors.Is(err, ErrSnapshotMismatch) || len(result.Statistics) != 0 || len(result.EvidenceIDs) != 0 {
		t.Fatalf("mismatched capture emitted metadata: %+v, %v", result, err)
	}
	dump.Snapshot.Tables[0].Rows--
	proof.err = errors.New("certificate rejected")
	if result, err := VerifyBusinessMetadata(context.Background(), scope, source, dump, proof); err == nil || len(result.Statistics) != 0 || len(result.EvidenceIDs) != 0 {
		t.Fatalf("unverified capture emitted metadata: %+v, %v", result, err)
	}
}

func TestVerifyBusinessMetadataRejectsCountOverflow(t *testing.T) {
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	source, dump := captureFixture(t)
	source.Snapshot.Tables[0].Rows = math.MaxInt64
	dump.Snapshot.Tables[0].Rows = math.MaxInt64
	proof := &proofFixture{}
	if result, err := VerifyBusinessMetadata(context.Background(), scope, source, dump, proof); err == nil || len(result.Statistics) != 0 || proof.calls != 0 {
		t.Fatalf("overflowing counts reached proof or metadata: %+v, %v", result, err)
	} else if category, known := KnownVerificationFailureCategory(err); !known || category != "validation_failed" {
		t.Fatalf("overflow category=%s known=%v", category, known)
	}
}

func TestKnownVerificationFailureCategoryMapsRestoreNormalizers(t *testing.T) {
	for _, err := range []error{
		ErrRestoreNormalizationMismatch, ErrUserRestoreMapping, ErrUserQuotaRestore,
		ErrNorthboundChallengeRestore, ErrNorthboundSessionRestore, ErrNorthboundCallerPolicyRestore,
		ErrEnterpriseAuthRestore, ErrLLMModelRestore, ErrGatewayAliasRestore,
		ErrRiskRuleRestore,
		ErrRiskHitRestore,
		ErrChatSessionRestore,
		ErrChatMessageRestore,
	} {
		if category, known := KnownVerificationFailureCategory(errors.Join(errors.New("restore step"), err)); !known || category != "normalization_failed" {
			t.Fatalf("restore normalizer error %v was not classified: %s, %v", err, category, known)
		}
	}
	if category, known := KnownVerificationFailureCategory(errors.New("untrusted restore error")); known || category != "" {
		t.Fatalf("untrusted restore error was classified: %s, %v", category, known)
	}
}
