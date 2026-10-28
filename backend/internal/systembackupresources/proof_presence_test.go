package systembackupresources

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"
)

type resourcesProofCallsKey struct{}

func recordResourcesProofCall(ctx context.Context) error {
	*ctx.Value(resourcesProofCallsKey{}).(*int)++
	return nil
}

// A missing adapter can have nil-safe methods that report success. Reject it
// before invoking those methods; relying on its own nil dereference is unsafe.
type resourcesProofPointer struct{}
type resourcesProofFunction func()
type resourcesProofMap map[string]int
type resourcesProofSlice []int
type resourcesProofChannel chan struct{}

func (*resourcesProofPointer) VerifyCapture(ctx context.Context, _, _ CaptureSnapshotEvidence) error {
	return recordResourcesProofCall(ctx)
}
func (*resourcesProofPointer) VerifyReadOnlyTarget(ctx context.Context, _ *sql.Tx) error {
	return recordResourcesProofCall(ctx)
}
func (resourcesProofFunction) VerifyCapture(ctx context.Context, _, _ CaptureSnapshotEvidence) error {
	return recordResourcesProofCall(ctx)
}
func (resourcesProofFunction) VerifyReadOnlyTarget(ctx context.Context, _ *sql.Tx) error {
	return recordResourcesProofCall(ctx)
}
func (resourcesProofMap) VerifyCapture(ctx context.Context, _, _ CaptureSnapshotEvidence) error {
	return recordResourcesProofCall(ctx)
}
func (resourcesProofMap) VerifyReadOnlyTarget(ctx context.Context, _ *sql.Tx) error {
	return recordResourcesProofCall(ctx)
}
func (resourcesProofSlice) VerifyCapture(ctx context.Context, _, _ CaptureSnapshotEvidence) error {
	return recordResourcesProofCall(ctx)
}
func (resourcesProofSlice) VerifyReadOnlyTarget(ctx context.Context, _ *sql.Tx) error {
	return recordResourcesProofCall(ctx)
}
func (resourcesProofChannel) VerifyCapture(ctx context.Context, _, _ CaptureSnapshotEvidence) error {
	return recordResourcesProofCall(ctx)
}
func (resourcesProofChannel) VerifyReadOnlyTarget(ctx context.Context, _ *sql.Tx) error {
	return recordResourcesProofCall(ctx)
}

type resourcesDualProof interface {
	CaptureProofVerifier
	TargetReadProofVerifier
}

func resourcesProofPresenceCases() []struct {
	name    string
	proof   resourcesDualProof
	missing bool
} {
	return []struct {
		name    string
		proof   resourcesDualProof
		missing bool
	}{
		{"interface_nil", nil, true},
		{"pointer_nil", (*resourcesProofPointer)(nil), true},
		{"function_nil", resourcesProofFunction(nil), true},
		{"map_nil", resourcesProofMap(nil), true},
		{"slice_nil", resourcesProofSlice(nil), true},
		{"channel_nil", resourcesProofChannel(nil), true},
		{"pointer_present", &resourcesProofPointer{}, false},
		{"function_present", resourcesProofFunction(func() {}), false},
		{"map_empty_present", resourcesProofMap{}, false},
		{"slice_empty_present", resourcesProofSlice{}, false},
		{"channel_present", make(resourcesProofChannel), false},
	}
}

func TestResourcesCaptureProofPresence(t *testing.T) {
	for _, tc := range resourcesProofPresenceCases() {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			ctx := context.WithValue(context.Background(), resourcesProofCallsKey{}, &calls)
			checks, err := VerifyBackupSnapshot(ctx, frozenRegistryBytes(t), verifierEvidence(), verifierEvidence(), tc.proof)
			if tc.missing {
				if err == nil || !strings.Contains(err.Error(), "proof verifier is required") || checks != nil || calls != 0 {
					t.Fatalf("missing capture proof invoked or accepted: calls=%d checks=%d err=%v", calls, len(checks), err)
				}
				return
			}
			if err != nil || calls != 1 {
				t.Fatalf("present proof rejected or repeated: calls=%d err=%v", calls, err)
			}
			assertResourceChecksPassed(t, checks)
		})
	}
}

func TestResourcesTargetProofPresence(t *testing.T) {
	for _, tc := range resourcesProofPresenceCases() {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			ctx := context.WithValue(context.Background(), resourcesProofCallsKey{}, &calls)
			state := controlFixture()
			verifier := SQLControlExclusionVerifier{DB: countDatabase(t, state), Proof: tc.proof}
			checks, err := verifier.VerifyRestoreTarget(ctx, frozenRegistryBytes(t), "sev_proof_presence_fixture")
			if tc.missing {
				if err == nil || !strings.Contains(err.Error(), "requires evidence, target proof and database") || checks != nil || calls != 0 || len(state.queries) != 0 || state.begin != (driver.TxOptions{}) || state.commits != 0 || state.rollbacks != 0 {
					t.Fatalf("missing target proof invoked or reached SQL: calls=%d queries=%d checks=%d err=%v", calls, len(state.queries), len(checks), err)
				}
				return
			}
			if err != nil || calls != 1 || len(checks) != 35 || len(state.queries) != 70 || state.commits != 1 || state.rollbacks != 0 || !state.begin.ReadOnly || state.begin.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
				t.Fatalf("present target proof changed the snapshot: calls=%d queries=%d checks=%d err=%v", calls, len(state.queries), len(checks), err)
			}
			for _, check := range checks {
				if check.Status != "passed" {
					t.Fatal("empty target control check changed", check)
				}
			}
		})
	}
}
