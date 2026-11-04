package systembackupcontroller

import (
	"context"
	"strings"
	"testing"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	q "clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
)

func TestSharedTaskWireOperationBelongsToWholePodOriginalAttemptAndInventory(t *testing.T) {
	a := d.Authority{InstallationID: "installation", TaskPublicID: "actual-public-task", AttemptNo: 1}
	inventory := strings.Repeat("a", 64)
	op := runtimeSharedOperation(a, "actual-pod-uid", inventory)
	if len(op) != 32 || op != runtimeSharedOperation(a, "actual-pod-uid", inventory) {
		t.Fatal("same whole-Pod original operation changed")
	}
	changed := a
	changed.AttemptNo++
	for _, other := range []string{runtimeSharedOperation(changed, "actual-pod-uid", inventory), runtimeSharedOperation(a, "other-pod", inventory), runtimeSharedOperation(a, "actual-pod-uid", strings.Repeat("b", 64))} {
		if other == op {
			t.Fatal("another original cohort/attempt reused operation")
		}
	}
}

func TestSharedTaskDataOrZeroOpaqueObjectCannotPassNativeHeldBoundary(t *testing.T) {
	for _, frame := range []*runtimeSharedHeldFrame{nil, {}, {book: runtimeSharedBook{Actors: []runtimeSharedActor{{}}}}, {book: runtimeSharedBook{Actors: []runtimeSharedActor{{}}}, proofs: []*q.VerifiedSharedRuntimeNodeObservation{{}}}} {
		if frame.recheck(context.Background(), time.Now()) == nil {
			t.Fatal("unobserved native state passed held boundary")
		}
	}
}

func TestSharedTaskCustodyIDsPreserveOriginalRegistryAndExplicitUnboundRows(t *testing.T) {
	spec := b.RuntimeWriterSpec{UID: "actual-pod", Source: b.InstanceIdentity{ID: 12, Status: "running"}}
	if sharedRuntimeWriterID(spec) != "gateway/actual-pod/12" {
		t.Fatal("existing physical participant ID lost")
	}
	spec.Source.Status = "stopped"
	if sharedRuntimeWriterID(spec) != "stopped/12" {
		t.Fatal("original stopped registry identity lost")
	}
	spec.Source.Status = "error"
	spec.UID = "unbound"
	if sharedRuntimeWriterID(spec) != "shared-source/12" {
		t.Fatal("unbound error silently omitted or impersonated a gateway")
	}
}
