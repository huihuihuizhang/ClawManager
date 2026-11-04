//go:build linux

package quiesce

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"clawreef/internal/services"
)

// Actual filesystem/fsync/HMAC/guard tests. No synthetic ledger is claimed to
// authenticate a production reservation, physical hold or SQL recovery fence.
func sharedOwnerStoreFixture(t *testing.T) (*sharedRuntimeNodeOwner, SharedRuntimeNodeRequest, sharedRuntimeOwnerRecord) {
	t.Helper()
	o := &sharedRuntimeNodeOwner{observer: &NodeObserver{key: bytes.Repeat([]byte{7}, 32), BootID: "fixture-boot"}, directory: t.TempDir()}
	r := SharedRuntimeNodeRequest{Version: SharedRuntimeNodeProtocol, Binding: ObservationBinding{OperationID: "original-task", ReservationID: strings.Repeat("a", 32)}, AgentPod: PodIdentity{Name: "agent", UID: "original-pod"}, Original: services.RuntimeSharedNativeState{OriginalSHA256: strings.Repeat("b", 64)}, SourcePaths: []string{"/owned-workspace"}}
	rec := sharedRuntimeOwnerRecord{Version: SharedRuntimeNodeProtocol, ID: sharedRuntimeOwnerID(r), Original: sharedRuntimeOwnerOriginal(r), Phase: "prepared", Cgroup: sharedCgroupPin{BootID: "fixture-boot"}}
	rec.Anchor = o.anchor(rec)
	return o, r, rec
}

func TestSharedOwnerDurableIntentSurvivesRestartAndRejectsForeignSource(t *testing.T) {
	o, r, rec := sharedOwnerStoreFixture(t)
	if err := o.save(&rec); err != nil {
		t.Fatal(err)
	}
	rec.Phase = "freezing"
	if err := o.save(&rec); err != nil {
		t.Fatal(err)
	}
	restarted := &sharedRuntimeNodeOwner{observer: o.observer, directory: o.directory}
	r.Anchor = rec.Anchor
	got, err := restarted.load(r)
	if err != nil || got.Phase != "freezing" || got.Sequence != 2 {
		t.Fatal("original persisted intent lost", err)
	}
	wrong := r
	wrong.Anchor = "different-anchor"
	if _, err = restarted.load(wrong); err == nil {
		t.Fatal("foreign anchor accepted")
	}
	wrong = r
	wrong.SourcePaths = []string{"/other-workspace"}
	if _, err = restarted.load(wrong); err == nil {
		t.Fatal("foreign source roots accepted")
	}
	wrong = r
	wrong.Binding.OperationID = "successor-task"
	if _, err = restarted.load(wrong); err == nil {
		t.Fatal("successor task borrowed original intent")
	}
}

func TestSharedOwnerTamperedDurablePhaseCannotBecomeRecoveryProof(t *testing.T) {
	o, r, rec := sharedOwnerStoreFixture(t)
	if err := o.save(&rec); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(o.directory, rec.ID+".json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(raw, []byte(`"Phase":"prepared"`), []byte(`"Phase":"completed"`), 1)
	if bytes.Equal(raw, changed) {
		t.Fatal("fixture did not change phase")
	}
	if err = os.WriteFile(p, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = o.load(r); err == nil {
		t.Fatal("tampered completion accepted")
	}
}

func TestSharedOwnerUncertainReplacementRetainsIntentWithoutCurrentProof(t *testing.T) {
	o, r, rec := sharedOwnerStoreFixture(t)
	// Force only current-pointer replacement to fail after its immutable event
	// was written. It must return failure and cannot load a completion record.
	if err := os.Mkdir(filepath.Join(o.directory, rec.ID+".json"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := o.save(&rec); err == nil {
		t.Fatal("uncertain current replacement claimed success")
	}
	if _, err := o.load(r); err == nil {
		t.Fatal("uncertain write manufactured an original record")
	}
	items, err := os.ReadDir(o.directory)
	if err != nil {
		t.Fatal(err)
	}
	event, pending := false, false
	for _, item := range items {
		event = event || strings.HasSuffix(item.Name(), ".event")
		pending = pending || strings.HasPrefix(item.Name(), ".pending-")
	}
	if !event || !pending {
		t.Fatal("uncertain original obligations erased")
	}
	if o.prepareWriteBoundary(context.Background()) == nil {
		t.Fatal("uncertain durable write admitted a new prepare")
	}
}

func TestSharedOwnerMissingCurrentEventBlocksNewPrepare(t *testing.T) {
	o, _, rec := sharedOwnerStoreFixture(t)
	if err := o.save(&rec); err != nil {
		t.Fatal(err)
	}
	if err := o.prepareWriteBoundary(context.Background()); err != nil {
		t.Fatal("current event rejected", err)
	}
	if err := os.Remove(filepath.Join(o.directory, rec.ID+".json")); err != nil {
		t.Fatal(err)
	}
	if o.prepareWriteBoundary(context.Background()) == nil {
		t.Fatal("immutable prepare event without current pointer erased")
	}
}

func TestSharedOwnerNativeGuardHasOneWriter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "owner")
	o := &NodeObserver{key: bytes.Repeat([]byte{9}, 32)}
	release := map[string]sharedRuntimeAgentRelease{"openclaw": {strings.Repeat("a", 64), "/var/lib/openclaw-agent"}}
	first, err := newSharedRuntimeNodeOwner(o, "/sys/fs/cgroup", dir, release)
	if err != nil {
		t.Fatal("private native owner rejected", err)
	}
	if second, err := newSharedRuntimeNodeOwner(o, "/sys/fs/cgroup", dir, release); err == nil {
		second.close()
		first.close()
		t.Fatal("two physical owners acquired native store")
	}
	first.close()
	next, err := newSharedRuntimeNodeOwner(o, "/sys/fs/cgroup", dir, release)
	if err != nil {
		t.Fatal("closed owner's guard never released", err)
	}
	next.close()
}
