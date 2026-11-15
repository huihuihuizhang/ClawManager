//go:build linux

package quiesce

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// Persistence only: synthetic mount fields are not a native NFS or hold proof.
func TestSharedRuntimeLonghornOriginalMountReferenceSurvivesJournalReopen(t *testing.T) {
	o, _, _ := sharedOwnerStoreFixture(t)
	r := sharedLonghornRequestFixture(t)
	w := &sharedRuntimeLonghornWitness{Coordinates: *r.LonghornClient, MountID: "fixture-mount", RootInode: 42}
	rec := sharedRuntimeOwnerRecord{Version: SharedRuntimeNodeProtocol, ID: sharedRuntimeOwnerID(r), Original: sharedRuntimeOwnerOriginal(r), Witness: sharedRuntimeNativeWitness{Longhorn: w}, Phase: "prepared", Cgroup: sharedCgroupPin{BootID: o.observer.BootID}, Tasks: 1}
	rec.Anchor = o.anchor(rec)
	if err := o.save(&rec); err != nil {
		t.Fatal(err)
	}
	r.Anchor = rec.Anchor
	reopened := &sharedRuntimeNodeOwner{observer: o.observer, directory: o.directory}
	got, err := reopened.load(r)
	if err != nil || !reflect.DeepEqual(got.Witness.Longhorn, w) || got.Files != 0 {
		t.Fatal("original CSI reference lost across authenticated journal reopen", err)
	}
	client := *r.LonghornClient
	client.PVUID = "replacement-pv"
	r.LonghornClient = &client
	if _, err := reopened.load(r); err == nil {
		t.Fatal("replacement volume adopted original recovery journal")
	}
}

func TestSharedRuntimeLonghornNativeRejectsUninstalledOrChangedClientBeforeMountIO(t *testing.T) {
	r := sharedLonghornRequestFixture(t)
	o := &NodeObserver{}
	if _, err := o.sharedRuntimeLonghornMount(context.Background(), r, nil); err == nil || !strings.Contains(err.Error(), "shared_longhorn_installed_client_required") {
		t.Fatal("uninstalled source reached native mount IO", err)
	}
	o.longhornClientTemplates = map[string]LonghornRWXClientCoordinates{r.LonghornClient.Identity: sharedRuntimeLonghornTemplate(*r.LonghornClient)}
	r.LonghornClient.PVCUID = "replacement-pvc"
	if _, err := o.sharedRuntimeLonghornMount(context.Background(), r, nil); err == nil || !strings.Contains(err.Error(), "shared_longhorn_installed_client_required") {
		t.Fatal("changed installed source reached native mount IO", err)
	}
	if _, err := o.sharedRuntimeLonghornMount(context.Background(), r, &sharedRuntimeNativeWitness{}); err == nil || !strings.Contains(err.Error(), "shared_longhorn_original_client_required") {
		t.Fatal("missing original witness was promoted to recovery source", err)
	}
}
