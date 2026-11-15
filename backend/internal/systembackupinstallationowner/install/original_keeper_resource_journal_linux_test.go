//go:build linux

package install

import (
	"context"
	"os"
	"strings"
	"testing"

	"clawreef/internal/systembackup/kube"
)

func TestOriginalKeeperJournalRetainsUnknownCreateAndRejectsStaleCAS(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	op := strings.Repeat("a", 32)
	j := &originalWriterJournal{root: root, directory: dir, directoryIdentity: info, operation: op, inventory: strings.Repeat("b", 64)}
	id := kube.Identity{Namespace: "tenant", Name: "keeper", Owner: "adoption-" + op}
	allowed := true
	check := func(context.Context) error {
		if !allowed {
			return ErrInstall
		}
		return nil
	}
	a := &originalKeeperResourceJournal{journal: j, identity: id, check: check}
	b := &originalKeeperResourceJournal{journal: j, identity: id, check: check}
	ctx := context.Background()
	// The real factory persists its prepared set before creating a keeper.
	if err := j.append(ctx, "", "prepared_original_complete_set", nil, struct{}{}); err != nil {
		t.Fatal(err)
	}
	intent := kube.ResourceIntent{Identity: id, Kind: kube.LonghornKeeperResource, RequestSHA256: strings.Repeat("c", 64), RequestJSON: []byte(`{"kind":"Job"}`)}
	r, err := a.Prepare(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	old := r
	r, err = a.RecordCreate(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.RecordCreate(ctx, old); err == nil {
		t.Fatal("stale CAS accepted")
	}
	if err := b.RecordAbsent(ctx, r); err == nil {
		t.Fatal("unknown create marked absent")
	}
	r, err = b.Observe(ctx, r, "actual-uid", "1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Observe(ctx, r, "replacement-uid", "2"); err == nil {
		t.Fatal("replacement adopted")
	}
	r, err = a.RecordDelete(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.RecordAbsent(ctx, r); err != nil {
		t.Fatal(err)
	}
	retained, err := a.Prepare(ctx, intent)
	if err != nil || !retained.Deleted || retained.UID != "actual-uid" {
		t.Fatal("lost terminal resource", err)
	}
	allowed = false
	if _, err := b.Prepare(ctx, intent); err == nil {
		t.Fatal("journal substituted for authority")
	}
}
