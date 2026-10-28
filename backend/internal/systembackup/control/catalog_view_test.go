package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql/driver"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"clawreef/internal/systembackup/recovery"
)

func scannedFixture(t *testing.T, backup string) recovery.ScannedRecord {
	t.Helper()
	_, p, _, _ := sixPlanFixture(t)
	id := p.Input.Manifest.Identity
	id.Backup = backup
	obj := func(key string) recovery.Object {
		return recovery.Object{Key: key, Version: "v1", Size: 2, SHA256: recovery.Hash([]byte(`{}`))}
	}
	r := recovery.Record{Schema: recovery.Version, ID: recovery.RegistrationID(id), Type: "artifact_registered", Registration: &recovery.Registration{Identity: id, Matrix: "k8s-cluster", Locator: recovery.Locator{Provider: "s3", Bucket: "canary-private", Prefix: "canary-private/" + id.Origin + "/" + backup + "/1", FailureDomain: "fixture"}, Core: recovery.Core{Manifest: obj("manifest.json"), Index: obj("artifact-index.json"), Marker: obj("_COMMITTED"), Acceptance: obj("_ACCEPTANCE")}, Bootstrap: p.Input.Bootstrap, AcceptanceKey: p.ManifestKey, DecisionTime: 500}}
	k, e := r.Key()
	if e != nil {
		t.Fatal(e)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	trust := recovery.Trust{{ID: "catalog", Version: "v1", Purpose: recovery.CatalogPurpose, Public: private.Public().(ed25519.PublicKey)}}
	signed, e := recovery.Seal(r, recovery.CatalogPurpose, "catalog", "v1", private, trust)
	if e != nil {
		t.Fatal(e)
	}
	return recovery.ScannedRecord{Key: k, Object: recovery.Object{Key: k, Version: "fixed", Size: int64(len(signed)), SHA256: recovery.Hash(signed)}, Record: r, Signed: signed}
}
func viewStep(complete bool) sqlStep {
	b, _ := recovery.Marshal(recovery.ScanState{Snapshot: recovery.Snapshot{ID: "snapshot", Count: 2}, Count: 2, Complete: complete})
	return sqlStep{contains: "SELECT state_json", rows: [][]driver.Value{{b}}}
}
func TestCatalogPaginationPinsSnapshotAndRedactsProviderData(t *testing.T) {
	records := []recovery.ScannedRecord{scannedFixture(t, "backup-a"), scannedFixture(t, "backup-b")}
	sort.Slice(records, func(i, j int) bool {
		return recovery.Hash([]byte(records[i].Key)) < recovery.Hash([]byte(records[j].Key))
	})
	rows := [][]driver.Value{}
	for _, r := range records {
		b, _ := recovery.Marshal(r)
		rows = append(rows, []driver.Value{recovery.Hash([]byte(r.Key)), b})
	}
	s, script := scriptStore(t, viewStep(true), sqlStep{contains: "key_hash>?", rows: rows}, viewStep(true), sqlStep{contains: "key_hash>?", rows: rows[1:]}, viewStep(true))
	a, e := s.CatalogPage(context.Background(), "sb-scan", "", 1)
	if e != nil || len(a.Items) != 1 || a.Next == "" {
		t.Fatal(a, e)
	}
	b, e := s.CatalogPage(context.Background(), "sb-scan", a.Next, 1)
	if e != nil || len(b.Items) != 1 || b.Items[0].ID == a.Items[0].ID || b.Next != "" {
		t.Fatal(b, e)
	}
	if _, e = s.CatalogPage(context.Background(), "sb-other", a.Next, 1); e == nil {
		t.Fatal("cursor escaped its scan")
	}
	raw, _ := json.Marshal(a)
	if strings.Contains(string(raw), "canary-private") || strings.Contains(string(raw), "bootstrap") || script.writes != 0 {
		t.Fatal("view leaked data or wrote")
	}
}
func TestCatalogViewRejectsIncompleteScanAndCorruptRecord(t *testing.T) {
	s, _ := scriptStore(t, viewStep(false))
	if _, e := s.CatalogPage(context.Background(), "sb-scan", "", 50); e == nil {
		t.Fatal("partial snapshot exposed")
	}
	r := scannedFixture(t, "backup-a")
	r.Signed[0] ^= 1
	b, _ := recovery.Marshal(r)
	if _, e := projectRecord(b); e == nil {
		t.Fatal("corrupt record")
	}
}
func TestCatalogDetailTombstoneAndReportRemainReadOnly(t *testing.T) {
	r := scannedFixture(t, "backup-a")
	registered := r.Record.Registration
	r.Record = recovery.Record{Schema: recovery.Version, ID: "sbd_" + r.Record.ID[4:], Type: "artifact_deleted", Deletion: &recovery.Deletion{RegistrationID: r.Record.ID, RegistrationSHA256: r.Object.SHA256, Locator: registered.Locator, Core: registered.Core, PruneRun: "prune-1", CandidateSHA256: r.Object.SHA256, DeletedAt: 700, FirstActor: "operator-1"}}
	r.Key, _ = r.Record.Key()
	r.Signed, _ = recovery.Marshal(recovery.Envelope{Payload: func() []byte { b, _ := recovery.Marshal(r.Record); return b }()})
	r.Object = recovery.Object{Key: r.Key, Version: "v2", Size: int64(len(r.Signed)), SHA256: recovery.Hash(r.Signed)}
	raw, _ := recovery.Marshal(r)
	task := testTask()
	task.Request.Kind = "catalog_import"
	task.Request.Artifact = registeredID(registered)
	task.Request.RecordSHA256 = strings.Repeat("a", 64)
	task.Status = "succeeded"
	s, script := scriptStore(t, viewStep(true), sqlStep{contains: "object_key=?", rows: [][]driver.Value{{raw}}}, sqlStep{contains: "FROM system_backup_tasks", rows: [][]driver.Value{taskRow(task)}})
	item, e := s.CatalogDetail(context.Background(), "sb-scan", r.Record.ID, r.Record.Type)
	if e != nil || item.DeletedAt != 700 {
		t.Fatal(item, e)
	}
	report, e := s.Report(context.Background(), task.ID)
	if e != nil || !report.Verified || report.RestoreAuthorized || script.writes != 0 {
		t.Fatal(report, e)
	}
}
func registeredID(r *recovery.Registration) string { return recovery.RegistrationID(r.Identity) }
