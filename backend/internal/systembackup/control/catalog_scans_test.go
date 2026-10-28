package control

import (
	"context"
	"database/sql/driver"
	"testing"

	"clawreef/internal/systembackup/recovery"
)

func emptyCatalogScan() (recovery.ScanState, recovery.ScanState, recovery.ScanPage) {
	hash := recovery.Hash([]byte("clawmanager/catalog-inventory/v1"))
	before := recovery.ScanState{Snapshot: recovery.Snapshot{ID: "snapshot", Mode: "inventory_manifest", Root: recovery.Reference{ID: "root", Version: "v1", SHA256: hash}, RecordsSHA256: hash, ExpiresAt: 9999999999999}}
	p := recovery.Page{SnapshotID: "snapshot", Objects: []recovery.Object{}}
	raw, _ := recovery.Marshal([]any{"catalog-page.v1", "", p})
	receipt := recovery.ScanPage{Page: p, SHA256: recovery.Hash(raw)}
	after := before
	after.Page = 1
	after.RollingSHA256 = hash
	after.PageSHA256 = receipt.SHA256
	return before, after, receipt
}

func TestCatalogScanPageAndCursorCommitAtomicallyAcrossLostReply(t *testing.T) {
	task, _ := catalogTask()
	before, after, page := emptyCatalogScan()
	b, _ := recovery.Marshal(before)
	a, _ := recovery.Marshal(after)
	steps := append(workerCommit(task), sqlStep{contains: "SELECT state_json", rows: [][]driver.Value{{b}}}, sqlStep{contains: "INSERT INTO system_backup_catalog_pages", affected: 1}, sqlStep{contains: "UPDATE system_backup_catalog_scans", affected: 1})
	store, script := scriptStore(t, steps...)
	script.loseCommit = true
	j := CatalogScans{Store: store, Task: task}
	if e := j.CommitPage(context.Background(), "scan", before, after, page, nil); e == nil {
		t.Fatal("uncertain commit reported success")
	}
	script.steps = append(workerCommit(task), sqlStep{contains: "SELECT state_json", rows: [][]driver.Value{{a}}})
	if e := j.CommitPage(context.Background(), "scan", before, after, page, nil); e != nil || script.writes != 2 {
		t.Fatal("retry duplicated committed page", e)
	}
}

func TestCatalogScanFinishRequiresDurablePageChain(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "missing-page"}[missing], func(t *testing.T) {
			task, _ := catalogTask()
			_, after, page := emptyCatalogScan()
			a, _ := recovery.Marshal(after)
			p, _ := recovery.Marshal(page)
			pages := [][]driver.Value{{p}}
			if missing {
				pages = nil
			}
			steps := append(workerCommit(task), sqlStep{contains: "SELECT state_json", rows: [][]driver.Value{{a}}}, sqlStep{contains: "SELECT record_json"}, sqlStep{contains: "SELECT page_json", rows: pages})
			if !missing {
				steps = append(steps, sqlStep{contains: "UPDATE system_backup_catalog_scans", affected: 1})
			}
			store, script := scriptStore(t, steps...)
			e := (CatalogScans{Store: store, Task: task}).Finish(context.Background(), "scan", after)
			if missing && (e == nil || script.writes != 0) || !missing && (e != nil || script.commits != 1) {
				t.Fatal("scan chain verification", e)
			}
		})
	}
}
