package systembackupexecution

import (
	"context"
	"testing"
	"time"
)

func TestAPublicationOriginalConflictFailsSameTaskWithActualDDL(t *testing.T) {
	x, store, state := newAOriginalPublicationService(t)
	h := x.history
	ctx := context.Background()
	access, err := h.service.publicationAccess(ctx, h.token, h.original.AttemptNo)
	if err != nil {
		t.Fatal(err)
	}
	key := store.config.Root + h.original.TaskPublicID + "/3/manifest.json"
	state.objects["/"+store.config.Bucket+"/"+key] = []byte(`{"foreign":"body"}`)
	intent := publicationJSONIntent{Kind: "manifest_put", Key: key, Payload: []byte(`{"original":"manifest"}`), Deadline: access.ValidUntil().Add(-time.Second)}
	object, err := h.service.publishOriginalJSON(ctx, h.token, h.original.AttemptNo, store, intent)
	if err != errPublicationConflict || object.Version != "" || object.receipt != nil || state.puts != 1 {
		t.Fatal("actual immutable conflict accepted", err)
	}
	var status, category, attention, stateSQL string
	var finished, canCancel, owned bool
	if h.db.QueryRow("SELECT status,failure_category,attention_reason,finished_at IS NOT NULL,can_cancel,controller_owner IS NOT NULL FROM system_backup_v2_backups WHERE public_id=?", h.original.TaskPublicID).Scan(&status, &category, &attention, &finished, &canCancel, &owned) != nil || status != "failed" || category != "artifact_conflict" || attention != "none" || !finished || canCancel || owned {
		t.Fatal("original task conflict terminal invalid")
	}
	if h.db.QueryRow("SELECT state FROM system_backup_v2_external_actions WHERE target_public_id=?", h.original.TaskPublicID).Scan(&stateSQL) != nil || stateSQL != "conflict" {
		t.Fatal("original conflict receipt missing")
	}
}

func TestAPublicationConsumerReceiptBindsExactOriginalAction(t *testing.T) {
	x, store, _ := newAOriginalPublicationService(t)
	h := x.history
	ctx := context.Background()
	access, err := h.service.publicationAccess(ctx, h.token, h.original.AttemptNo)
	if err != nil {
		t.Fatal(err)
	}
	intent := publicationJSONIntent{Kind: "manifest_put", Key: store.config.Root + h.original.TaskPublicID + "/3/manifest.json", Payload: []byte(`{"original":"manifest"}`), Deadline: access.ValidUntil().Add(-time.Second)}
	object, err := h.service.publishOriginalJSON(ctx, h.token, h.original.AttemptNo, store, intent)
	if err != nil || object.receipt == nil {
		t.Fatal(err)
	}
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = object.recheckPublicationReceiptTx(ctx, tx, h.token); err != nil {
		tx.Rollback()
		t.Fatal("actual original receipt", err)
	}
	changed := object
	changed.Version = "substitute"
	if changed.recheckPublicationReceiptTx(ctx, tx, h.token) == nil {
		tx.Rollback()
		t.Fatal("object DTO mutation manufactured authority")
	}
	tx.Rollback()
	if _, err = h.admin.Exec("UPDATE system_backup_v2_external_actions SET row_version=row_version+1 WHERE target_public_id=?", h.original.TaskPublicID); err != nil {
		t.Fatal(err)
	}
	tx, err = h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if object.recheckPublicationReceiptTx(ctx, tx, h.token) == nil {
		t.Fatal("consumer accepted changed original action version")
	}
}
