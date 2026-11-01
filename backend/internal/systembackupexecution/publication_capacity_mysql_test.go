package systembackupexecution

import (
	"context"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

func TestPublicationCapacityUsesCurrentOriginalConfigMySQL(t *testing.T) {
	x, store, _ := newAOriginalPublicationService(t)
	h := x.history
	ctx := context.Background()
	intent := publicationJSONIntent{Kind: "manifest_put", Key: store.config.Root + h.original.TaskPublicID + "/capacity/manifest.json", Payload: []byte(`{"local":"config capacity protocol DATA"}`), Deadline: time.Now().Add(8 * time.Second)}
	if _, err := h.service.publishOriginalJSON(ctx, h.token, h.original.AttemptNo, store, intent); err != nil {
		t.Fatal(err)
	}
	if _, err := (c.ClaimCoordinator{Executor: h.db, InstallationID: h.original.InstallationID}).Release(ctx, h.token, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Exec(`UPDATE system_backup_v2_backups SET next_reconcile_at=NULL WHERE public_id=?`, h.original.TaskPublicID); err != nil {
		t.Fatal(err)
	}
	p, err := h.service.preparePublicationContinuation(ctx, store)
	if err != nil || p == nil {
		t.Fatal(err)
	}
	defer p.close()
	var actual ArtifactReadLimits
	if err := h.admin.QueryRow(`SELECT max_artifact_bytes,max_index_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=?`, h.original.InstallationID, h.original.ConfigVersion).Scan(&actual.MaxArtifactBytes, &actual.MaxIndexBytes); err != nil {
		t.Fatal(err)
	}
	if p.limits != actual || actual.validate() != nil {
		t.Fatal("continuation did not use actual original config budget", p.limits, actual)
	}
	bounded, err := store.withObjectLimit(p.limits.MaxArtifactBytes)
	if err != nil || bounded.maxObjectBytes != actual.MaxArtifactBytes {
		t.Fatal("native transport was not tightened to original config", err)
	}
	reader, err := NewArtifactReadOnlyS3(artifactReadMaterials(store.config), p.limits)
	if err != nil {
		t.Fatal(err)
	}
	reader.Close()
	// Same admitted config row, committed materialized-budget mutation DATA.
	// This must not be silently adopted by an already issued current scope.
	changed := actual.MaxArtifactBytes - MinPublicationBudgetBytes
	if changed < MinPublicationBudgetBytes {
		changed = actual.MaxArtifactBytes + MinPublicationBudgetBytes
	}
	r, err := h.admin.Exec(`UPDATE system_backup_v2_configs SET max_artifact_bytes=? WHERE origin_installation_id=? AND version=?`, changed, h.original.InstallationID, h.original.ConfigVersion)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := r.RowsAffected(); err != nil || n != 1 {
		t.Fatal("owned config fault not applied", n, err)
	}
	defer h.admin.Exec(`UPDATE system_backup_v2_configs SET max_artifact_bytes=? WHERE origin_installation_id=? AND version=?`, actual.MaxArtifactBytes, h.original.InstallationID, h.original.ConfigVersion)
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := p.recheckTx(ctx, tx); err == nil {
		t.Fatal("original scope silently adopted a changed actual config budget")
	}
}
