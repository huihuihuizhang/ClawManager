package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
)

// Native current guard and actual097/098 config/task rows. Explicit owned
// fixture DATA, no full backup or production admission claim. The complete
// config JSON is fixed BEFORE capture/authority creation, never hand-replaced
// in an admitted task to mint a new hash/window.
func TestPublicationInitialCapacityCannotAdoptMaterializedDriftMySQL(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "admin-control-redacted-examples.json"))
	if err != nil {
		t.Fatal(err)
	}
	var example struct {
		Request struct {
			Config map[string]json.RawMessage `json:"config"`
		} `json:"config_update_request"`
	}
	if json.Unmarshal(raw, &example) != nil || len(example.Request.Config) == 0 {
		t.Fatal("original config example unavailable")
	}
	config := example.Request.Config
	var capacity map[string]json.RawMessage
	if json.Unmarshal(config["capacity"], &capacity) != nil {
		t.Fatal("original capacity map unavailable")
	}
	capacity["control_metadata_capacity_bytes"] = json.RawMessage(strconv.FormatInt(1<<30, 10))
	config["enabled"] = json.RawMessage("true")
	capacityRaw, err := ce.Canonical(capacity)
	if err != nil {
		t.Fatal(err)
	}
	config["capacity"] = capacityRaw
	snapshot, err := ce.Canonical(config)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := newANativePublicationStore(t, time.Minute)
	x := newAPublisherVerifierFixtureOptions(t, aPublisherVerifierFixtureOptions{FullService: true, PublicationTarget: &store.config, ConfigSnapshot: snapshot})
	aStartPublisherVerifierSamePod(t, x)
	aUseActualPublicationDDL(t, x, store.config)
	h := x.history
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var taskJSON []byte
	var taskSHA string
	var original int64
	if err := h.admin.QueryRowContext(ctx, `SELECT b.config_snapshot_json,b.config_snapshot_sha256,c.max_artifact_bytes FROM system_backup_v2_backups b JOIN system_backup_v2_configs c ON c.origin_installation_id=b.origin_installation_id AND c.version=b.config_version WHERE b.public_id=?`, h.original.TaskPublicID).Scan(&taskJSON, &taskSHA, &original); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshot, taskJSON) || taskSHA != hash(snapshot) || original != 16<<30 {
		t.Fatal("original snapshot/SQL budget precondition changed", original)
	}
	check := func() (ArtifactReadLimits, error) {
		access, err := h.service.publicationAccess(ctx, h.token, h.original.AttemptNo)
		if err != nil {
			return ArtifactReadLimits{}, err
		}
		tx, err := h.db.BeginTx(ctx, nil)
		if err != nil {
			return ArtifactReadLimits{}, err
		}
		defer tx.Rollback()
		guard, err := access.Bind(ctx, tx)
		if err != nil {
			return ArtifactReadLimits{}, err
		}
		return readPublicationLimitsTx(ctx, tx, guard)
	}
	first, err := check()
	if err != nil || first.MaxArtifactBytes != original {
		t.Fatal("healthy original budget rejected", first, err)
	}
	// Stay inside the original097 staging relationship CHECK: widening to32GiB
	// correctly exceeded the unchanged20GiB staging budget in the first probe.
	// This smaller legal drift leaves every protection and other column intact.
	result, err := h.admin.ExecContext(ctx, `UPDATE system_backup_v2_configs SET max_artifact_bytes=? WHERE origin_installation_id=? AND version=?`, original+(1<<30), h.original.InstallationID, h.original.ConfigVersion)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		t.Fatal("owned budget fault not applied", count, err)
	}
	got, err := check()
	var after []byte
	var afterSHA string
	if e := h.admin.QueryRowContext(ctx, `SELECT config_snapshot_json,config_snapshot_sha256 FROM system_backup_v2_backups WHERE public_id=?`, h.original.TaskPublicID).Scan(&after, &afterSHA); e != nil || !bytes.Equal(after, taskJSON) || afterSHA != taskSHA {
		t.Fatal("fault changed original task snapshot", e)
	}
	if err == nil {
		t.Fatalf("new scope adopted materialized budget drift before binding: original=%d adopted=%d; original JSON/SHA unchanged", original, got.MaxArtifactBytes)
	}
}
