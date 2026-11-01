package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

func newPublicationCatalogServiceFixture(t *testing.T) (*aPublisherVerifierFixture, *nativePublicationS3, *nativePublicationS3, *aNativePublicationServer, *aNativePublicationServer, PublicationCatalogMaterials) {
	t.Helper()
	parent, m, artifactState, catalogState := newPublicationCatalogTransportFixture(t)
	artifact, err := newNativePublicationS3(parent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(artifact.Close)
	x := newAPublisherVerifierFixtureOptions(t, aPublisherVerifierFixtureOptions{FullService: true, PublicationTarget: &artifact.config, PreparePublicationTarget: func(p *PublicationTargetMaterials) {
		// Complete installation coordinates BEFORE sealing the deployment core;
		// purpose identity/ref values already exist in the original snapshot.
		m.InstallationID = p.InstallationID
		m.Root = p.Root + "catalog/"
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p.CatalogMaterialsFile, raw, 0600); err != nil {
			t.Fatal(err)
		}
		p.CatalogMaterialsSHA256 = hash(raw)
	}})
	aStartPublisherVerifierSamePod(t, x)
	aUseActualPublicationDDL(t, x, artifact.config)
	catalog, err := x.history.service.catalogStore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(catalog.Close)
	return x, artifact, catalog, artifactState, catalogState, m
}

func TestPublicationArtifactPurposeSnapshotAndCurrentSQLMySQL(t *testing.T) {
	x, store, _ := newAOriginalPublicationService(t)
	h, ctx := x.history, context.Background()
	check := func(target PublicationTargetMaterials) error {
		access, err := h.service.publicationAccess(ctx, h.token, h.original.AttemptNo)
		if err != nil {
			return err
		}
		tx, err := h.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		guard, err := access.Bind(ctx, tx)
		if err != nil {
			return err
		}
		if err := h.service.checkPublicationTargetTx(ctx, tx, guard.Facts(), target); err != nil {
			return err
		}
		return guard.RecheckTx(ctx, tx)
	}
	if err := check(store.config); err != nil {
		t.Fatal("healthy original artifact refs", err)
	}
	var before []byte
	var sha string
	if err := h.admin.QueryRow("SELECT config_snapshot_json,config_snapshot_sha256 FROM system_backup_v2_backups WHERE public_id=?", h.original.TaskPublicID).Scan(&before, &sha); err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []string{"artifact_write", "artifact_read", "artifact_ca"} {
		t.Run(purpose, func(t *testing.T) {
			changed := store.config
			var version *string
			switch purpose {
			case "artifact_write":
				version = &changed.WriteRefVersion
			case "artifact_read":
				version = &changed.ReadRefVersion
			case "artifact_ca":
				version = &changed.CARefVersion
			}
			original := *version
			*version += "-drift"
			query := "UPDATE system_backup_v2_configs SET " + purpose + "_ref_version=? WHERE origin_installation_id=? AND version=?"
			if _, err := h.admin.Exec(query, *version, h.original.InstallationID, h.original.ConfigVersion); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := h.admin.Exec(query, original, h.original.InstallationID, h.original.ConfigVersion); err != nil {
					t.Error(err)
				}
			}()
			if err := check(changed); !errors.Is(err, c.ErrExecutionAuthority) {
				t.Fatal("fresh matching target adopted materialized drift", err)
			}
		})
	}
	var after []byte
	var afterSHA string
	if err := h.admin.QueryRow("SELECT config_snapshot_json,config_snapshot_sha256 FROM system_backup_v2_backups WHERE public_id=?", h.original.TaskPublicID).Scan(&after, &afterSHA); err != nil || !bytes.Equal(before, after) || sha != afterSHA {
		t.Fatal("ref drift changed admitted original snapshot", err)
	}
}

// Real current guard + original097/098 + independent local transport mapping.
// The body used in the read-only recovery case is named protocol JSON DATA,
// not a signed/accepted catalog record or a completed publication.
func TestPublicationCatalogPurposeSnapshotAndCurrentSQLMySQL(t *testing.T) {
	x, artifact, catalog, artifactState, catalogState, m := newPublicationCatalogServiceFixture(t)
	h := x.history
	ctx := context.Background()
	check := func(expected ...publicationConfigReference) error {
		access, err := h.service.publicationAccess(ctx, h.token, h.original.AttemptNo)
		if err != nil {
			return err
		}
		tx, err := h.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		guard, err := access.Bind(ctx, tx)
		if err != nil {
			return err
		}
		if expected == nil {
			if err := h.service.checkPublicationActionTargetTx(ctx, tx, guard.Facts(), catalog.config, "catalog_registration_append"); err != nil {
				return err
			}
		} else if err := checkOriginalPublicationReferencesTx(ctx, tx, guard.Facts(), expected...); err != nil {
			return err
		}
		return guard.RecheckTx(ctx, tx)
	}
	if err := check(); err != nil {
		t.Fatal("original catalog mapping not bound to original/current purpose refs", err)
	}
	var before []byte
	var beforeSHA string
	if err := h.admin.QueryRow(`SELECT config_snapshot_json,config_snapshot_sha256 FROM system_backup_v2_backups WHERE public_id=?`, h.original.TaskPublicID).Scan(&before, &beforeSHA); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []publicationConfigReference{{"catalog_read", m.ReadIdentityHash, m.ReadRefVersion}, {"catalog_append", m.AppendIdentityHash, m.AppendRefVersion}, {"artifact_ca", m.CAIdentityHash, m.CARefVersion}} {
		t.Run(ref.Purpose, func(t *testing.T) {
			changed := ref
			changed.Version += "-drift"
			query := "UPDATE system_backup_v2_configs SET " + ref.Purpose + "_ref_version=? WHERE origin_installation_id=? AND version=?"
			r, err := h.admin.Exec(query, changed.Version, h.original.InstallationID, h.original.ConfigVersion)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := r.RowsAffected(); err != nil || n != 1 {
				t.Fatal("owned single-ref drift", n, err)
			}
			// A matching changed DTO/current SQL still cannot become original refs.
			if err := check(changed); !errors.Is(err, c.ErrExecutionAuthority) {
				t.Fatal("fresh matching ref adopted changed SQL", err)
			}
			if _, err := h.admin.Exec(query, ref.Version, h.original.InstallationID, h.original.ConfigVersion); err != nil {
				t.Fatal(err)
			}
		})
	}
	var after []byte
	var afterSHA string
	if err := h.admin.QueryRow(`SELECT config_snapshot_json,config_snapshot_sha256 FROM system_backup_v2_backups WHERE public_id=?`, h.original.TaskPublicID).Scan(&after, &afterSHA); err != nil || !bytes.Equal(before, after) || beforeSHA != afterSHA {
		t.Fatal("fault changed admitted snapshot", err)
	}
	intent := publicationJSONIntent{Kind: "catalog_registration_append", Key: m.Root + "registration/original.json", Payload: []byte(`{"local":"catalog purpose protocol DATA"}`), Deadline: time.Now().Add(8 * time.Second)}
	if _, err := h.service.publishOriginalJSON(ctx, h.token, h.original.AttemptNo, artifact, intent); !errors.Is(err, ErrPublicationCatalogUnavailable) {
		t.Fatal("artifact write alias used for catalog", err)
	}
	if _, err := h.service.publishOriginalJSON(ctx, h.token, h.original.AttemptNo, catalog, intent); !errors.Is(err, ErrPublicationFinalizationRequired) {
		t.Fatal("mapping alone authorized a new acceptance/catalog action", err)
	}
	if artifactState.puts != 0 || catalogState.puts != 0 {
		t.Fatal("unverified new catalog bytes were sent")
	}
}

func TestPublicationCatalogUnknownUsesDedicatedReadOnlyRecoveryMySQL(t *testing.T) {
	x, _, catalog, artifactState, catalogState, m := newPublicationCatalogServiceFixture(t)
	h := x.history
	ctx := context.Background()
	intent := publicationJSONIntent{Kind: "catalog_registration_append", Key: m.Root + "registration/original.json", Payload: []byte(`{"local":"already-sent original catalog protocol DATA"}`), Deadline: time.Now().Add(10 * time.Second).UTC().Truncate(time.Microsecond)}
	if _, err := catalog.createJSON(ctx, intent.Key, bytes.NewReader(intent.Payload), int64(len(intent.Payload)), hash(intent.Payload), intent.Deadline); err != nil {
		t.Fatal(err)
	}
	// Exact named original request_sent SQL DATA, never a send grant or a
	// substitute new task. Recovery must only read that existing object.
	id := "sxa_11111111-1111-4111-8111-111111111111"
	if _, err := h.admin.Exec(`INSERT INTO system_backup_v2_external_actions(public_id,origin_installation_id,target_type,target_public_id,action_type,logical_action_hash,action_key,canonical_payload_bytes,payload_sha256,content_length,final_key,dispatch_generation,dispatch_deadline,state,send_attempt_count) VALUES(?,?,'backup',?,?,?,?,?,?,?,?,1,?,'request_sent',1)`, id, h.original.InstallationID, h.original.TaskPublicID, intent.Kind, publicationLogicalHash(h.original.InstallationID, h.original.TaskPublicID, h.original.AttemptNo, intent), publicationActionKey(h.original.TaskPublicID, h.original.AttemptNo, intent.Kind), intent.Payload, hash(intent.Payload), len(intent.Payload), intent.Key, intent.Deadline.UTC().Truncate(time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Exec(`UPDATE system_backup_v2_backups SET status='publishing',commit_started_at=UTC_TIMESTAMP(6),can_cancel=FALSE,finalization_action_public_id=? WHERE public_id=?`, id, h.original.TaskPublicID); err != nil {
		t.Fatal(err)
	}
	if _, err := (c.ClaimCoordinator{Executor: h.db, InstallationID: h.original.InstallationID}).Release(ctx, h.token, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Exec(`UPDATE system_backup_v2_backups SET next_reconcile_at=NULL WHERE public_id=?`, h.original.TaskPublicID); err != nil {
		t.Fatal(err)
	}
	if err := h.service.RunPublicationPass(ctx); err != nil {
		t.Fatal("dedicated catalog query-only recovery", err)
	}
	var state, status string
	var usable bool
	if h.db.QueryRow(`SELECT state FROM system_backup_v2_external_actions WHERE public_id=?`, id).Scan(&state) != nil || state != "confirmed_present" || h.db.QueryRow(`SELECT status,artifact_usable FROM system_backup_v2_backups WHERE public_id=?`, h.original.TaskPublicID).Scan(&status, &usable) != nil || status != "publishing" || usable || catalogState.puts != 1 || catalogState.gets != 1 || artifactState.puts != 0 || artifactState.gets != 0 {
		t.Fatal("catalog recovery replayed or promoted presence to success", state, status, usable, catalogState.puts, catalogState.gets, artifactState.puts)
	}
}
