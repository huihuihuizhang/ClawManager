//go:build systembackup_mysql

package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	reg "clawreef/internal/systembackupkekregistry"
	read "clawreef/internal/systembackupread"
)

// Actual original HTTP login/RBAC scope and SQL rows feed the concrete native
// reader, never the CONTENT SQL/provider fixtures from the unit tests.
func completeNonDRLiveRead(t *testing.T, ctx context.Context, f *dOriginalSixPartTask, registered *publicationRegisteredObject, signer *aSameTaskCertificateMaterials) {
	t.Helper()
	proof := registered.signed.prepared.proof
	limits := proof.limits
	if limits.MaxIndexBytes > 16<<20 {
		limits.MaxIndexBytes = 16 << 20
	}
	materials := PublicationHTTPReadMaterials{Version: PublicationHTTPReadVersion, Artifacts: artifactReadMaterials(proof.target), Catalog: artifactReadMaterials(registered.signed.prepared.catalog.transport()), History: signer.httpHistory, HistoryPin: signer.httpHistoryPin, Limits: limits, MaxReadSeconds: 20}
	raw, err := json.Marshal(materials)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(f.directory, "original-complete-http-read.json")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	provider, err := NewPublicationHTTPReader(ctx, PublicationHTTPReadInput{File: file, SHA256: hash(raw)})
	if err != nil {
		t.Fatal("independent READ composition", err)
	}
	reader := func(path string) (*read.Reader, context.Context) {
		request := httptest.NewRequest(http.MethodGet, "https://localhost/api/v1/admin/"+path, nil)
		request.Header.Set("Authorization", f.originalReadRequest.Header.Get("Authorization"))
		request.TLS = f.originalReadRequest.TLS
		scope, err := f.originalReadAuthorizer.Scope(request)
		if err != nil {
			t.Fatal("actual original login READ scope", err)
		}
		r, err := read.NewReader(f.db, scope)
		if err != nil {
			t.Fatal(err)
		}
		return r, scope.Context()
	}
	r, readCtx := reader("system-backup-catalog-records")
	codec, err := read.NewCatalogCursorCodec([]byte(strings.Repeat("c", 32)))
	if err != nil {
		t.Fatal(err)
	}
	page, err := r.ListCatalogRecordsCurrentV1(readCtx, 50, "", codec, provider)
	if err != nil || len(page.Items) != 1 || page.Items[0].RecordSHA256 != registered.object.SHA256 || !bytes.Equal(page.Items[0].Record, registered.signed.raw) {
		t.Fatal("same-task live catalog list", err)
	}
	r, readCtx = reader("system-backup-catalog-records/" + page.Items[0].ID)
	item, err := r.ReadCatalogRecordCurrentV1(readCtx, page.Items[0].ID, provider)
	if err != nil || !bytes.Equal(item.Record, registered.signed.raw) {
		t.Fatal("same-task live original signed registration", err)
	}
	r, readCtx = reader("system-backups/" + f.publicID + "/manifest")
	manifest, err := r.ReadBackupManifestCurrentV1(readCtx, f.publicID, provider, provider)
	if err != nil || !bytes.Equal(manifest, proof.manifest) {
		t.Fatal("same-task live original negative-qualification manifest", err)
	}
}

func completeNonDRSequenceSnapshot(t *testing.T, ctx context.Context, f *dOriginalSixPartTask) string {
	t.Helper()
	var result string
	err := f.db.QueryRowContext(ctx, `SELECT CONCAT_WS('|',id,row_version,config_version,consecutive_anomaly_count,COALESCE(DATE_FORMAT(first_anomaly_at,'%Y-%m-%dT%H:%i:%s.%f'),'null'),COALESCE(DATE_FORMAT(last_observed_at,'%Y-%m-%dT%H:%i:%s.%f'),'null'),COALESCE(DATE_FORMAT(last_eligible_success_at,'%Y-%m-%dT%H:%i:%s.%f'),'null')) FROM system_backup_v2_alert_states WHERE origin_installation_id=? AND rule_key='acceptance-consecutive-anomalies' AND matrix_key='all' AND task_type='backup' AND task_purpose='acceptance'`, f.service.Config.InstallationID).Scan(&result)
	if errors.Is(err, sql.ErrNoRows) {
		return "absent"
	}
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func completeNonDRAssert(t *testing.T, ctx context.Context, f *dOriginalSixPartTask, registered *publicationRegisteredObject, before terminalFixtureSQLSnapshot, sequence string, artifact *aNativePublicationServer) terminalFixtureSQLSnapshot {
	t.Helper()
	proof := registered.signed.prepared.proof
	local, err := decodePublicationAcceptancePayload(registered.signed.prepared.accepted.signed.prepared.intent.Payload)
	if err != nil || local.Accepted {
		t.Fatal("original negative signed DR evaluation", err)
	}
	after := terminalFixtureSQL(t, ctx, f)
	var purpose, reasons string
	if f.db.QueryRowContext(ctx, `SELECT task_purpose,eligibility_reason_codes FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`, f.service.Config.InstallationID, f.publicID).Scan(&purpose, &reasons) != nil || purpose != "functional_test" || reasons != strings.Join(local.Reasons, ",") {
		t.Fatal("terminal changed purpose or negative reasons")
	}
	if after.status != "succeeded" || after.state != "committed" || !after.usable || after.eligible || after.rowVersion != proof.claim.RowVersion+1 || after.owner.Valid || after.lease.Valid || after.terminalEvents != before.terminalEvents+1 || !after.finished.Valid || !after.decided.Valid || after.registrationSHA != registered.object.SHA256 || after.artifactBytes < 1 {
		t.Fatal("complete original non-DR backup did not atomically succeed")
	}
	if after.sequenceVersion != before.sequenceVersion || after.sequenceCount != before.sequenceCount || after.sequenceSuccess != before.sequenceSuccess {
		t.Fatal("ordinary success changed acceptance anomaly sequence")
	}
	if completeNonDRSequenceSnapshot(t, ctx, f) != sequence {
		t.Fatal("ordinary success rewrote an acceptance sequence field")
	}
	artifact.mu.Lock()
	physical, objects := int64(0), len(artifact.objects)
	for _, body := range artifact.objects {
		physical += int64(len(body))
	}
	artifact.mu.Unlock()
	if objects != 18 || after.artifactBytes != physical {
		t.Fatal("ordinary artifact bytes lost complete original outer objects")
	}
	var raw []byte
	if f.db.QueryRowContext(ctx, `SELECT inline_payload FROM system_backup_v2_evidence WHERE public_id=? AND owner_target_type='backup' AND owner_target_public_id=?`, publicationDecisionID(f.service.Config.InstallationID, f.publicID, proof.attempt), f.publicID).Scan(&raw) != nil {
		t.Fatal("original decision missing")
	}
	decision, at, err := decodePublicationDecision(raw)
	if err != nil || decision.Eligible || !reflect.DeepEqual(decision.Reasons, local.Reasons) || hash(raw) != after.decisionSHA || !at.Equal(after.decided.Time) {
		t.Fatal("negative decision lost its original proof/hash/time", err)
	}
	return after
}

func completeNonDRSeedSequence(t *testing.T, ctx context.Context, f *dOriginalSixPartTask) {
	t.Helper()
	_, err := f.db.ExecContext(ctx, `INSERT INTO system_backup_v2_alert_states(origin_installation_id,rule_key,matrix_key,task_type,task_purpose,config_version,consecutive_anomaly_count,first_anomaly_at,last_observed_at,last_eligible_success_at) VALUES(?,'acceptance-consecutive-anomalies','all','backup','acceptance',1,2,TIMESTAMPADD(MINUTE,-10,UTC_TIMESTAMP(6)),TIMESTAMPADD(MINUTE,-5,UTC_TIMESTAMP(6)),TIMESTAMPADD(MINUTE,-20,UTC_TIMESTAMP(6)))`, f.service.Config.InstallationID)
	if err != nil {
		t.Fatal("seed existing acceptance anomaly, never replace it", err)
	}
}

func TestPublicationTerminalCompleteNonDRHappyPathMySQL(t *testing.T) {
	for _, mode := range []string{"current", "no-acceptance-state", "unwrap-revoked"} {
		t.Run(mode, func(t *testing.T) {
			runPublicationDecisionOriginalRegistered(t, nil, func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, registered *publicationRegisteredObject, signer *aSameTaskCertificateMaterials, artifact, catalog *aNativePublicationServer, clocks *atomic.Int64) {
				terminalFixtureIndependentReadback(t, ctx, f, registered)
				proof := registered.signed.prepared.proof
				if proof.sourceRecovery == nil || len(proof.source.Teams.Teams) == 0 || len(proof.source.Skills.Skills) == 0 {
					t.Fatal("ordinary path lost physical recovery/nonempty source content")
				}
				if mode != "no-acceptance-state" {
					completeNonDRSeedSequence(t, ctx, f)
				}
				sequence := completeNonDRSequenceSnapshot(t, ctx, f)
				before := terminalFixtureSQL(t, ctx, f)
				network := terminalFixtureNetworkSnapshot(signer, artifact, catalog)
				if mode == "unwrap-revoked" {
					binding := f.service.publisherVerifier.Binding
					rev := reg.Revocation{Purpose: reg.UnwrapRevocation, Source: reg.SourceRecord{SourceID: "owned-original-observer", RecordID: "ordinary-unwrap-withdrawal", RecordVersion: "r2", ContentSHA256: hash([]byte("original withdrawal DATA"))}, SourceRevision: "r2", ObservedAt: time.Now().UTC().Add(-time.Millisecond)}
					raw, _ := json.Marshal(rev)
					tx, err := f.db.BeginTx(ctx, nil)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback()
					if _, err = tx.ExecContext(ctx, `UPDATE system_backup_v2_kek_fences SET epoch=epoch+1 WHERE installation_id=?`, binding.InstallationID); err != nil {
						t.Fatal(err)
					}
					if _, err = tx.ExecContext(ctx, `UPDATE system_backup_v2_kek_bindings SET unwrap_revocation_json=?,row_version=row_version+1 WHERE installation_id=? AND identity_hash=? AND registry_version=?`, raw, binding.InstallationID, binding.ConfigRef.IdentityHash, binding.ConfigRef.Version); err != nil {
						t.Fatal(err)
					}
					if err = tx.Commit(); err != nil {
						t.Fatal(err)
					}
					var progress publicationTerminalProgress
					if err = f.service.completeOriginalPublicationTerminal(ctx, proof.claim, proof.attempt, proof, true, &progress); err == nil || progress.committed {
						t.Fatal("negative DR classification excused current key withdrawal")
					}
					if !reflect.DeepEqual(before, terminalFixtureSQL(t, ctx, f)) || network != terminalFixtureNetworkSnapshot(signer, artifact, catalog) {
						t.Fatal("withdrawn ordinary task reached terminal or replayed external work")
					}
					return
				}
				var progress publicationTerminalProgress
				if err := f.service.completeOriginalPublicationTerminal(ctx, proof.claim, proof.attempt, proof, true, &progress); err != nil || !progress.committed {
					t.Fatal("complete ordinary terminal producer", err)
				}
				committed := completeNonDRAssert(t, ctx, f, registered, before, sequence, artifact)
				if network != terminalFixtureNetworkSnapshot(signer, artifact, catalog) || clocks.Load() != 1 {
					t.Fatal("ordinary terminal replayed signed journals/decision")
				}
				if err := f.service.completeOriginalPublicationTerminal(ctx, proof.claim, proof.attempt, proof, true, &progress); err == nil || !reflect.DeepEqual(committed, terminalFixtureSQL(t, ctx, f)) {
					t.Fatal("ordinary terminal event/CAS repeated")
				}
				completeNonDRLiveRead(t, ctx, f, registered, signer)
			}, true)
		})
	}
}

func TestPublicationTerminalCompleteNonDRCommitUnknownReadOnlyMySQL(t *testing.T) {
	lose := &atomic.Bool{}
	runPublicationDecisionOriginalRegistered(t, lose, func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, registered *publicationRegisteredObject, signer *aSameTaskCertificateMaterials, artifact, catalog *aNativePublicationServer, clocks *atomic.Int64) {
		terminalFixtureIndependentReadback(t, ctx, f, registered)
		proof := registered.signed.prepared.proof
		completeNonDRSeedSequence(t, ctx, f)
		sequence := completeNonDRSequenceSnapshot(t, ctx, f)
		prepared, err := f.service.prepareOriginalPublicationDecision(ctx, registered)
		if err != nil {
			t.Fatal(err)
		}
		decision, err := prepared.Persist(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ready, err := f.service.completeOriginalPublicationReady(ctx, decision)
		if err != nil {
			t.Fatal(err)
		}
		before := terminalFixtureSQL(t, ctx, f)
		network := terminalFixtureNetworkSnapshot(signer, artifact, catalog)
		originalFacts := ready.facts
		ready.facts.Eligible = true
		if err = f.service.applyOriginalPublicationTerminal(ctx, proof.claim, proof.attempt, ready); err == nil {
			t.Fatal("ordinary Ready scalar forged DR approval")
		}
		ready.facts = originalFacts
		if !reflect.DeepEqual(before, terminalFixtureSQL(t, ctx, f)) {
			t.Fatal("forged projection changed task")
		}
		lose.Store(true)
		if err = f.service.applyOriginalPublicationTerminal(ctx, proof.claim, proof.attempt, ready); !errors.Is(err, c.ErrExecutionCommitUnknown) || lose.Load() {
			t.Fatal("ordinary actual terminal ACK loss", err)
		}
		committed := completeNonDRAssert(t, ctx, f, registered, before, sequence, artifact)
		for n := 0; n < 2; n++ {
			if err = f.service.observeOriginalPublicationTerminal(ctx, proof.claim, proof.attempt, ready); err != nil {
				t.Fatal("ordinary independent exact terminal observation", err)
			}
			if !reflect.DeepEqual(committed, terminalFixtureSQL(t, ctx, f)) || network != terminalFixtureNetworkSnapshot(signer, artifact, catalog) || clocks.Load() != 1 {
				t.Fatal("unknown ordinary observation mutated/replayed work")
			}
		}
		completeNonDRLiveRead(t, ctx, f, registered, signer)
	}, true)
}
