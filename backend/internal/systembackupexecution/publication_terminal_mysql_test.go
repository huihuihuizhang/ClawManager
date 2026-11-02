//go:build systembackup_mysql

package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	pc "clawreef/internal/systembackuppartcontainer"
	security "clawreef/internal/systembackupsecurity"
)

// Uses the actual original admitted task, production capture/SQL, original
// source-recovery producer, encrypted worker output, real cleanup and complete
// final/acceptance/catalog producers. Kube/S3/provider remain local transports;
// this is not a field/page PASS and never constructs a private Ready/facts DTO.
type terminalFixtureNetwork struct {
	signs                                                int64
	artifactPuts, artifactGets, catalogPuts, catalogGets int
}

func terminalFixtureNetworkSnapshot(signer *aSameTaskCertificateMaterials, artifact, catalog *aNativePublicationServer) terminalFixtureNetwork {
	out := terminalFixtureNetwork{signs: signer.signs.Load()}
	artifact.mu.Lock()
	out.artifactPuts, out.artifactGets = artifact.puts, artifact.gets
	artifact.mu.Unlock()
	catalog.mu.Lock()
	out.catalogPuts, out.catalogGets = catalog.puts, catalog.gets
	catalog.mu.Unlock()
	return out
}

func terminalFixtureIndependentReadback(t *testing.T, ctx context.Context, f *dOriginalSixPartTask, registered *publicationRegisteredObject) {
	t.Helper()
	proof := registered.signed.prepared.proof
	accepted := registered.signed.prepared.accepted
	material := registered.signed.prepared.catalog
	if material.ReadIdentityHash == proof.target.ReadIdentityHash || material.ReadCredentialFile == proof.target.ReadCredentialFile {
		t.Fatal("independent catalog read principal missing")
	}
	catalog, err := NewArtifactReadOnlyS3(artifactReadMaterials(material.transport()), proof.limits)
	if err != nil {
		t.Fatal(err)
	}
	defer catalog.Close()
	raw, observed, err := catalog.readVersionedBytes(ctx, registered.object.Key, registered.object.Version, registered.object.SHA256, registered.object.Size, proof.access.ValidUntil())
	if err != nil || observed.Size != registered.object.Size || !bytes.Equal(raw, registered.signed.raw) {
		t.Fatal("independent exact original catalog EOF readback", err)
	}
	history, err := f.service.PublicationSigningHistory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	task := security.ArtifactSigningTask{BackupPublicID: f.publicID, AttemptNo: int64(proof.attempt)}
	if _, err = history.VerifyPublicationRecord(raw, task, "catalog_record"); err != nil {
		t.Fatal("independent original catalog signature", err)
	}
	payload, err := decodePublicationCatalogPayload(registered.signed.prepared.intent.Payload)
	if err != nil || payload.Manifest.Key != proof.manifestObject.Key || payload.Manifest.Version != proof.manifestObject.Version || payload.ManifestSHA256 != proof.manifestObject.SHA256 || payload.AcceptanceSHA256 != accepted.object.SHA256 {
		t.Fatal("catalog does not anchor this original artifact", err)
	}
	artifact, err := NewArtifactReadOnlyS3(artifactReadMaterials(proof.target), proof.limits)
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	completion := proof.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion
	report, digest, err := proof.contentSamples.snapshot()
	if err != nil || !formalCandidateDigest(digest) || report.Manifest != proof.manifestObject || report.Backup != f.publicID || proof.source.Teams == nil || len(proof.source.Teams.Teams) == 0 || proof.source.Skills == nil || len(proof.source.Skills.Skills) == 0 {
		t.Fatal("same final artifact lacks nonempty authenticated business observations", err)
	}
	actualSQLRows := map[string]int64{}
	for _, member := range report.Members {
		if member.Operation == "capture-database" {
			for _, table := range member.Counts.SQLTables {
				actualSQLRows[table.Table] = table.Rows
			}
		}
	}
	var skillRows int64
	for _, table := range proof.source.Skills.Tables {
		if actualSQLRows[table.Name] != int64(len(table.IDs)) {
			t.Fatal("final SQL readback did not cover original Skills table keyset")
		}
		skillRows += actualSQLRows[table.Name]
	}
	if actualSQLRows["teams"] != int64(len(proof.source.Teams.Teams)) || skillRows == 0 {
		t.Fatal("final parsed SQL observations are empty or not the original Teams/Skills")
	}
	for _, item := range []struct {
		object ArtifactReadObject
		raw    []byte
	}{
		{proof.manifestObject, proof.manifest}, {proof.markerObject, proof.marker},
		{completion.objects.Metadata["artifact-index.json"], proof.index},
		{ArtifactReadObject{Key: accepted.object.Key, Version: accepted.object.Version, SHA256: accepted.object.SHA256, Size: accepted.object.Size}, accepted.signed.raw},
	} {
		got, fixed, readErr := artifact.readVersionedBytes(ctx, item.object.Key, item.object.Version, item.object.SHA256, item.object.Size, proof.access.ValidUntil())
		if readErr != nil || fixed != item.object || !bytes.Equal(got, item.raw) {
			t.Fatal("independent fixed-version public object EOF readback", readErr)
		}
	}
	if _, err = history.VerifyPublicationRecord(accepted.signed.raw, task, "acceptance_record"); err != nil {
		t.Fatal(err)
	}
	capture := completion.capture
	for _, requested := range publicationRequestedParts {
		checkpoints := map[string]string{}
		for _, part := range capture.Parts {
			if part.RequestedPart == requested {
				checkpoints[part.Part], err = pcCheckpointSHA(part.Checkpoint)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		object := completion.objects.Containers[requested]
		facts, readErr := artifact.InspectPartContainer(ctx, object, pc.Scope{Installation: capture.Input.InstallationID, Backup: f.publicID, Attempt: proof.attempt, ConfigVersion: capture.Input.ConfigVersion, ConfigSHA256: capture.Input.ConfigSHA256, CaptureContextSHA256: capture.CaptureContextSHA256, Part: requested}, checkpoints, proof.access.ValidUntil())
		if readErr != nil || facts.SHA256 != object.SHA256 || facts.Size != object.Size || len(facts.Header.Members) != len(checkpoints) {
			t.Fatal("independent full original container EOF readback", requested, readErr)
		}
	}
	// Full plaintext/domain validation already happened in the real finalizer;
	// this repeat is outer-object readback, never an invented Unwrap/restore proof.
	custody, err := openPublicationLocalCustody(f.owner.Staging)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	if !publicationLocalFilesAbsent(f.owner.Staging, custody, f.publicID, proof.cleanup.seals) {
		t.Fatal("independent readback depended on/recreated original stage")
	}
}

type terminalFixtureSQLSnapshot struct {
	rowVersion, taskCount, terminalEvents, sequenceVersion    uint64
	status, state, registration, registrationSHA, decisionSHA string
	usable, eligible                                          bool
	owner                                                     sql.NullString
	lease, finished, decided, sequenceSuccess                 sql.NullTime
	sequenceCount                                             uint32
	artifactBytes                                             int64
}

func terminalFixtureSQL(t *testing.T, ctx context.Context, f *dOriginalSixPartTask) terminalFixtureSQLSnapshot {
	t.Helper()
	var out terminalFixtureSQLSnapshot
	if err := f.db.QueryRowContext(ctx, `SELECT row_version,status,artifact_state,artifact_usable,acceptance_eligible,controller_owner,controller_lease_expires_at,finished_at,COALESCE(artifact_registration_id,''),COALESCE(artifact_registration_hash,''),COALESCE(eligibility_decision_hash,''),eligibility_decided_at,COALESCE(artifact_bytes,0) FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`, f.service.Config.InstallationID, f.publicID).Scan(&out.rowVersion, &out.status, &out.state, &out.usable, &out.eligible, &out.owner, &out.lease, &out.finished, &out.registration, &out.registrationSHA, &out.decisionSHA, &out.decided, &out.artifactBytes); err != nil {
		t.Fatal(err)
	}
	if f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_backups`).Scan(&out.taskCount) != nil || out.taskCount != 1 {
		t.Fatal("publication created a different task")
	}
	if f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_events WHERE target_type='backup' AND target_public_id=? AND event_type='task_status_changed' AND task_status='succeeded' AND detail_previous_status='publishing' AND detail_current_status='succeeded'`, f.publicID).Scan(&out.terminalEvents) != nil {
		t.Fatal("terminal event query")
	}
	err := f.db.QueryRowContext(ctx, `SELECT row_version,consecutive_anomaly_count,last_eligible_success_at FROM system_backup_v2_alert_states WHERE origin_installation_id=? AND rule_key='acceptance-consecutive-anomalies' AND matrix_key='all' AND task_type='backup' AND task_purpose='acceptance'`, f.service.Config.InstallationID).Scan(&out.sequenceVersion, &out.sequenceCount, &out.sequenceSuccess)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	return out
}

func terminalFixtureAssertSuccess(t *testing.T, ctx context.Context, f *dOriginalSixPartTask, proof *publicationFinalVerification, registered *publicationRegisteredObject, artifact *aNativePublicationServer, before terminalFixtureSQLSnapshot) terminalFixtureSQLSnapshot {
	t.Helper()
	after := terminalFixtureSQL(t, ctx, f)
	wantSequence := before.sequenceVersion + 1
	if before.sequenceVersion == 0 {
		wantSequence = 2
	} // Existing helper inserts RV1 then CASes once.
	if after.status != "succeeded" || after.state != "committed" || !after.usable || !after.eligible || after.rowVersion != proof.claim.RowVersion+1 || after.rowVersion != before.rowVersion+1 || after.owner.Valid || after.lease.Valid || !after.finished.Valid || !after.decided.Valid || after.finished.Time.Before(after.decided.Time) || after.registration != publicationCatalogRecordID(f.service.Config.InstallationID, f.publicID, proof.attempt) || after.registrationSHA != registered.object.SHA256 || !formalCandidateDigest(after.decisionSHA) || after.artifactBytes < 1 || after.terminalEvents != before.terminalEvents+1 || after.sequenceVersion != wantSequence || after.sequenceCount != 0 || !after.sequenceSuccess.Valid || after.sequenceSuccess.Time.Before(after.finished.Time) {
		t.Fatal("task/artifact/event/sequence did not atomically reach the one original terminal outcome")
	}
	// Sum the server's ACTUAL remaining physical bodies independently of Ready's
	// calculation. The one candidate is gone; catalog has a different server.
	artifact.mu.Lock()
	objects, physicalBytes := len(artifact.objects), int64(0)
	for _, body := range artifact.objects {
		physicalBytes += int64(len(body))
	}
	artifact.mu.Unlock()
	if objects != 18 || after.artifactBytes != physicalBytes {
		t.Fatal("terminal bytes are not the original unique outer physical bodies")
	}
	var decisionRaw []byte
	var decisionSHA string
	id := publicationDecisionID(f.service.Config.InstallationID, f.publicID, proof.attempt)
	if f.db.QueryRowContext(ctx, `SELECT inline_payload,content_checksum FROM system_backup_v2_evidence WHERE origin_installation_id=? AND public_id=? AND owner_target_type='backup' AND owner_target_public_id=?`, f.service.Config.InstallationID, id, f.publicID).Scan(&decisionRaw, &decisionSHA) != nil || hash(decisionRaw) != decisionSHA || decisionSHA != after.decisionSHA {
		t.Fatal("terminal decision does not name the actual persisted complete preimage")
	}
	_, originalDecisionAt, err := decodePublicationDecision(decisionRaw)
	if err != nil || !after.decided.Time.Equal(originalDecisionAt) {
		t.Fatal("terminal replaced the original internal decision time", err)
	}
	var artifactURI, manifestURI, artifactVersion, manifestVersion, artifactSHA, manifestSHA string
	if f.db.QueryRowContext(ctx, `SELECT artifact_uri,manifest_uri,artifact_immutable_version,manifest_immutable_version,artifact_checksum,manifest_checksum FROM system_backup_v2_backups WHERE public_id=?`, f.publicID).Scan(&artifactURI, &manifestURI, &artifactVersion, &manifestVersion, &artifactSHA, &manifestSHA) != nil || artifactURI != manifestURI || artifactVersion != manifestVersion || artifactSHA != manifestSHA || manifestVersion != proof.manifestObject.Version || manifestSHA != proof.manifestObject.SHA256 {
		t.Fatal("terminal manifest compatibility alias drifted")
	}
	return after
}

func TestPublicationTerminalOriginalHappyPathMySQL(t *testing.T) {
	runPublicationDecisionOriginalRegistered(t, nil, func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, registered *publicationRegisteredObject, signer *aSameTaskCertificateMaterials, artifact, catalog *aNativePublicationServer, clocks *atomic.Int64) {
		terminalFixtureIndependentReadback(t, ctx, f, registered)
		proof := registered.signed.prepared.proof
		before := terminalFixtureSQL(t, ctx, f)
		network := terminalFixtureNetworkSnapshot(signer, artifact, catalog)
		var progress publicationTerminalProgress
		if err := f.service.completeOriginalPublicationTerminal(ctx, proof.claim, proof.attempt, proof, true, &progress); err != nil || !progress.committed || progress.commitUnknown {
			t.Fatal("real complete publication/Ready/terminal producer", err)
		}
		terminalFixtureAssertSuccess(t, ctx, f, proof, registered, artifact, before)
		after := terminalFixtureNetworkSnapshot(signer, artifact, catalog)
		if after.signs != network.signs || after.artifactPuts != 19 || after.catalogPuts != 1 || after.artifactPuts != network.artifactPuts || after.catalogPuts != network.catalogPuts || clocks.Load() != 1 {
			t.Fatal("terminal replayed signing/publication or decision clock")
		}
		// Same in-process completed invocation cannot initialize another decision.
		stable := terminalFixtureSQL(t, ctx, f)
		if err := f.service.completeOriginalPublicationTerminal(ctx, proof.claim, proof.attempt, proof, true, &progress); err == nil {
			t.Fatal("completed invocation reentered mutation chain")
		}
		if !reflect.DeepEqual(stable, terminalFixtureSQL(t, ctx, f)) {
			t.Fatal("completed invocation advanced terminal/event/sequence twice")
		}
	})
}

func TestPublicationTerminalCommitUnknownReadOnlyMySQL(t *testing.T) {
	lose := &atomic.Bool{}
	runPublicationDecisionOriginalRegistered(t, lose, func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, registered *publicationRegisteredObject, signer *aSameTaskCertificateMaterials, artifact, catalog *aNativePublicationServer, clocks *atomic.Int64) {
		terminalFixtureIndependentReadback(t, ctx, f, registered)
		proof := registered.signed.prepared.proof
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
			t.Fatal("actual persisted decision did not create Ready", err)
		}
		before := terminalFixtureSQL(t, ctx, f)
		network := terminalFixtureNetworkSnapshot(signer, artifact, catalog)
		lose.Store(true) // Native driver commits THIS write transaction, then loses its ACK.
		if err = f.service.applyOriginalPublicationTerminal(ctx, proof.claim, proof.attempt, ready); !errors.Is(err, c.ErrExecutionCommitUnknown) || lose.Load() {
			t.Fatal("actual terminal commit ACK loss not preserved", err)
		}
		committed := terminalFixtureAssertSuccess(t, ctx, f, proof, registered, artifact, before)
		readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		for n := 0; n < 2; n++ {
			if err = f.service.observeOriginalPublicationTerminal(readCtx, proof.claim, proof.attempt, ready); err != nil {
				t.Fatal("independent query-only original terminal confirmation", err)
			}
			if !reflect.DeepEqual(committed, terminalFixtureSQL(t, readCtx, f)) || terminalFixtureNetworkSnapshot(signer, artifact, catalog) != network || clocks.Load() != 1 {
				t.Fatal("unknown confirmation mutated task/event/sequence or replayed external work")
			}
		}
		// Successful terminal clears the old publishing claim. Its refusal is
		// expected; the independent observer above must not invoke this gate.
		tx, err := f.control.BeginTx(readCtx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		oldErr := ready.recheckTx(readCtx, tx)
		_ = tx.Rollback()
		if oldErr == nil {
			t.Fatal("old publishing authority survived terminal success")
		}
	})
}
