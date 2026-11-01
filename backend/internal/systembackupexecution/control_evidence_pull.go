package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

const ControlEvidencePullPath = "/control-evidence"

// The public invocation contains ONLY this locator under control_evidence.
// Its complete original bytes are independently compared by Owner.Authorize;
// extraction cannot turn a request/locator into execution permission.
func originalControlEvidenceLocator(request worker.ControlRequest) (ce.CaptureLocator, error) {
	var locator ce.CaptureLocator
	if request.Action != "key-check" || request.Invocation.Request.Operation != ce.Operation || request.Invocation.FormalCapture == nil || request.Invocation.ProviderKey == nil {
		return locator, c.ErrExecutionAuthority
	}
	raw, err := json.Marshal(request.Invocation.Request)
	if err != nil {
		return locator, c.ErrExecutionAuthority
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return locator, c.ErrExecutionAuthority
	}
	encoded, ok := fields["control_evidence"]
	if !ok || decodeProviderDeploymentJSON(encoded, &locator) != nil || locator.Validate() != nil {
		return ce.CaptureLocator{}, c.ErrExecutionAuthority
	}
	inv := request.Invocation
	binding, context := inv.Request.Binding, inv.ProviderKey.Request.Context
	if locator.Expected.Backup != binding.BackupID || strconv.FormatUint(locator.Expected.Attempt, 10) != binding.Attempt || locator.Expected.Installation != context.InstallationID || inv.FormalCapture.SourceConfigSHA256 != locator.Expected.ConfigSHA256 || binding.Path != context.Part || binding.CaptureContextHash != context.CaptureContextHash {
		return ce.CaptureLocator{}, c.ErrExecutionAuthority
	}
	if binding.Path == ce.Part {
		if inv.Request.ArtifactName != ce.LogicalCipherName {
			return ce.CaptureLocator{}, c.ErrExecutionAuthority
		}
	} else if binding.Path == ce.ProofPart {
		if inv.Request.ArtifactName != ce.LogicalProofCipherName {
			return ce.CaptureLocator{}, c.ErrExecutionAuthority
		}
	} else {
		return ce.CaptureLocator{}, c.ErrExecutionAuthority
	}
	return locator, nil
}

func (s *DeploymentService) controlEvidenceSourceHandler() http.Handler {
	owner := s.Runtime.Owner
	return WorkloadIdentity{Client: owner.Client, Namespace: owner.Namespace, ServiceAccount: owner.Security.ServiceAccountName, ServiceAccountUID: owner.Security.ServiceAccountUID, Next: http.HandlerFunc(s.serveControlEvidenceSource)}
}

func (s *DeploymentService) serveControlEvidenceSource(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	stage, started := "controller-pull-input-materials-tls", time.Now()
	diagnosticContext, diagnosticUntil := r.Context(), time.Time{}
	deny := func() {
		logOriginalControlEvidenceRejection(stage, diagnosticContext, diagnosticUntil, started)
		w.WriteHeader(http.StatusForbidden)
	}
	if r.Method != http.MethodPost || s == nil || !s.ForwardEnabled || s.Runtime == nil || s.Runtime.Owner == nil || s.captureMaterials == nil || s.captureMaterials.ControlEvidence == nil || s.checkProductionCaptureMaterials() != nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		deny()
		return
	}
	cert := r.TLS.PeerCertificates[0]
	stage = "controller-pull-peer-uri"
	if len(cert.URIs) != 1 || cert.URIs[0].Scheme != "spiffe" || cert.URIs[0].Host == "" {
		deny()
		return
	}
	var request worker.ControlRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, (1<<20)+1))
	decoder.DisallowUnknownFields()
	stage = "controller-pull-request-decode"
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !worker.ValidateControl(request) {
		deny()
		return
	}
	stage = "controller-pull-original-locator"
	locator, err := originalControlEvidenceLocator(request)
	if err != nil {
		deny()
		return
	}
	stage = "controller-pull-installation"
	if locator.Expected.Installation != s.Config.InstallationID {
		deny()
		return
	}
	peer := cert.URIs[0].String()
	owner := s.Runtime.Owner
	stage = "controller-pull-authorize-before"
	first, err := owner.Authorize(r.Context(), peer, request)
	defer first.Clear()
	if err != nil || first.KeyUse == nil || first.KeyUse.State != "using" || first.KeyUse.Nonce != request.Point || first.InvocationSHA256 != request.InvocationSHA256 {
		deny()
		return
	}
	diagnosticUntil = first.ExpiresAt
	stage = "controller-pull-source-materials"
	operation, exists := s.captureMaterials.Operations[ce.Operation]
	if !exists || operation.Formal.PermitDelivery == nil || s.captureMaterials.ControlEvidenceSource == nil {
		deny()
		return
	}
	mount := *s.captureMaterials.ControlEvidenceSource
	stage = "controller-pull-source-mount"
	if mount.Endpoint != s.Config.ControlURL || request.Invocation.FormalCapture.PermitDelivery == nil || bytes.Equal(mount.Issuer, request.Invocation.FormalCapture.PermitDelivery.Issuer) {
		deny()
		return
	}
	stage = "controller-pull-source-grant-before"
	firstGrant, err := worker.ReadControlEvidenceSourceGrant(r.Context(), mount, locator.Expected, first.KeyUse.Identity, true)
	if err != nil {
		deny()
		return
	}
	until := first.ExpiresAt
	if firstGrant.Until.Before(until) {
		until = firstGrant.Until
	}
	ctx, cancel := context.WithDeadline(r.Context(), until)
	defer cancel()
	diagnosticContext, diagnosticUntil = ctx, until
	stage = "controller-pull-source-sql-before"
	entries, err := s.readOriginalControlEvidenceEntries(ctx, request, locator, first)
	if err != nil {
		deny()
		return
	}
	stage = "controller-pull-rebuild-snapshot"
	prepared, finalSeal, responseEntries, locatorChunks, err := rebuildControlSourceSnapshot(ctx, locator, entries)
	if err != nil {
		deny()
		return
	}
	defer clear(prepared.SidecarJSON)
	defer clear(prepared.ProofsJSON)
	// Last workload/provider/Job checks finish before the final short original
	// task/key-use/evidence SQL snapshot. No SQL lock is held over network I/O.
	stage = "controller-pull-authorize-after"
	last, err := owner.Authorize(ctx, peer, request)
	defer last.Clear()
	if err != nil || last.KeyUse == nil || *last.KeyUse != *first.KeyUse || !last.ExpiresAt.Equal(first.ExpiresAt) || last.InvocationSHA256 != first.InvocationSHA256 {
		deny()
		return
	}
	stage = "controller-pull-source-grant-after"
	lastGrant, err := worker.ReadControlEvidenceSourceGrant(ctx, mount, locator.Expected, first.KeyUse.Identity, true)
	if err != nil || lastGrant != firstGrant {
		deny()
		return
	}
	stage = "controller-pull-source-sql-after"
	finalEntries, err := s.readOriginalControlEvidenceEntries(ctx, request, locator, first)
	if err != nil || len(finalEntries) != len(entries) {
		deny()
		return
	}
	for i := range entries {
		stage = "controller-pull-source-snapshot-match"
		if entries[i].PublicID != finalEntries[i].PublicID || entries[i].SHA256 != finalEntries[i].SHA256 || !bytes.Equal(entries[i].Payload, finalEntries[i].Payload) {
			deny()
			return
		}
	}
	// The final SQL snapshot can itself outlive a source-owner revocation. This
	// bounded local check follows SQL and cannot adopt a replacement grant or
	// extend the original fixed source/key-use deadline. No network follows it.
	stage = "controller-pull-source-grant-tail"
	finalGrant, err := worker.ReadControlEvidenceSourceGrant(ctx, mount, locator.Expected, first.KeyUse.Identity, true)
	if err != nil || finalGrant != firstGrant {
		deny()
		return
	}
	stage = "controller-pull-materials-and-clock-tail"
	if s.checkProductionCaptureMaterials() != nil || ctx.Err() != nil || !time.Now().Before(first.ExpiresAt) {
		deny()
		return
	}
	response := ce.SourceResponse{Version: "system-backup-control-evidence-source-response.v1", InvocationSHA256: request.InvocationSHA256, KeyUseNonce: request.Point, AuthoritySHA256: first.KeyUse.AuthoritySHA256, Until: first.ExpiresAt, Evidence: entries}
	if locator.Finalization != nil {
		response.Version = "system-backup-control-evidence-source-response.v2"
		response.FinalizedSource = finalSeal
		response.FinalizedLocatorChunks = locatorChunks
		response.Evidence = responseEntries
	}
	stage = "controller-pull-response-canonical"
	raw, err := ce.CanonicalProofs(response)
	if err != nil {
		deny()
		return
	}
	defer clear(raw)
	_ = http.NewResponseController(w).SetWriteDeadline(until)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// SQL-only exact original scope. It cannot revive an old capture claim or
// substitute current publisher permission for a live original Job/key-use.
func (s *DeploymentService) readOriginalControlEvidenceEntries(ctx context.Context, request worker.ControlRequest, locator ce.CaptureLocator, lease worker.Lease) (_ []ce.RegisteredEvidence, resultErr error) {
	stage, started := "controller-source-using-lease", time.Now()
	defer func() {
		if resultErr != nil {
			logOriginalControlEvidenceRejection(stage, ctx, lease.ExpiresAt, started)
		}
	}()
	if lease.KeyUse == nil || lease.KeyUse.State != "using" || lease.KeyUse.Identity.InvocationSHA256 != request.InvocationSHA256 || ctx.Err() != nil {
		return nil, c.ErrExecutionAuthority
	}
	gate := s.Runtime.Owner.Gate.Authority
	stage = "controller-source-begin-snapshot"
	tx, err := gate.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, c.ErrExecutionAuthority
	}
	defer tx.Rollback()
	authority := d.Authority{InstallationID: locator.Expected.Installation, TaskPublicID: locator.Expected.Backup, TaskType: "backup", Phase: "capture", AttemptNo: locator.Expected.Attempt, MaintenanceOwner: locator.Expected.Backup}
	stage = "controller-source-original-claim-config"
	if readOriginalCaptureAuthorityLookup(ctx, tx, &authority) != nil || authority.ConfigSHA256 != locator.Expected.ConfigSHA256 {
		return nil, c.ErrExecutionAuthority
	}
	authorityRaw, _ := json.Marshal(authority)
	stage = "controller-source-original-authority-hash"
	if hash(authorityRaw) != lease.KeyUse.AuthoritySHA256 {
		return nil, c.ErrExecutionAuthority
	}
	stage = "controller-source-execution-bind"
	guard, err := gate.BindObserved(ctx, tx, authority, logOriginalExecutionBindDiagnostic)
	if err != nil {
		return nil, err
	}
	var originalUse []byte
	stage = "controller-source-original-runtime-key-row"
	if tx.QueryRowContext(ctx, `SELECT key_use_json FROM system_backup_v2_runtime_resources WHERE target_type=? AND task_public_id=? AND attempt_no=? AND phase=? AND resource_kind='Job' AND observed_uid=? AND namespace_name=? AND revoked=FALSE AND lifecycle='ready' AND create_dispatched=TRUE AND stopped_at IS NULL FOR SHARE`, authority.TaskType, authority.TaskPublicID, authority.AttemptNo, authority.Phase, lease.KeyUse.Identity.JobUID, lease.KeyUse.Identity.Namespace).Scan(&originalUse) != nil {
		return nil, c.ErrExecutionAuthority
	}
	var actual worker.KeyUseLease
	stage = "controller-source-original-runtime-key-match"
	if decodeProviderDeploymentJSON(originalUse, &actual) != nil || actual != *lease.KeyUse || !time.Now().Before(actual.Until) || actual.State != "using" {
		return nil, c.ErrExecutionAuthority
	}
	effective := locator
	var finalized []ce.RegisteredEvidence
	if locator.Finalization != nil {
		stage = "controller-source-finalized-business-sql"
		prepared, seal, err := loadFinalizedControlSourceSQL(ctx, tx, locator)
		if err != nil {
			return nil, err
		}
		effective = prepared.Locator
		clear(prepared.SidecarJSON)
		clear(prepared.ProofsJSON)
		finalized = seal
	}
	out := make([]ce.RegisteredEvidence, 0, len(effective.Evidence)+1)
	for _, ref := range effective.Evidence {
		stage = "controller-source-registered-evidence"
		entry, err := ce.LoadRegisteredSQL(ctx, tx, locator.Expected.Scope, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	out = append(out, finalized...)
	stage = "controller-source-guard-tail"
	if guard.Recheck(ctx, tx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	var now time.Time
	stage = "controller-source-delivered-clock"
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !now.Before(actual.Until) || !now.Before(lease.ExpiresAt) || guard.Recheck(ctx, tx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	stage = "controller-source-close-snapshot"
	if tx.Rollback() != nil {
		return nil, c.ErrExecutionAuthority
	}
	return out, nil
}

func rebuildControlSourceSnapshot(ctx context.Context, locator ce.CaptureLocator, entries []ce.RegisteredEvidence) (ce.PreparedSource, *ce.RegisteredEvidence, []ce.RegisteredEvidence, []ce.RegisteredEvidence, error) {
	if locator.Finalization == nil {
		prepared, err := ce.Rebuild(ctx, locator, entries)
		return prepared, nil, entries, nil, err
	}
	if len(entries) < 2 {
		return ce.PreparedSource{}, nil, nil, nil, ce.ErrInvalid
	}
	seal := entries[len(entries)-1]
	refs, err := ce.FinalizedSourceReferences(locator, seal)
	if err != nil || len(refs)+1 >= len(entries) {
		return ce.PreparedSource{}, nil, nil, nil, ce.ErrInvalid
	}
	chunks := entries[len(entries)-len(refs)-1 : len(entries)-1]
	final, err := ce.ReadFinalizedSourceSeal(locator, seal, chunks...)
	if err != nil {
		return ce.PreparedSource{}, nil, nil, nil, err
	}
	proofs := entries[:len(entries)-len(refs)-1]
	prepared, err := ce.VerifyFinalized(ctx, locator, final, proofs)
	return prepared, &seal, proofs, chunks, err
}
