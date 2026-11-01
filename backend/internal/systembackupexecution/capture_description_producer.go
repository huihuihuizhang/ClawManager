package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	cd "clawreef/internal/systembackupcapturedescription"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

type originalDescriptionMember struct{ candidate, result []byte }

// Exact plan-set comparison is outside the descriptor codec: an encrypted
// descriptor's own list is never accepted as the original authoritative set.
func descriptionPlan(seed cd.Seed, parts []b.JobPart) ([]cd.Invocation, error) {
	if seed.Validate() != nil || len(parts) != len(seed.Members)+3 {
		return nil, c.ErrExecutionRecord
	}
	business := []cd.Selection{}
	admin := map[string]cd.Invocation{}
	indices := map[uint32]bool{}
	envelopes := map[string]bool{}
	for _, p := range parts {
		var inv worker.Invocation
		if decodeProviderDeploymentJSON(p.InvocationJSON, &inv) != nil || !worker.ValidateRecordedInvocation(inv) || hash(p.InvocationJSON) != p.InvocationSHA256 || inv.Request.Binding.Path != p.Part || indices[inv.Request.Binding.PartIndex] || envelopes[inv.Request.Binding.EnvelopeID] {
			return nil, c.ErrExecutionRecord
		}
		sha, err := inv.Hash()
		if err != nil || sha != p.InvocationSHA256 {
			return nil, c.ErrExecutionRecord
		}
		index := inv.Request.Binding.PartIndex
		indices[index] = true
		envelopes[inv.Request.Binding.EnvelopeID] = true
		selection := cd.Selection{Part: p.Part, Operation: inv.Request.Operation, PartIndex: index}
		if cd.BusinessOperation(selection.Operation) {
			business = append(business, selection)
			continue
		}
		if p.Part == cd.Part && selection.Operation == cd.Operation && inv.Request.CaptureDescription != nil {
			actual, _ := json.Marshal(inv.Request.CaptureDescription)
			expected, _ := json.Marshal(seed)
			if !bytes.Equal(actual, expected) {
				return nil, c.ErrExecutionRecord
			}
		} else if (p.Part != cd.ControlPart && p.Part != cd.ProofPart) || selection.Operation != cd.ControlOperation || inv.Request.ControlEvidence == nil {
			return nil, c.ErrExecutionRecord
		}
		if _, exists := admin[p.Part]; exists {
			return nil, c.ErrExecutionRecord
		}
		admin[p.Part] = cd.Invocation{Selection: selection, JSON: bytes.Clone(p.InvocationJSON), SHA256: p.InvocationSHA256}
	}
	sort.Slice(business, func(i, j int) bool { return business[i].Part < business[j].Part })
	left, _ := json.Marshal(business)
	right, _ := json.Marshal(seed.Members)
	if !bytes.Equal(left, right) || len(admin) != 3 {
		return nil, c.ErrExecutionRecord
	}
	for i := range parts {
		if !indices[uint32(i)] {
			return nil, c.ErrExecutionRecord
		}
	}
	return []cd.Invocation{admin[cd.Part], admin[cd.ControlPart], admin[cd.ProofPart]}, nil
}

func buildOriginalDescription(in d.Input, plan d.Plan, discovery b.Discovery, seed cd.Seed, records map[string]originalDescriptionMember) (cd.Description, error) {
	var zero cd.Description
	administrative, err := descriptionPlan(seed, discovery.Parts)
	if err != nil {
		return zero, err
	}
	if hash(discovery.Source) != discovery.SourceSHA256 || len(records) != len(seed.Members) {
		return zero, c.ErrExecutionRecord
	}
	inner, err := d.UnwrapTaskPlan(in, plan, b.PlanVersion)
	if err != nil {
		return zero, err
	}
	defer clear(inner.CanonicalJSON)
	a := in.Authority
	description := cd.Description{Version: cd.Version, Scope: cd.Scope{InstallationID: a.InstallationID, TaskPublicID: a.TaskPublicID, ConfigVersion: a.ConfigVersion, ConfigSHA256: a.ConfigSHA256, AttemptNo: a.AttemptNo}, Seed: seed, SourceInventoryJSON: bytes.Clone(discovery.Source), SourceInventorySHA256: discovery.SourceSHA256, Members: []cd.Member{}, AdministrativeInvocations: administrative}
	keep := false
	defer func() {
		if !keep {
			description.Clear()
		}
	}()
	parts := map[string]b.JobPart{}
	for _, p := range discovery.Parts {
		parts[p.Part] = p
	}
	for _, selection := range seed.Members {
		p := parts[selection.Part]
		packet, exists := records[selection.Part]
		if !exists {
			return zero, c.ErrExecutionRecord
		}
		var candidate FormalCandidateRecord
		var result d.ModuleResult
		var checkpoint b.Checkpoint
		var inv worker.Invocation
		if decodeProviderDeploymentJSON(p.InvocationJSON, &inv) != nil || decodeProviderDeploymentJSON(packet.candidate, &candidate) != nil || validateFormalCandidatePlan(candidate, discovery) != nil || decodeProviderDeploymentJSON(packet.result, &result) != nil || b.ValidatePartResult(in, inner, candidate.Job, packet.result) != nil || decodeProviderDeploymentJSON(result.Checkpoint, &checkpoint) != nil {
			return zero, c.ErrExecutionRecord
		}
		if candidate.Authority.InstallationID != a.InstallationID || candidate.Authority.TaskPublicID != a.TaskPublicID || candidate.Authority.AttemptNo != a.AttemptNo || candidate.Authority.ConfigVersion != a.ConfigVersion || candidate.Authority.ConfigSHA256 != a.ConfigSHA256 || candidate.Authority.Phase != "capture" || candidate.InvocationSHA256 != p.InvocationSHA256 || !worker.ValidateFormalCaptureResult(inv, &candidate.Candidate) || checkpoint.ContentSHA256 != candidate.Candidate.Ciphertext.SHA256 || checkpoint.JobUID != candidate.Job.UID || result.Status != "completed" || result.FailureCategory != "none" || result.Statistics["files"] != uint64(candidate.Candidate.Files) || result.Statistics["bytes"] != uint64(candidate.Candidate.Bytes) || result.Statistics["rows"] != uint64(candidate.Candidate.Rows) || result.Statistics["tables"] != uint64(candidate.Candidate.Tables) || result.Statistics["sealed_bytes"] != uint64(candidate.Candidate.Ciphertext.Size) {
			return zero, c.ErrExecutionRecord
		}
		if description.Scope.CaptureContextSHA256 == "" {
			description.Scope.CaptureContextSHA256 = inv.Request.Binding.CaptureContextHash
		}
		if description.Scope.CaptureContextSHA256 != inv.Request.Binding.CaptureContextHash {
			return zero, c.ErrExecutionRecord
		}
		description.Members = append(description.Members, cd.Member{Invocation: cd.Invocation{Selection: selection, JSON: bytes.Clone(p.InvocationJSON), SHA256: p.InvocationSHA256}, CandidateJSON: bytes.Clone(packet.candidate), CandidateSHA256: hash(packet.candidate), ResultSHA256: hash(packet.result)})
	}
	var carrier worker.Invocation
	if decodeProviderDeploymentJSON(administrative[0].JSON, &carrier) != nil || validateDescriptionContents(description, carrier) != nil {
		return zero, c.ErrExecutionRecord
	}
	keep = true
	return description, nil
}

func (s *DeploymentService) captureDescriptionHandler() http.Handler {
	o := s.Runtime.Owner
	return WorkloadIdentity{Client: o.Client, Namespace: o.Namespace, ServiceAccount: o.Security.ServiceAccountName, ServiceAccountUID: o.Security.ServiceAccountUID, Next: http.HandlerFunc(s.serveCaptureDescription)}
}

func (s *DeploymentService) serveCaptureDescription(out http.ResponseWriter, r *http.Request) {
	out.Header().Set("Cache-Control", "no-store")
	stage := "description-pull-dependencies"
	diagnosticCtx, diagnosticUntil := r.Context(), time.Time{}
	var err error
	deny := func() {
		logOriginalDescriptionFailure(stage, diagnosticCtx, diagnosticUntil, 0, 0, err)
		out.WriteHeader(http.StatusForbidden)
	}
	if r.Method != http.MethodPost || s == nil || !s.ForwardEnabled || s.Runtime == nil || s.Runtime.Owner == nil || s.checkProductionCaptureMaterials() != nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		deny()
		return
	}
	stage = "description-pull-peer"
	cert := r.TLS.PeerCertificates[0]
	if len(cert.URIs) != 1 || cert.URIs[0].Scheme != "spiffe" || cert.URIs[0].Host == "" {
		deny()
		return
	}
	stage = "description-pull-request"
	var request worker.ControlRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, (1<<20)+1))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.Action != "key-check" || request.Invocation.Request.Operation != cd.Operation || request.Invocation.Request.CaptureDescription == nil || request.Invocation.FormalCapture == nil || request.Invocation.ProviderKey == nil || !worker.ValidateControl(request) {
		deny()
		return
	}
	stage = "description-pull-operation"
	if _, exists := s.captureMaterials.Operations[cd.Operation]; !exists {
		deny()
		return
	}
	o := s.Runtime.Owner
	peer := cert.URIs[0].String()
	stage = "description-pull-first-control"
	first, err := o.Authorize(r.Context(), peer, request)
	defer first.Clear()
	if err != nil || first.KeyUse == nil || first.KeyUse.State != "using" || first.KeyUse.Nonce != request.Point || first.InvocationSHA256 != request.InvocationSHA256 {
		deny()
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), first.ExpiresAt)
	defer cancel()
	diagnosticCtx, diagnosticUntil = ctx, first.ExpiresAt
	stage = "description-pull-memory"
	release, err := cd.AdmitDecodeMemory(*request.Invocation.Request.CaptureDescription)
	if err != nil {
		deny()
		return
	}
	defer release()
	stage = "description-pull-first-original-read"
	raw, err := s.readOriginalDescription(ctx, request, first)
	if err != nil {
		deny()
		return
	}
	defer clear(raw)
	stage = "description-pull-final-control"
	last, err := o.Authorize(ctx, peer, request)
	defer last.Clear()
	if err != nil || last.KeyUse == nil || *last.KeyUse != *first.KeyUse || !last.ExpiresAt.Equal(first.ExpiresAt) || last.InvocationSHA256 != first.InvocationSHA256 {
		deny()
		return
	}
	stage = "description-pull-final-original-read"
	final, err := s.readOriginalDescription(ctx, request, first)
	defer clear(final)
	if err != nil || !bytes.Equal(raw, final) || s.checkProductionCaptureMaterials() != nil || ctx.Err() != nil || !time.Now().Before(first.ExpiresAt) {
		deny()
		return
	}
	_ = http.NewResponseController(out).SetWriteDeadline(first.ExpiresAt)
	out.Header().Set("Content-Type", "application/json")
	_, _ = out.Write(raw)
}

// The current original task/using key window is read and bound from SQL. This
// is not the publisher's historical-authority parsing path and cannot revive a
// completed capture. Network workload checks remain outside this short TX.
func (s *DeploymentService) descriptionAuthority(ctx context.Context, request worker.ControlRequest, lease worker.Lease) (_ d.Authority, resultErr error) {
	var zero d.Authority
	if lease.KeyUse == nil || lease.KeyUse.State != "using" || request.Invocation.ProviderKey == nil || request.Invocation.FormalCapture == nil {
		return zero, c.ErrExecutionAuthority
	}
	key := request.Invocation.ProviderKey.Request.Context
	attempt, err := strconv.ParseUint(key.AttemptNo, 10, 64)
	if err != nil {
		return zero, c.ErrExecutionAuthority
	}
	a := d.Authority{InstallationID: key.InstallationID, TaskPublicID: key.BackupPublicID, TaskType: "backup", Phase: "capture", AttemptNo: attempt, MaintenanceOwner: key.BackupPublicID}
	stage := "description-authority-transaction"
	defer func() {
		if resultErr != nil {
			cause := err
			if cause == nil {
				cause = resultErr
			}
			logOriginalDescriptionFailure(stage, ctx, lease.ExpiresAt, a.ClaimRowVersion, a.MaintenanceFencingToken, cause)
		}
	}()
	gate := s.Runtime.Owner.Gate.Authority
	tx, err := gate.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	// Preliminary locator only; Bind below acquires Gate -> Task locks and
	// independently revalidates this exact current authority in the same TX.
	stage = "description-authority-current-locator"
	err = readOriginalCaptureAuthorityLookup(ctx, tx, &a)
	if err != nil || a.ConfigSHA256 != request.Invocation.FormalCapture.SourceConfigSHA256 {
		return zero, c.ErrExecutionAuthority
	}
	stage = "description-authority-original-hash"
	authorityRaw, _ := json.Marshal(a)
	if hash(authorityRaw) != lease.KeyUse.AuthoritySHA256 {
		return zero, c.ErrExecutionAuthority
	}
	stage = "description-authority-current-bind"
	guard, err := gate.BindObserved(ctx, tx, a, logOriginalDescriptionBindDiagnostic)
	if err != nil {
		return zero, err
	}
	stage = "description-authority-original-key-row"
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT key_use_json FROM system_backup_v2_runtime_resources WHERE target_type='backup' AND task_public_id=? AND attempt_no=? AND phase='capture' AND resource_kind='Job' AND observed_uid=? AND namespace_name=? AND revoked=FALSE AND lifecycle='ready' AND create_dispatched=TRUE AND stopped_at IS NULL FOR SHARE`, a.TaskPublicID, a.AttemptNo, lease.KeyUse.Identity.JobUID, lease.KeyUse.Identity.Namespace).Scan(&raw)
	if err != nil {
		return zero, c.ErrExecutionAuthority
	}
	stage = "description-authority-original-key-binding"
	var actual worker.KeyUseLease
	if decodeProviderDeploymentJSON(raw, &actual) != nil || actual != *lease.KeyUse || actual.Identity.InvocationSHA256 != request.InvocationSHA256 || actual.Nonce != request.Point || !time.Now().Before(actual.Until) || !time.Now().Before(lease.ExpiresAt) || guard.Recheck(ctx, tx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	return a, nil
}

func (s *DeploymentService) readOriginalDescription(ctx context.Context, request worker.ControlRequest, lease worker.Lease) (_ []byte, resultErr error) {
	stage := "description-original-authority"
	a, err := s.descriptionAuthority(ctx, request, lease)
	defer func() {
		if resultErr != nil {
			cause := err
			if cause == nil {
				cause = resultErr
			}
			logOriginalDescriptionFailure(stage, ctx, lease.ExpiresAt, a.ClaimRowVersion, a.MaintenanceFencingToken, cause)
		}
	}()
	if err != nil {
		return nil, err
	}
	o := s.Runtime.Owner
	stage = "description-original-input"
	in, plan, discovery, err := o.input(ctx, a, false)
	if err != nil {
		return nil, err
	}
	defer clear(plan.CanonicalJSON)
	seed := *request.Invocation.Request.CaptureDescription
	stage = "description-original-plan"
	admin, err := descriptionPlan(seed, discovery.Parts)
	if err != nil || admin[0].SHA256 != request.InvocationSHA256 {
		return nil, c.ErrExecutionRecord
	}
	records := map[string]originalDescriptionMember{}
	defer func() {
		for _, record := range records {
			clear(record.candidate)
			clear(record.result)
		}
	}()
	parts := map[string]b.JobPart{}
	for _, p := range discovery.Parts {
		parts[p.Part] = p
	}
	stage = "description-original-members"
	for _, selection := range seed.Members {
		p := parts[selection.Part]
		var jobRaw, useRaw []byte
		var candidateSHA, resultSHA string
		if o.Gate.Authority.DB.QueryRowContext(ctx, `SELECT binding_json,key_use_json,candidate_sha256,result_sha256 FROM system_backup_v2_runtime_resources WHERE target_type='backup' AND task_public_id=? AND attempt_no=? AND phase='capture' AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND revoked=FALSE AND lifecycle='ready' AND create_dispatched=TRUE AND stopped_at IS NULL`, a.TaskPublicID, a.AttemptNo, p.Intent.Namespace, p.Intent.Name).Scan(&jobRaw, &useRaw, &candidateSHA, &resultSHA) != nil {
			return nil, c.ErrExecutionRecord
		}
		var job d.JobBinding
		var use worker.KeyUseLease
		if decodeProviderDeploymentJSON(jobRaw, &job) != nil || decodeProviderDeploymentJSON(useRaw, &use) != nil || use.State != "finished" || use.Identity.InvocationSHA256 != p.InvocationSHA256 || use.Identity.JobUID != job.UID {
			return nil, c.ErrExecutionRecord
		}
		stage = "description-original-member-candidate"
		_, candidateRaw, err := o.ReadFormalCandidateBytes(ctx, a, job, false)
		if err != nil {
			return nil, err
		}
		records[selection.Part] = originalDescriptionMember{candidate: candidateRaw}
		ref := resultEvidenceRef(a, job, resultSHA)
		stage = "description-original-member-evidence"
		registered, err := o.Evidence(ctx, a, job)
		if err != nil || registered == nil || *registered != ref || hash(candidateRaw) != candidateSHA {
			return nil, c.ErrExecutionRecord
		}
		stage = "description-original-member-result"
		resultRaw, err := o.ReadResult(ctx, a, job, ref)
		records[selection.Part] = originalDescriptionMember{candidate: candidateRaw, result: resultRaw}
		if err != nil || hash(resultRaw) != resultSHA {
			return nil, c.ErrExecutionRecord
		}
	}
	stage = "description-original-build"
	description, err := buildOriginalDescription(in, plan, discovery, seed, records)
	if err != nil {
		return nil, err
	}
	defer description.Clear()
	stage = "description-original-encode"
	raw, err := cd.Encode(description)
	if err != nil {
		return nil, err
	}
	stage = "description-original-final-authority"
	final, err := s.descriptionAuthority(ctx, request, lease)
	if err != nil || final != a || s.checkProductionCaptureMaterials() != nil {
		clear(raw)
		return nil, c.ErrExecutionAuthority
	}
	return raw, nil
}
