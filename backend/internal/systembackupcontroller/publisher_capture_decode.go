package systembackupcontroller

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	batchv1 "k8s.io/api/batch/v1"
)

// HistoricalCaptureInput contains immutable historical facts, deliberately no
// Authority/claim/fence token. The new publisher authority supplies permission.
type HistoricalCaptureInput struct {
	InstallationID, TaskPublicID, RequestID                 string
	ConfigVersion, CaptureAttemptNo, CaptureEpoch           uint64
	ConfigSHA256, ProfileID, ProfileRevision, ProfileSHA256 string
	ConfigSnapshot                                          json.RawMessage
	Backup                                                  d.BackupSpec
	Deadline                                                time.Time
}

type PublisherCaptureRecord struct {
	receipt                                             *publisherCaptureReceipt
	Input                                               HistoricalCaptureInput
	Plan                                                d.Plan
	Job                                                 d.JobBinding
	Invocation                                          worker.Invocation
	CandidateJSON                                       json.RawMessage
	CandidateSHA256, RequestSHA256, CaptureResultSHA256 string
	KeyUse                                              worker.KeyUseLease
	SealScope                                           staging.SealScope
	PartResult                                          d.ModuleResult
	ValidUntil                                          time.Time
}

type publisherCaptureCoordinates struct {
	installation, task, request, configSHA, profileSHA, captureGrantSHA, captureOwner string
	configVersion, attempt, epoch                                                     uint64
	deadline                                                                          time.Time
	config, profile                                                                   []byte
	spec                                                                              d.BackupSpec
}

// Kept local to record custody to avoid an execution->controller import cycle.
// CandidateJSON returned to the caller remains the SAME authenticated bytes.
type publisherStoredCandidate struct {
	Version                                             string                                                   `json:"schema_version"`
	Authority                                           d.Authority                                              `json:"authority"`
	Job                                                 d.JobBinding                                             `json:"job"`
	Pod                                                 struct{ Namespace, Name, UID, ServiceAccountUID string } `json:"pod"`
	InvocationSHA256, KeyUseNonce, ExecutionGrantSHA256 string
	Candidate                                           worker.FormalCaptureResult `json:"candidate"`
}

func publisherDecodeClosed(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrExecutionRecord
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrExecutionRecord
	}
	return nil
}

func publisherRecordBinding(c publisherCaptureCoordinates, kind, digest string) staging.Binding {
	return staging.Binding{BackupID: c.task, Attempt: strconv.FormatUint(c.attempt, 10), Path: c.installation + "/capture/" + kind, CaptureContextHash: c.configSHA, EnvelopeID: digest}
}

func publisherCandidateBinding(c publisherCaptureCoordinates, j d.JobBinding, digest string) staging.Binding {
	return staging.Binding{BackupID: c.task, Attempt: strconv.FormatUint(c.attempt, 10), Path: c.installation + "/capture/formal-candidate/" + j.Namespace + "/" + j.Name + "/" + j.UID + "/" + j.JobUnitKey, CaptureContextHash: c.configSHA, EnvelopeID: digest}
}

func publisherOpenRecord(ctx context.Context, sealed, key []byte, binding staging.Binding, max int64) ([]byte, error) {
	if !executionHash.MatchString(binding.EnvelopeID) || len(sealed) < 2 || int64(len(sealed)) > max+4096 || len(key) != 32 {
		return nil, ErrExecutionRecord
	}
	var plain bytes.Buffer
	defer func() { clear(plain.Bytes()) }()
	if staging.Open(ctx, bytes.NewReader(sealed), &plain, key, binding, max) != nil || recordHash(plain.Bytes()) != binding.EnvelopeID {
		return nil, ErrExecutionRecord
	}
	return bytes.Clone(plain.Bytes()), nil
}

// This initial decode selects only a readonly SQL locator from the authenticated
// encrypted plan. It grants nothing. The final decode below validates the SAME
// bytes through the original D/B parsers using the genuinely recorded candidate
// Authority, never a synthesized old claim or the current publisher claim.
func publisherBootstrapPart(planRaw []byte, wanted string) (b.JobPart, error) {
	var envelope struct {
		Version      string          `json:"schema_version"`
		Binding      json.RawMessage `json:"binding"`
		InnerVersion string          `json:"runner_plan_version"`
		InnerSHA256  string          `json:"runner_plan_sha256"`
		InnerBytes   []byte          `json:"runner_plan_bytes"`
	}
	if len(planRaw) > 8<<20 || publisherDecodeClosed(planRaw, &envelope) != nil || envelope.Version != d.TaskPlanVersion || envelope.InnerVersion != b.PlanVersion || len(envelope.InnerBytes) > 4<<20 || recordHash(envelope.InnerBytes) != envelope.InnerSHA256 {
		return b.JobPart{}, ErrExecutionRecord
	}
	var frozen struct {
		Version             string
		Binding             json.RawMessage
		LocalFlowGeneration int64
		Discovery           json.RawMessage
	}
	if publisherDecodeClosed(envelope.InnerBytes, &frozen) != nil || frozen.Version != b.PlanVersion || frozen.LocalFlowGeneration != 1 {
		return b.JobPart{}, ErrExecutionRecord
	}
	var selected b.JobPart
	count := 0
	var discovery struct {
		Source         json.RawMessage
		SourceSHA256   string
		Writers, Parts json.RawMessage
		HoldUntil      time.Time
	}
	if json.Unmarshal(frozen.Discovery, &discovery) != nil || publisherBoundedArray(discovery.Writers, 10000, nil) != nil {
		return b.JobPart{}, ErrExecutionRecord
	}
	if publisherBoundedArray(discovery.Parts, 10000, func(raw []byte) error {
		var identity struct{ Part string }
		if json.Unmarshal(raw, &identity) != nil {
			return ErrExecutionRecord
		}
		if identity.Part == wanted {
			if publisherDecodeClosed(raw, &selected) != nil {
				return ErrExecutionRecord
			}
			count++
		}
		return nil
	}) != nil {
		return b.JobPart{}, ErrExecutionRecord
	}
	if count != 1 || selected.Intent.JobUnitKey == "" || recordHash(selected.InvocationJSON) != selected.InvocationSHA256 {
		return b.JobPart{}, ErrExecutionRecord
	}
	return selected, nil
}

func publisherBoundedArray(raw []byte, max int, visit func([]byte) error) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return ErrExecutionRecord
	}
	if token == nil {
		return nil
	}
	if token != json.Delim('[') {
		return ErrExecutionRecord
	}
	count := 0
	for decoder.More() {
		count++
		if count > max {
			return ErrExecutionRecord
		}
		var item json.RawMessage
		if decoder.Decode(&item) != nil {
			return ErrExecutionRecord
		}
		if visit != nil && visit(item) != nil {
			return ErrExecutionRecord
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim(']') || decoder.Decode(new(any)) != io.EOF {
		return ErrExecutionRecord
	}
	return nil
}

func publisherValidateHistory(c publisherCaptureCoordinates, wanted string, planRaw, resultRaw, candidateRaw, keyUseRaw, requestRaw []byte, candidateSHA, requestSHA string, j d.JobBinding) (PublisherCaptureRecord, error) {
	var zero PublisherCaptureRecord
	var candidate publisherStoredCandidate
	if len(candidateRaw) > 16384 || recordHash(candidateRaw) != candidateSHA || publisherDecodeClosed(candidateRaw, &candidate) != nil || candidate.Version != "public-formal-candidate-record.v1" || candidate.Job != j {
		return zero, ErrExecutionRecord
	}
	a := candidate.Authority
	if a.InstallationID != c.installation || a.TaskPublicID != c.task || a.TaskType != "backup" || a.RequestID != c.request || a.ConfigVersion != c.configVersion || a.ConfigSHA256 != c.configSHA || a.AttemptNo != c.attempt || a.Phase != "capture" || !a.DeadlineAt.Equal(c.deadline) || a.ClaimOwner != c.captureOwner || a.ClaimRowVersion == 0 || a.MaintenanceOwner == "" || a.MaintenanceFencingToken != c.epoch || candidate.ExecutionGrantSHA256 != c.captureGrantSHA {
		return zero, ErrExecutionRecord
	}
	var profile struct {
		InstallationID string `json:"installation_id"`
		Profile        string `json:"source_profile"`
		Revision       string `json:"revision"`
	}
	decoder := json.NewDecoder(bytes.NewReader(c.profile))
	if decoder.Decode(&profile) != nil || decoder.Decode(new(any)) != io.EOF || profile.InstallationID != c.installation || profile.Profile == "" || profile.Revision == "" || recordHash(c.profile) != c.profileSHA || recordHash(c.config) != c.configSHA {
		return zero, ErrExecutionRecord
	}
	// These exact historical claim fields were encrypted in the ORIGINAL
	// candidate. They are used only by pure binding/shape parsers, never by a
	// live execution or record-key authorization call, and are not returned.
	original := d.Input{Authority: a, ConfigSnapshot: bytes.Clone(c.config), ProfileID: profile.Profile, ProfileRevision: profile.Revision, Backup: &c.spec}
	plan := d.Plan{SchemaVersion: d.TaskPlanVersion, CanonicalJSON: bytes.Clone(planRaw), SHA256: recordHash(planRaw)}
	inner, err := d.UnwrapTaskPlan(original, plan, b.PlanVersion)
	if err != nil {
		return zero, ErrExecutionRecord
	}
	defer clear(inner.CanonicalJSON)
	discovery, err := b.DescribePlan(original, inner)
	if err != nil {
		return zero, ErrExecutionRecord
	}
	var selected b.JobPart
	found := 0
	for _, part := range discovery.Parts {
		if part.Part == wanted {
			selected = part
			found++
		}
	}
	if found != 1 || selected.Intent.JobUnitKey != j.JobUnitKey || selected.Intent.Namespace != j.Namespace || selected.Intent.Name != j.Name || selected.Intent.Generation != j.Generation || selected.InvocationSHA256 != candidate.InvocationSHA256 || recordHash(selected.InvocationJSON) != candidate.InvocationSHA256 {
		return zero, ErrExecutionRecord
	}
	var invocation worker.Invocation
	if json.Unmarshal(selected.InvocationJSON, &invocation) != nil || !worker.ValidateFormalCaptureResult(invocation, &candidate.Candidate) || candidate.Candidate.InvocationSHA256 != candidate.InvocationSHA256 || invocation.Request.Binding.Path != wanted {
		return zero, ErrExecutionRecord
	}
	var object batchv1.Job
	if json.Unmarshal(selected.Intent.SpecJSON, &object) != nil {
		return zero, ErrExecutionRecord
	}
	intent, err := kube.Intent("Job", &object)
	if err != nil || intent.RequestSHA256 != requestSHA || !bytes.Equal(intent.RequestJSON, requestRaw) {
		return zero, ErrExecutionRecord
	}
	var keyUse worker.KeyUseLease
	if len(keyUseRaw) > 16384 || publisherDecodeClosed(keyUseRaw, &keyUse) != nil || keyUse.State != "finished" || invocation.ProviderKey == nil || keyUse.Access != *invocation.ProviderKey || keyUse.Nonce != candidate.KeyUseNonce || keyUse.Until.IsZero() || keyUse.Until.After(a.DeadlineAt) {
		return zero, ErrExecutionRecord
	}
	authorityRaw, err := json.Marshal(a)
	if err != nil || keyUse.AuthoritySHA256 != recordHash(authorityRaw) || keyUse.Identity.InvocationSHA256 != candidate.InvocationSHA256 || keyUse.Identity.ExecutionGrantSHA256 != candidate.ExecutionGrantSHA256 || keyUse.Identity.JobUID != j.UID || keyUse.Identity.Namespace != j.Namespace || candidate.Pod.Namespace != j.Namespace || candidate.Pod.Name == "" || candidate.Pod.UID == "" || candidate.Pod.ServiceAccountUID == "" || keyUse.Identity.PodUID != candidate.Pod.UID || keyUse.Identity.ServiceAccountUID != candidate.Pod.ServiceAccountUID {
		return zero, ErrExecutionRecord
	}
	outcome, err := decodeExecutionResult(resultRaw, plan.SHA256)
	if err != nil || outcome.Err != nil || len(outcome.Results) != len(discovery.Parts) {
		return zero, ErrExecutionRecord
	}
	selectedResult := 0
	var partResult d.ModuleResult
	sealScope := staging.SealScope{Installation: c.installation, Task: c.task, Phase: "capture", Unit: j.JobUnitKey, Namespace: j.Namespace, JobName: j.Name, JobUID: j.UID, Attempt: c.attempt, Generation: j.Generation, ConfigVersion: c.configVersion, ConfigSHA256: c.configSHA, InvocationSHA256: candidate.InvocationSHA256, Binding: invocation.Request.Binding}
	sealReference, err := publisherExpectedFormalReference(sealScope, candidate.Candidate)
	if err != nil {
		return zero, err
	}
	seen := map[string]bool{}
	for _, result := range outcome.Results {
		if result.Status != "completed" || result.FailureCategory != "none" || seen[result.Part] {
			return zero, ErrExecutionRecord
		}
		seen[result.Part] = true
		if result.Part == wanted {
			raw, err := json.Marshal(result)
			if err != nil || b.ValidatePartResult(original, inner, j, raw) != nil {
				return zero, ErrExecutionRecord
			}
			var checkpoint b.Checkpoint
			if json.Unmarshal(result.Checkpoint, &checkpoint) != nil || checkpoint.ContentSHA256 != candidate.Candidate.Ciphertext.SHA256 || checkpoint.SealedRef != sealReference || result.Statistics["files"] != uint64(candidate.Candidate.Files) || result.Statistics["bytes"] != uint64(candidate.Candidate.Bytes) || result.Statistics["rows"] != uint64(candidate.Candidate.Rows) || result.Statistics["tables"] != uint64(candidate.Candidate.Tables) || result.Statistics["sealed_bytes"] != uint64(candidate.Candidate.Ciphertext.Size) {
				return zero, ErrExecutionRecord
			}
			partResult = result
			selectedResult++
		}
	}
	if selectedResult != 1 {
		return zero, ErrExecutionRecord
	}
	input := HistoricalCaptureInput{InstallationID: c.installation, TaskPublicID: c.task, RequestID: c.request, ConfigVersion: c.configVersion, CaptureAttemptNo: c.attempt, CaptureEpoch: c.epoch, ConfigSHA256: c.configSHA, ProfileID: profile.Profile, ProfileRevision: profile.Revision, ProfileSHA256: c.profileSHA, ConfigSnapshot: bytes.Clone(c.config), Backup: c.spec, Deadline: c.deadline}
	input.Backup.RequestedParts = append([]string(nil), c.spec.RequestedParts...)
	return PublisherCaptureRecord{Input: input, Plan: plan, Job: j, Invocation: invocation, CandidateJSON: bytes.Clone(candidateRaw), CandidateSHA256: candidateSHA, RequestSHA256: requestSHA, CaptureResultSHA256: recordHash(resultRaw), KeyUse: keyUse, SealScope: sealScope, PartResult: partResult}, nil
}

func publisherExpectedFormalReference(scope staging.SealScope, candidate worker.FormalCaptureResult) (string, error) {
	cipherRef, err := staging.SealReferenceForIntent(staging.SealIntent{Schema: "controller-staging-seal-intent.v1", Scope: scope, Original: candidate.Ciphertext})
	if err != nil {
		return "", ErrExecutionRecord
	}
	scope.Unit += "/formal-envelope"
	envelopeRef, err := staging.SealReferenceForIntent(staging.SealIntent{Schema: "controller-staging-seal-intent.v1", Scope: scope, Original: candidate.Envelope})
	if err != nil {
		return "", ErrExecutionRecord
	}
	const prefix = "controller-staging-seal.v1/"
	return "controller-formal-seal.v1/" + strings.TrimPrefix(cipherRef, prefix) + "/" + strings.TrimPrefix(envelopeRef, prefix), nil
}
