package systembackupcontroller

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"

	security "clawreef/internal/systembackupsecurity"
)

// PublisherCaptureParts returns bounded lookup locators from the original
// encrypted plan. It grants no part permission: every locator must still pass
// LoadPublisherCapture under the SAME real publisher claim before use.
func (s SQLExecutionRecords) PublisherCaptureParts(ctx context.Context, access *security.SQLPublisherCaptureAuthority) ([]string, error) {
	if !s.ready() || ctx == nil || access == nil || access.Check(ctx) != nil {
		return nil, ErrExecutionAuthority
	}
	identity, ok := s.Keys.(*PinnedExecutionIdentity)
	if !ok || identity == nil {
		return nil, ErrExecutionAuthority
	}
	binding, ok := s.Authority.Authorization.(PublisherCaptureCustodyBinding)
	if !ok {
		return nil, ErrExecutionAuthority
	}
	deployment := access.Deployment()
	if s.Authority.InstallationID != deployment.InstallationID || publisherIdentityMatches(identity, deployment) != nil || binding.CheckPublisherCaptureCustody(ctx, deployment) != nil || identity.CheckDeployment(ctx, s.Authority.DB) != nil {
		return nil, ErrExecutionAuthority
	}
	first, err := s.publisherReadSnapshot(ctx, access, nil)
	if err != nil {
		return nil, err
	}
	key, err := publisherReadRecordKey(identity, first.Plan.Ref)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	raw, err := publisherOpenRecord(ctx, first.Plan.Cipher, key, publisherRecordBinding(first.Coordinates, "plan", first.Plan.Digest), 8<<20)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var envelope struct {
		Version      string          `json:"schema_version"`
		Binding      json.RawMessage `json:"binding"`
		InnerVersion string          `json:"runner_plan_version"`
		InnerSHA256  string          `json:"runner_plan_sha256"`
		InnerBytes   []byte          `json:"runner_plan_bytes"`
	}
	if publisherDecodeClosed(raw, &envelope) != nil || recordHash(envelope.InnerBytes) != envelope.InnerSHA256 {
		return nil, ErrExecutionRecord
	}
	var frozen struct {
		Version             string
		Binding             json.RawMessage
		LocalFlowGeneration int64
		Discovery           json.RawMessage
	}
	if publisherDecodeClosed(envelope.InnerBytes, &frozen) != nil {
		return nil, ErrExecutionRecord
	}
	var discovery struct{ Parts json.RawMessage }
	if json.Unmarshal(frozen.Discovery, &discovery) != nil {
		return nil, ErrExecutionRecord
	}
	seen := map[string]bool{}
	var parts []string
	if publisherBoundedArray(discovery.Parts, 10000, func(raw []byte) error {
		var item struct{ Part string }
		if json.Unmarshal(raw, &item) != nil || item.Part == "" || len(item.Part) > 128 || seen[item.Part] {
			return ErrExecutionRecord
		}
		seen[item.Part] = true
		parts = append(parts, item.Part)
		return nil
	}) != nil || len(parts) == 0 {
		return nil, ErrExecutionRecord
	}
	// Reuse the exact closed plan parser for every selected locator. This checks
	// the original envelope versions and invocation hashes, without synthesizing
	// the historical capture authority.
	for _, part := range parts {
		if _, err := publisherBootstrapPart(raw, part); err != nil {
			return nil, err
		}
	}
	second, err := s.publisherReadSnapshot(ctx, access, nil)
	if err != nil || !publisherSameBase(first, second) || binding.CheckPublisherCaptureCustody(ctx, deployment) != nil || access.Check(ctx) != nil {
		return nil, ErrExecutionAuthority
	}
	if binding.CheckPublisherCaptureCustody(ctx, deployment) != nil || identity.CheckDeployment(ctx, s.Authority.DB) != nil {
		return nil, ErrExecutionAuthority
	}
	// No external I/O may follow this last original-byte snapshot. A final
	// workload GET can change the plan/keyref/profile after the preceding read.
	last, err := s.publisherReadSnapshot(ctx, access, nil)
	if err != nil || !publisherSameBase(first, last) {
		return nil, ErrExecutionRecord
	}
	sort.Strings(parts)
	return parts, nil
}

// Detached returns an independent view of authenticated history. The opaque
// receipt stays attached and still rejects any changed byte at RecheckTx.
func (record PublisherCaptureRecord) Detached() (PublisherCaptureRecord, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return PublisherCaptureRecord{}, ErrExecutionRecord
	}
	defer clear(raw)
	var out PublisherCaptureRecord
	if json.Unmarshal(raw, &out) != nil {
		return PublisherCaptureRecord{}, ErrExecutionRecord
	}
	out.Input.ConfigSnapshot = bytes.Clone(record.Input.ConfigSnapshot)
	out.Input.SourceSnapshot = bytes.Clone(record.Input.SourceSnapshot)
	out.Plan.CanonicalJSON = bytes.Clone(record.Plan.CanonicalJSON)
	out.CandidateJSON = bytes.Clone(record.CandidateJSON)
	out.PartResult.Checkpoint = bytes.Clone(record.PartResult.Checkpoint)
	out.receipt = record.receipt
	if publisherCaptureRecordHash(out) != publisherCaptureRecordHash(record) {
		return PublisherCaptureRecord{}, ErrExecutionRecord
	}
	return out, nil
}
