package systembackupevidence

import (
	"context"
	"encoding/json"
	"io"
	"time"
)

// ContentAuthority is an internal trust boundary, NOT a parser of caller
// assertions. Implementations must authenticate the live producer and check
// installation/task/attempt/claim/config/revocation in authoritative state.
// The requested identity is only a lookup/binding input, never authority.
// SQLTaskAuthority supplies the task job-log path; system capability producers
// still require their own authority and reviewed policy.
type ContentAuthority interface {
	AuthorizeContent(context.Context, Identity) (ContentAuthorization, error)
}

type ContentAuthorization struct {
	Identity             Identity
	ProducerIdentityHash string
	ValidUntil           time.Time
	Capability           *CapabilityContentPolicy
	JobLog               *JobLogPolicy
	ConfigResponse       *ConfigResponseContentPolicy
}

// ContentDispatcher allows only the implemented body profiles. A second live
// authorization after reading catches revocation/policy replacement while the
// body was read. D must still recheck its SQL transaction and write deadline.
type ContentDispatcher struct{ authority ContentAuthority }

func NewContentDispatcher(a ContentAuthority) (*ContentDispatcher, error) {
	if nilSystemAdapter(a) {
		return nil, ErrRedaction
	}
	return &ContentDispatcher{authority: a}, nil
}

func contentValidator(a ContentAuthorization, i Identity) (Redactor, string, error) {
	if a.Identity != i || !digestPattern.MatchString(a.ProducerIdentityHash) || !time.Now().Before(a.ValidUntil) {
		return nil, "", ErrRedaction
	}
	switch i.Type {
	case "capability_snapshot":
		if a.Capability == nil || a.JobLog != nil || a.ConfigResponse != nil {
			return nil, "", ErrRedaction
		}
		v, err := NewCapabilityRedactor(*a.Capability)
		if err != nil {
			return nil, "", ErrRedaction
		}
		return v, hash(canonical(v.policy)), nil
	case "job_log_chunk":
		if a.JobLog == nil || a.Capability != nil || a.ConfigResponse != nil {
			return nil, "", ErrRedaction
		}
		v, err := NewJobLogRedactor(*a.JobLog)
		if err != nil {
			return nil, "", ErrRedaction
		}
		return v, logPolicyHash(v.policy), nil
	case "diagnostic":
		if a.ConfigResponse == nil || a.Capability != nil || a.JobLog != nil {
			return nil, "", ErrRedaction
		}
		v, err := NewConfigResponseRedactor(*a.ConfigResponse)
		if err != nil {
			return nil, "", ErrRedaction
		}
		return v, v.policyHash(), nil
	default:
		return nil, "", ErrRedaction
	}
}

func logPolicyHash(p JobLogPolicy) string {
	raw, _ := json.Marshal(p)
	return hash(raw)
}

func (d *ContentDispatcher) Validate(ctx context.Context, i Identity, src io.Reader) error {
	if d == nil || nilSystemAdapter(d.authority) || nilSystemAdapter(src) || ctx == nil || ctx.Err() != nil || !i.validExternal() || !oneOf(i.Type, "capability_snapshot", "job_log_chunk", "diagnostic") {
		return ErrRedaction
	}
	before, err := d.authority.AuthorizeContent(ctx, i)
	if err != nil {
		return ErrRedaction
	}
	v, policyHash, err := contentValidator(before, i)
	if err != nil || v.Validate(ctx, i, src) != nil || ctx.Err() != nil {
		return ErrRedaction
	}
	after, err := d.authority.AuthorizeContent(ctx, i)
	if err != nil {
		return ErrRedaction
	}
	_, nextHash, err := contentValidator(after, i)
	if err != nil || before.ProducerIdentityHash != after.ProducerIdentityHash || policyHash != nextHash ||
		!time.Now().Before(before.ValidUntil) || ctx.Err() != nil {
		return ErrRedaction
	}
	return nil
}
