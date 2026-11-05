package systembackupcontroller

import (
	"bytes"
	"context"
	"reflect"

	reg "clawreef/internal/systembackupkekregistry"
)

// The receiver is the actual independently deployed current Records.Keys.
// The original locator must come from trusted deployment, not an Invocation.
// No issuer/key directory supplied by the predecessor document is accepted.
// This authenticates signed data; it creates no task/key/config permission.
func (p *PinnedExecutionIdentity) OpenOriginalEnabledOnlyPredecessor(file, sha string) (*PinnedExecutionIdentity, error) {
	if p == nil {
		return nil, ErrExecutionAuthority
	}
	old, e := NewPinnedExecutionIdentity(file, sha, p.keyDirectory, p.public)
	if e != nil || !p.exactEnabledOnlyPredecessor(old) {
		return nil, ErrExecutionAuthority
	}
	return old, nil
}
func (p *PinnedExecutionIdentity) exactEnabledOnlyPredecessor(old *PinnedExecutionIdentity) bool {
	if p == nil || old == nil || p == old || p.digest == old.digest || !bytes.Equal(p.public, old.public) || old.grant.ConfigVersion != 1 || p.grant.ConfigVersion != 2 || old.grant.ConfigSHA256 == p.grant.ConfigSHA256 {
		return false
	}
	expected := old.grant
	expected.ConfigVersion, expected.ConfigSHA256 = p.grant.ConfigVersion, p.grant.ConfigSHA256
	return reflect.DeepEqual(expected, p.grant)
}

// Both complete original signed envelopes, original keys, database identity,
// original windows and exact all-field pairing are checked in this same view.
// No config inheritance is inferred here: caller additionally reads the real
// enabled-only SQL lineage in this exact ctx/view under its original grant.
func (p *PinnedExecutionIdentity) CheckOriginalEnabledOnlyPredecessorInView(ctx context.Context, view reg.SQLReadView, old *PinnedExecutionIdentity) error {
	if !p.exactEnabledOnlyPredecessor(old) || old.CheckDeploymentInViewWithIssuer(ctx, view, p.public) != nil || p.CheckDeploymentInViewWithIssuer(ctx, view, p.public) != nil || !p.exactEnabledOnlyPredecessor(old) {
		return ErrExecutionAuthority
	}
	return nil
}
