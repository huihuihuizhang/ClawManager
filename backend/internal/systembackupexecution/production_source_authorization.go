package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
	sec "clawreef/internal/systembackupsecurity"
)

// A private in-process comparison pin, produced only after the real source
// freeze and the current task's original SQL bind. It is not serialized into
// source metadata, an independently usable authority or a readiness cache.
type originalFrozenSourceAuthorization struct {
	origin                *originalFrozenSourceAuthorization
	binding               *productionSourceBinding
	ctx                   context.Context
	key, authorizationSHA string
	until                 time.Time
}

func originalSourceAuthorizationKey(in d.Input, source b.SourceInventory) (string, error) {
	raw, err := json.Marshal(struct {
		Authority   d.Authority
		MetadataSHA string
	}{in.Authority, hash(source.CaptureMetadata)})
	if err != nil || len(source.CaptureMetadata) == 0 || len(source.CaptureMetadata) > 8<<20 {
		return "", d.ErrNotReady
	}
	return hash(raw), nil
}

func (p *originalFrozenSourceAuthorization) matches(in d.Input, source b.SourceInventory) bool {
	if p == nil || p.origin != p || p.binding == nil || !p.binding.matchesCapturePlan() || p.ctx == nil || p.ctx.Err() != nil || !time.Now().Before(p.until) || !formalCandidateDigest(p.authorizationSHA) {
		return false
	}
	key, err := originalSourceAuthorizationKey(in, source)
	return err == nil && key == p.key
}

// All reads use the very same actual SQL view as the current task authority.
// No SDK string, frozen metadata JSON, caller Passed or old observation alone
// can turn configuration succession into a permission to capture.
func (s *DeploymentService) readOriginalSourceAuthorization(ctx context.Context, owner *PublicJobOwner, in d.Input, originalSHA string) (string, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || owner == nil || owner.Gate.Authority.DB == nil || in.Authority.InstallationID != s.Config.InstallationID || in.Authority.TaskType != "backup" || in.Authority.Phase != "capture" || !formalCandidateDigest(originalSHA) || !formalCandidateDigest(in.Authority.ConfigSHA256) || hash(in.ConfigSnapshot) != in.Authority.ConfigSHA256 {
		return "", d.ErrNotReady
	}
	gate := owner.Gate.Authority
	tx, err := gate.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return "", d.ErrNotReady
	}
	defer tx.Rollback()
	guard, err := gate.Bind(ctx, tx, in.Authority)
	if err != nil {
		return "", err
	}
	if originalSHA != in.Authority.ConfigSHA256 {
		proof, err := sec.ReadOriginalEnabledOnlyLineage(ctx, tx, in.Authority.InstallationID, originalSHA, in.Authority.ConfigVersion, in.Authority.ConfigSHA256)
		if err != nil || !proof.Matches(in.Authority.InstallationID, originalSHA, in.Authority.ConfigVersion, in.Authority.ConfigSHA256) {
			return "", d.ErrNotReady
		}
		actual, err := proof.AuthorizationConfigSHA256(ctx, tx)
		if err != nil || actual != originalSHA {
			return "", d.ErrNotReady
		}
	}
	if guard.Recheck(ctx, tx) != nil || ctx.Err() != nil || tx.Rollback() != nil {
		return "", d.ErrNotReady
	}
	return originalSHA, nil
}

func (x *productionSourceBinding) rememberOriginalSourceAuthorization(ctx context.Context, in d.Input, metadata []byte, authority *originalSourceMetadataAuthority) error {
	if !x.matchesCapturePlan() || authority == nil || authority.service != x.service || authority.owner != x.owner || authority.input.Authority != in.Authority || authority.Recheck(ctx) != nil {
		return d.ErrNotReady
	}
	authorizationSHA, err := x.service.readOriginalSourceAuthorization(ctx, x.owner, in, authority.grant.ConfigSHA256)
	if err != nil {
		return err
	}
	source := b.SourceInventory{CaptureMetadata: metadata}
	key, err := originalSourceAuthorizationKey(in, source)
	if err != nil || ctx.Err() != nil || !time.Now().Before(authority.until) {
		return d.ErrNotReady
	}
	p := &originalFrozenSourceAuthorization{binding: x, ctx: ctx, key: key, authorizationSHA: authorizationSHA, until: authority.until}
	p.origin = p
	x.authorizationMu.Lock()
	if x.authorizations == nil {
		x.authorizations = make(map[string]*originalFrozenSourceAuthorization)
	}
	for key, old := range x.authorizations {
		if old.ctx.Err() != nil || !time.Now().Before(old.until) {
			delete(x.authorizations, key)
		}
	}
	if len(x.authorizations) >= 64 && x.authorizations[key] == nil {
		x.authorizationMu.Unlock()
		return d.ErrNotReady
	}
	x.authorizations[key] = p
	x.authorizationMu.Unlock()
	context.AfterFunc(ctx, func() {
		x.authorizationMu.Lock()
		defer x.authorizationMu.Unlock()
		if x.authorizations[key] == p {
			delete(x.authorizations, key)
		}
	})
	return nil
}

func (x *productionSourceBinding) frozenSourceAuthorization(in d.Input, source b.SourceInventory) (*originalFrozenSourceAuthorization, error) {
	if !x.matchesCapturePlan() {
		return nil, d.ErrNotReady
	}
	key, err := originalSourceAuthorizationKey(in, source)
	if err != nil {
		return nil, err
	}
	x.authorizationMu.Lock()
	p := x.authorizations[key]
	x.authorizationMu.Unlock()
	if p == nil {
		// The original pure factory remains usable with current-config grants.
		// Absence grants no compatibility: no old authorization pin is emitted.
		return nil, nil
	}
	if !p.matches(in, source) {
		return nil, d.ErrNotReady
	}
	return p, nil
}

// Finalization precedes the CE Job. It therefore obtains its own real current
// SQL/source-authority proof, rather than accepting an invocation supplied by a
// future worker. Only the static grant comparison is projected to v1; the CE
// locator/payload and all task/key-use checks remain v2.
func (s *DeploymentService) originalControllerControlSourceExpected(ctx context.Context, in d.Input, seed ce.CaptureLocator) (ce.Expected, error) {
	if s == nil || s.Runtime == nil || s.Runtime.Owner == nil || seed.Validate() != nil || seed.Expected.Installation != in.Authority.InstallationID || seed.Expected.Backup != in.Authority.TaskPublicID || seed.Expected.Attempt != in.Authority.AttemptNo || seed.Expected.ConfigSHA256 != in.Authority.ConfigSHA256 {
		return ce.Expected{}, d.ErrNotReady
	}
	authority, err := s.sourceMetadataAuthority(ctx, s.Runtime.Owner, in)
	if err != nil {
		return ce.Expected{}, err
	}
	sha, err := s.readOriginalSourceAuthorization(ctx, s.Runtime.Owner, in, authority.grant.ConfigSHA256)
	if err != nil {
		return ce.Expected{}, err
	}
	expected := seed.Expected
	expected.ConfigSHA256 = sha
	return expected, nil
}
