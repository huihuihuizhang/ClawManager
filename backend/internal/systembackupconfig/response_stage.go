package systembackupconfig

import (
	"bytes"
	"context"
	"database/sql"
	"time"

	ev "clawreef/internal/systembackupevidence"
	sec "clawreef/internal/systembackupsecurity"
)

// The publication owner must supply current authority/retention/pending-intent
// admission for the exact original ciphertext and immutable object. This check
// is local/SQL only and cannot publish, perform network I/O or commit. No JSON
// success flag, plain Ref or read grant can substitute for it.
type ConfigMutationResponsePublicationGuard interface {
	ValidUntil() time.Time
	Recheck(context.Context, *sql.Tx, time.Time) error
}
type preparedConfigMutationEvidenceResponse struct {
	content           ConfigMutationResponseContent
	prepared          ev.Prepared
	ref               ev.Ref
	guard             ConfigMutationResponsePublicationGuard
	guardUntil, until time.Time
	stageID           int64
	stageTx           *sql.Tx
}

func PrepareInlineConfigMutationResponse(c ConfigMutationResponseContent) (sec.PreparedConfigMutationResponse, error) {
	if len(c.payload) < 2 || len(c.payload) > 8192 || !validDatabase(c.database) || c.until.IsZero() {
		return nil, sec.ErrRegistrationUnavailable
	}
	return &preparedConfigMutationEvidenceResponse{content: c, until: c.until}, nil
}
func PreparePublishedConfigMutationResponse(c ConfigMutationResponseContent, p ev.Prepared, ref ev.Ref, g ConfigMutationResponsePublicationGuard) (sec.PreparedConfigMutationResponse, error) {
	m := p.Manifest()
	if len(c.payload) <= 8192 || len(c.payload) > configMutationResponseMaxBytes || m.Identity != c.identity || m.Key != c.kek || isNil(g) {
		return nil, sec.ErrRegistrationUnavailable
	}
	guardUntil := g.ValidUntil()
	until := c.until
	if guardUntil.Before(until) {
		until = guardUntil
	}
	if guardUntil.IsZero() || !time.Now().Before(until) {
		return nil, sec.ErrRegistrationUnavailable
	}
	return &preparedConfigMutationEvidenceResponse{content: c, prepared: p, ref: ref, guard: g, guardUntil: guardUntil, until: until}, nil
}
func (p *preparedConfigMutationEvidenceResponse) ValidUntil() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.until
}
func (p *preparedConfigMutationEvidenceResponse) checkPublication(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if p == nil || ctx == nil || ctx.Err() != nil || tx == nil || now.IsZero() || !now.Before(p.until) {
		return sec.ErrRegistrationUnavailable
	}
	if p.guard != nil && (p.guard.Recheck(ctx, tx, now) != nil || !p.guard.ValidUntil().Equal(p.guardUntil)) {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
func (p *preparedConfigMutationEvidenceResponse) Stage(ctx context.Context, tx *sql.Tx, now time.Time) (int64, error) {
	if p == nil || p.stageID != 0 || p.checkPublication(ctx, tx, now) != nil {
		return 0, sec.ErrRegistrationUnavailable
	}
	var id int64
	var err error
	if p.guard == nil {
		id, err = p.content.StageInline(ctx, tx, now)
	} else {
		id, err = p.content.BindPublished(ctx, tx, p.prepared, p.ref, now)
	}
	if err != nil {
		return 0, err
	}
	p.stageID, p.stageTx = id, tx
	return id, nil
}
func (p *preparedConfigMutationEvidenceResponse) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if p == nil || p.stageID < 1 || p.stageTx != tx || p.checkPublication(ctx, tx, now) != nil {
		return sec.ErrRegistrationUnavailable
	}
	if p.guard != nil {
		id, err := p.content.BindPublished(ctx, tx, p.prepared, p.ref, now)
		if err != nil || id != p.stageID {
			return sec.ErrRegistrationUnavailable
		}
		return nil
	}
	c := p.content
	if checkDatabase(ctx, tx, c.database) != nil {
		return sec.ErrRegistrationUnavailable
	}
	var id, size int64
	var schema, ownerType, owner, kind, state, failure, health, checksum, media, encryption, classification string
	var raw []byte
	var expiry, created time.Time
	err := tx.QueryRowContext(ctx, `SELECT id,schema_version,owner_target_type,owner_target_public_id,evidence_type,storage_state,evidence_failure_code,observed_health,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,expires_at,created_at FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE`, c.identity.ID).Scan(&id, &schema, &ownerType, &owner, &kind, &state, &failure, &health, &raw, &checksum, &size, &media, &encryption, &classification, &expiry, &created)
	if err != nil || id != p.stageID || schema != "system-backup-evidence.v1" || ownerType != "system" || owner != c.identity.Installation || kind != "diagnostic" || state != "inline" || failure != "none" || health != "healthy" || !bytes.Equal(raw, c.payload) || checksum != c.identity.ContentHash || size != int64(len(c.payload)) || media != "application/json" || encryption != "none" || classification != "internal" || expiry.Before(c.retain) || !created.Equal(c.created) || ctx.Err() != nil {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
