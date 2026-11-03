package install

import (
	"bytes"
	"context"
	"database/sql"
	"sort"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
)

// Already signed original transport DATA, never a native observation or
// executable owner. One or both purposes may be applied atomically.
type SigningResourceSQLInput struct {
	Pin    owner.SigningResourceTrustPin
	Bundle []byte
	SHA256 string
}

type SigningResourceSQLItemReceipt struct {
	Purpose, AuthorityID string
	Comparison           owner.SigningResourceCAS
	Replayed             bool
}
type SigningResourceSQLReceipt struct {
	Version string
	Items   []SigningResourceSQLItemReceipt
}
type signingResourceSQLChange struct {
	input  SigningResourceSQLInput
	bundle SigningResourceBundle
	grant  owner.SigningResourceGrant
	head   owner.SigningResourceHead
}

func signingResourceSQLChanges(ctx context.Context, s *authenticatedOperator, enrollment EnrollmentPin, inputs []SigningResourceSQLInput) ([]signingResourceSQLChange, error) {
	if s == nil || !s.live(ctx) || len(inputs) < 1 || len(inputs) > 2 {
		return nil, ErrInstall
	}
	changes := make([]signingResourceSQLChange, 0, len(inputs))
	seen := map[string]bool{}
	for _, input := range inputs {
		input.Pin.Issuer = bytes.Clone(input.Pin.Issuer)
		input.Bundle = bytes.Clone(input.Bundle)
		if seen[input.Pin.Purpose] || owner.SigningResourceBootstrapPurpose(input.Pin.Purpose) == "" || s.signingResourcePin(ctx, enrollment, input.Pin) != nil {
			return nil, ErrInstall
		}
		seen[input.Pin.Purpose] = true
		b, g, h, err := signingResourceBundle(input.Bundle, input.SHA256, input.Pin)
		if err != nil || b.PlanSHA256 != s.installer.planHash || b.EnrollmentDocumentSHA256 != enrollment.DocumentSHA256 || g.Actor.UserID != s.userID {
			return nil, ErrInstall
		}
		changes = append(changes, signingResourceSQLChange{input: input, bundle: b, grant: g, head: h})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].input.Pin.Purpose < changes[j].input.Pin.Purpose })
	return changes, nil
}

// ImportSigningResourceSQLAuthority takes no signing key, native callback,
// capture authority or future task. Every supplied purpose is one atomic
// metadata transition under admin -> acceptance head/grant -> catalog head/grant.
func (i *Installer) ImportSigningResourceSQLAuthority(ctx context.Context, password []byte, enrollment EnrollmentPin, inputs []SigningResourceSQLInput) (SigningResourceSQLReceipt, error) {
	var zero SigningResourceSQLReceipt
	s, err := i.authenticate(ctx, password)
	if err != nil {
		return zero, ErrInstall
	}
	changes, err := signingResourceSQLChanges(ctx, s, enrollment, inputs)
	if err != nil {
		return zero, ErrInstall
	}
	tx, err := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, ErrInstall
	}
	defer tx.Rollback()
	now, err := s.lockAdmin(ctx, tx)
	if err != nil {
		return zero, ErrInstall
	}
	v := &signingResourceSQLView{ctx: ctx, tx: tx, operator: s, floor: now}
	previous := make([]*signingResourceSQLRows, len(changes))
	replayed := make([]bool, len(changes))
	// Acquire ALL selected purpose row/gap locks in fixed order before writes.
	for n, change := range changes {
		r, absent, err := readSigningResourceSQLRows(ctx, v, change.input.Pin, true)
		if err != nil {
			return zero, ErrInstall
		}
		previous[n] = r
		if !absent && exactSigningResourceSQLRows(r, change.bundle, change.head) {
			replayed[n] = true
			continue
		}
		if change.bundle.Action == "install" {
			if !absent {
				return zero, ErrInstall
			}
		} else if absent || signingResourceSQLRevocation(r, change.bundle) != nil {
			return zero, ErrInstall
		}
	}
	for n, change := range changes {
		if change.bundle.Action == "install" && (v.floor.Before(change.grant.NotBefore) || !v.floor.Before(change.grant.Until)) {
			return zero, ErrInstall
		}
		if replayed[n] {
			continue
		}
		if writeSigningResourceSQLChange(ctx, tx, change, previous[n]) != nil {
			return zero, ErrInstall
		}
	}
	for _, change := range changes {
		r, absent, err := readSigningResourceSQLRows(ctx, v, change.input.Pin, true)
		if err != nil || absent || !exactSigningResourceSQLRows(r, change.bundle, change.head) {
			return zero, ErrInstall
		}
	}
	now, err = s.lockAdmin(ctx, tx)
	if err != nil || now.Before(v.floor) {
		return zero, ErrInstall
	}
	for _, change := range changes {
		if change.bundle.Action == "install" && (now.Before(change.grant.NotBefore) || !now.Before(change.grant.Until)) {
			return zero, ErrInstall
		}
	}
	if tx.Commit() != nil {
		return zero, ErrCommitUnknown
	}
	// Once commit is attempted, no failure can be reported as an uncommitted
	// retry. Resolve only this exact original bundle, never repair/re-sign.
	if _, err = readCommittedSigningResourceSQL(ctx, s, changes, now, false); err != nil {
		return zero, ErrCommitUnknown
	}
	for _, change := range changes {
		if s.signingResourcePin(ctx, enrollment, change.input.Pin) != nil {
			return zero, ErrCommitUnknown
		}
	}
	rows, err := readCommittedSigningResourceSQL(ctx, s, changes, now, true)
	if err != nil {
		return zero, ErrCommitUnknown
	}
	return signingResourceSQLReceipt(changes, rows, replayed), nil
}

// Resolve is metadata readback only: exact raw/state/version tuple, original
// authenticated owner and ordered shared locks. It never writes or probes a
// provider. An expired active tuple is data, not usable resource permission;
// the actual consumer always calls RequireCurrent for fresh AND historical use.
func (i *Installer) ResolveSigningResourceSQLAuthority(ctx context.Context, password []byte, enrollment EnrollmentPin, inputs []SigningResourceSQLInput) (SigningResourceSQLReceipt, error) {
	var zero SigningResourceSQLReceipt
	s, err := i.authenticate(ctx, password)
	if err != nil {
		return zero, ErrInstall
	}
	changes, err := signingResourceSQLChanges(ctx, s, enrollment, inputs)
	if err != nil {
		return zero, ErrInstall
	}
	rows, err := readCommittedSigningResourceSQL(ctx, s, changes, s.sqlTime, false)
	if err != nil {
		return zero, ErrInstall
	}
	flags := make([]bool, len(changes))
	for n := range flags {
		flags[n] = true
	}
	return signingResourceSQLReceipt(changes, rows, flags), nil
}

func readCommittedSigningResourceSQL(ctx context.Context, s *authenticatedOperator, changes []signingResourceSQLChange, floor time.Time, requireInstallWindow bool) ([]*signingResourceSQLRows, error) {
	tx, err := s.installer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, ErrInstall
	}
	defer tx.Rollback()
	now, err := s.lockAdmin(ctx, tx)
	if err != nil || now.Before(floor) {
		return nil, ErrInstall
	}
	v := &signingResourceSQLView{ctx: ctx, tx: tx, operator: s, floor: now}
	rows := make([]*signingResourceSQLRows, 0, len(changes))
	for _, change := range changes {
		r, absent, err := readSigningResourceSQLRows(ctx, v, change.input.Pin, false)
		if err != nil || absent || !exactSigningResourceSQLRows(r, change.bundle, change.head) {
			return nil, ErrInstall
		}
		rows = append(rows, r)
	}
	now, err = s.lockAdmin(ctx, tx)
	if err != nil || now.Before(v.floor) {
		return nil, ErrInstall
	}
	for _, change := range changes {
		if requireInstallWindow && change.bundle.Action == "install" && (now.Before(change.grant.NotBefore) || !now.Before(change.grant.Until)) {
			return nil, ErrInstall
		}
	}
	return rows, nil
}

func signingResourceSQLReceipt(changes []signingResourceSQLChange, rows []*signingResourceSQLRows, replayed []bool) SigningResourceSQLReceipt {
	result := SigningResourceSQLReceipt{Version: "original-signing-resource-sql-metadata-receipt.v1", Items: []SigningResourceSQLItemReceipt{}}
	for n, change := range changes {
		result.Items = append(result.Items, SigningResourceSQLItemReceipt{Purpose: change.input.Pin.Purpose, AuthorityID: change.input.Pin.AuthorityID, Comparison: rows[n].cas, Replayed: replayed[n]})
	}
	return result
}

func writeSigningResourceSQLChange(ctx context.Context, tx *sql.Tx, change signingResourceSQLChange, previous *signingResourceSQLRows) error {
	p, b, g, h := change.input.Pin, change.bundle, change.grant, change.head
	if b.Action == "install" {
		if one(tx.ExecContext(ctx, `INSERT INTO system_backup_signing_resource_heads(installation_id,enrollment_id,authority_id,purpose,head_revision,permission_epoch,current_grant_id,current_grant_revision,head_sha256,signed_head,signature,head_state,row_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,'active',1)`, p.Target.InstallationID, p.EnrollmentID, p.AuthorityID, p.Purpose, h.HeadRevision, h.PermissionEpoch, h.CurrentGrantID, h.CurrentGrantRevision, hash(b.Head), b.Head, b.HeadSignature)) != nil {
			return ErrInstall
		}
		return one(tx.ExecContext(ctx, `INSERT INTO system_backup_signing_resource_grants(installation_id,enrollment_id,authority_id,purpose,grant_id,record_revision,permission_epoch,record_sha256,signed_record,signature,grant_state,row_version) VALUES(?,?,?,?,?,?,?,?,?,?,'active',1)`, p.Target.InstallationID, p.EnrollmentID, p.AuthorityID, p.Purpose, g.GrantID, g.RecordRevision, g.PermissionEpoch, hash(b.Grant), b.Grant, b.GrantSignature))
	}
	if signingResourceSQLRevocation(previous, b) != nil {
		return ErrInstall
	}
	e := b.Expected
	if one(tx.ExecContext(ctx, `UPDATE system_backup_signing_resource_heads SET head_revision=2,head_sha256=?,signed_head=?,signature=?,head_state='revoked',row_version=row_version+1,updated_at=UTC_TIMESTAMP(6) WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND purpose=? AND head_revision=? AND permission_epoch=? AND current_grant_id=? AND current_grant_revision=? AND head_sha256=? AND row_version=? AND head_state='active' AND signed_head=? AND signature=?`, hash(b.Head), b.Head, b.HeadSignature, p.Target.InstallationID, p.EnrollmentID, p.AuthorityID, p.Purpose, e.HeadRevision, e.PermissionEpoch, e.GrantID, e.GrantRevision, e.HeadSHA256, e.HeadRowVersion, previous.headRaw, previous.headSignature)) != nil {
		return ErrInstall
	}
	return one(tx.ExecContext(ctx, `UPDATE system_backup_signing_resource_grants SET grant_state='revoked',row_version=row_version+1 WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND purpose=? AND grant_id=? AND record_revision=? AND permission_epoch=? AND record_sha256=? AND row_version=? AND grant_state='active' AND signed_record=? AND signature=?`, p.Target.InstallationID, p.EnrollmentID, p.AuthorityID, p.Purpose, e.GrantID, e.GrantRevision, e.PermissionEpoch, e.GrantSHA256, e.GrantRowVersion, b.Grant, b.GrantSignature))
}
