package install

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
)

type signingResourceSQLRows struct {
	cas                                              owner.SigningResourceCAS
	grant                                            owner.SigningResourceGrant
	head                                             owner.SigningResourceHead
	grantRaw, grantSignature, headRaw, headSignature []byte
}

// Installer-local time floor, never a Bootstrap candidate capability. The
// actual consumer retains A's guarded SampleTime and SELECT-only reader.
type signingResourceSQLView struct {
	ctx      context.Context
	tx       *sql.Tx
	operator *authenticatedOperator
	floor    time.Time
}

func (v *signingResourceSQLView) sample(ctx context.Context) (time.Time, error) {
	if v == nil || v.tx == nil || !consumerSameContext(ctx, v.ctx) || !v.operator.live(ctx) {
		return time.Time{}, ErrInstall
	}
	now, err := v.operator.installer.database(ctx, v.tx, v.operator.until)
	if err != nil || now.Before(v.floor) {
		return time.Time{}, ErrInstall
	}
	v.floor = now
	return now, nil
}

func readSigningResourceSQLRows(ctx context.Context, v *signingResourceSQLView, p owner.SigningResourceTrustPin, write bool) (*signingResourceSQLRows, bool, error) {
	if _, err := v.sample(ctx); err != nil {
		return nil, false, ErrInstall
	}
	headSQL, grantSQL := owner.SigningResourceHeadReadSQL, owner.SigningResourceGrantReadSQL
	if write {
		headSQL = strings.TrimSuffix(headSQL, " FOR SHARE") + " FOR UPDATE"
		grantSQL = strings.TrimSuffix(grantSQL, " FOR SHARE") + " FOR UPDATE"
	}
	r := &signingResourceSQLRows{}
	var epoch, revision uint64
	err := v.tx.QueryRowContext(ctx, headSQL, p.Target.InstallationID, p.EnrollmentID, p.AuthorityID, p.Purpose).Scan(&r.cas.HeadRevision, &epoch, &r.cas.GrantID, &revision, &r.cas.HeadSHA256, &r.headRaw, &r.headSignature, &r.cas.State, &r.cas.HeadRowVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, true, nil
	}
	if err != nil || r.cas.HeadRowVersion < 1 || r.cas.HeadRowVersion > 9007199254740991 || hash(r.headRaw) != r.cas.HeadSHA256 {
		return nil, false, ErrInstall
	}
	r.head, err = owner.InspectSigningResourceHead(r.headRaw, r.headSignature, p)
	if err != nil || r.head.HeadRevision != r.cas.HeadRevision || r.head.PermissionEpoch != epoch || r.head.CurrentGrantID != r.cas.GrantID || r.head.CurrentGrantRevision != revision || r.head.State != r.cas.State {
		return nil, false, ErrInstall
	}
	var state string
	if v.tx.QueryRowContext(ctx, grantSQL, p.Target.InstallationID, p.EnrollmentID, p.AuthorityID, p.Purpose, p.GrantID, p.GrantRevision).Scan(&r.cas.PermissionEpoch, &r.cas.GrantSHA256, &r.grantRaw, &r.grantSignature, &state, &r.cas.GrantRowVersion) != nil || r.cas.GrantRowVersion < 1 || r.cas.GrantRowVersion > 9007199254740991 || r.cas.PermissionEpoch != epoch || r.cas.GrantSHA256 != p.GrantSHA256 || state != r.cas.State {
		return nil, false, ErrInstall
	}
	r.grant, err = owner.InspectSigningResourceGrant(r.grantRaw, r.grantSignature, p)
	if err != nil || !r.grant.NotBefore.Equal(r.head.NotBefore) || !r.grant.Until.Equal(r.head.Until) {
		return nil, false, ErrInstall
	}
	r.cas.GrantRevision = revision
	if _, err = v.sample(ctx); err != nil {
		return nil, false, ErrInstall
	}
	return r, false, nil
}

func exactSigningResourceSQLRows(r *signingResourceSQLRows, b SigningResourceBundle, h owner.SigningResourceHead) bool {
	if r == nil || !bytes.Equal(r.grantRaw, b.Grant) || !bytes.Equal(r.grantSignature, b.GrantSignature) || !bytes.Equal(r.headRaw, b.Head) || !bytes.Equal(r.headSignature, b.HeadSignature) {
		return false
	}
	headRow, grantRow := uint64(1), uint64(1)
	if b.Action == "revoke" {
		headRow = b.Expected.HeadRowVersion + 1
		grantRow = b.Expected.GrantRowVersion + 1
	}
	return r.cas.HeadRevision == h.HeadRevision && r.cas.HeadRowVersion == headRow && r.cas.GrantRowVersion == grantRow && r.cas.GrantRevision == h.CurrentGrantRevision && r.cas.GrantID == h.CurrentGrantID && r.cas.PermissionEpoch == h.PermissionEpoch && r.cas.State == h.State && r.cas.HeadSHA256 == hash(b.Head) && r.cas.GrantSHA256 == hash(b.Grant)
}

func signingResourceSQLRevocation(r *signingResourceSQLRows, b SigningResourceBundle) error {
	if r == nil || r.cas != b.Expected || r.cas.State != "active" || r.cas.HeadRevision != 1 || r.cas.PermissionEpoch != 1 || r.cas.HeadRowVersion >= 9007199254740991 || r.cas.GrantRowVersion >= 9007199254740991 || !bytes.Equal(r.grantRaw, b.Grant) || !bytes.Equal(r.grantSignature, b.GrantSignature) {
		return ErrInstall
	}
	head := r.head
	head.HeadRevision, head.State = 2, "revoked"
	want, err := owner.EncodeSigningResourceHead(head)
	if err != nil || !bytes.Equal(want, b.Head) {
		return ErrInstall
	}
	return nil
}
