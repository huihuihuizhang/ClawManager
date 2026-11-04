package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"

	ma "clawreef/internal/systembackupminioauthority"
)

// SEALED signing bridge. Only an actual install-package whole-cold recovery
// object can implement it; callers cannot supply a DTO, digest or Passed flag.
// D1 must retain BEFORE-cold Resources and genuine original B request/response,
// context/window/operation/reservation/inventory and actual archive readback.
type OriginalMinIORecoverySource interface {
	originalMinIORecoveryTransition(context.Context, *Installer, EnrollmentPin, ma.MinIORecoveryDescriptor, *ma.SQLCurrentSnapshot) (ma.MinIORecoveryTransition, error)
	recheckOriginalMinIORecoveryTransition(context.Context, ma.MinIORecoveryTransition) error
}

type OriginalMinIORecoveryProjectionReceipt struct {
	Version, State string
	Projection     BootstrapSourceFilePin
}

func (i *Installer) IssueOriginalMinIORecoveryProjection(ctx context.Context, password []byte, enrollment EnrollmentPin, descriptor BootstrapSourceFilePin, source OriginalMinIORecoverySource, issuerPrivate []byte) (OriginalMinIORecoveryProjectionReceipt, error) {
	var zero OriginalMinIORecoveryProjectionReceipt
	if source == nil || reflect.ValueOf(source).Kind() == reflect.Pointer && reflect.ValueOf(source).IsNil() {
		return zero, ErrInstall
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(descriptor, 65536)
	if e != nil {
		return zero, ErrInstall
	}
	d, e := ma.DecodeMinIORecoveryDescriptor(raw)
	if e != nil || op.minioSQLPin(ctx, enrollment, d.Pin) != nil {
		return zero, ErrInstall
	}
	if _, e = os.Lstat(d.ProjectionFile); !os.IsNotExist(e) {
		return zero, ErrCommitUnknown
	} // query existing bytes; NEVER re-sign
	head, now, e := originalAdoptionAuthoritySnapshot(ctx, op)
	if e != nil || head.cas.HeadRevision != 1 || head.cas.State != "active" || now.Before(head.head.NotBefore) || !now.Before(head.head.Until) || now.Before(head.record.NotBefore) || !now.Before(head.record.Until) {
		return zero, ErrInstall
	}
	current, e := readOriginalMinIORecoverySQL(ctx, op, d.Pin)
	if e != nil {
		return zero, ErrInstall
	}
	g, h, _, e := current.Declarations()
	expected, signedAt, ce := current.Comparison()
	if e != nil || ce != nil || current.RequireCurrent(signedAt) != nil || !minioSQLActor(op, g) || g.Actor != d.Actor || string(g.ConfigSHA256) != head.record.ConfigSHA256 || g.Observation.DefinitionSHA256 != d.DefinitionSHA256 {
		return zero, ErrInstall
	}
	transition, e := source.originalMinIORecoveryTransition(ctx, i, enrollment, d, current)
	if e != nil || ma.ValidateMinIORecoveryTransition(transition) != nil {
		return zero, ErrInstall
	}
	actual, e := ma.CollectMinIORecoveryResources(ctx, i.kube, g.Target, g.Provider, transition.NewPod, transition.NewContainerID)
	if e != nil || !reflect.DeepEqual(actual, transition.OriginalResources) || source.recheckOriginalMinIORecoveryTransition(ctx, transition) != nil {
		return zero, ErrInstall
	}
	last, e := readOriginalMinIORecoverySQL(ctx, op, d.Pin)
	if e != nil {
		return zero, ErrInstall
	}
	lastExpected, stamp, e := last.Comparison()
	if e != nil || !reflect.DeepEqual(expected, lastExpected) || last.RequireCurrent(stamp) != nil || transition.RecoveredAt.After(stamp) || !stamp.Before(transition.OriginalProofUntil) {
		return zero, ErrInstall
	}
	// Complete every native/source/Kube authorization check before final SQL.
	if source.recheckOriginalMinIORecoveryTransition(ctx, transition) != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	finalTx, e := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return zero, ErrInstall
	}
	defer finalTx.Rollback()
	if _, e = op.lockAdmin(ctx, finalTx); e != nil {
		return zero, ErrInstall
	}
	headAfter, e := op.current(ctx, finalTx, false)
	if e != nil || headAfter.cas != head.cas {
		return zero, ErrInstall
	}
	finalSQL, e := ma.ReadSQLCurrentForInstaller(ctx, finalTx, d.Pin)
	if e != nil {
		return zero, ErrInstall
	}
	finalExpected, clock, e := finalSQL.Comparison()
	if e != nil || !reflect.DeepEqual(finalExpected, expected) || finalSQL.RequireCurrent(clock) != nil || !clock.Before(head.head.Until) || !clock.Before(head.record.Until) || !clock.Before(transition.OriginalProofUntil) {
		return zero, ErrInstall
	}
	end := g.Until
	if h.Until.Before(end) {
		end = h.Until
	}
	record := ma.MinIORecoveryProjection{Version: ma.MinIORecoveryProjectionVersion, Target: g.Target, Enrollment: g.Enrollment, AuthorityID: g.AuthorityID, GrantID: g.GrantID, DefinitionSHA256: d.DefinitionSHA256, PermissionSourceSHA256: d.PermissionSourceSHA256, PermissionGrantSHA256: g.PermissionSource.GrantSHA256, OriginalSQL: expected, OriginalProvider: g.Provider, Transition: transition, NotBefore: g.NotBefore, Until: end, SignedAt: clock}
	body, e := canonical(record)
	if e != nil {
		return zero, ErrInstall
	}
	key, e := op.privateKey(issuerPrivate)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	sealed := ma.SignedMinIORecoveryProjection{Record: body, Signature: ed25519.Sign(key, append([]byte(ma.MinIORecoveryProjectionDomain), body...))}
	wire, e := canonical(sealed)
	if e != nil || len(wire) > 65536 {
		return zero, ErrInstall
	}
	if _, e = ma.VerifyMinIORecoveryProjection(wire, d, finalSQL, clock); e != nil {
		return zero, ErrInstall
	}
	again, e := readBootstrapSourcePin(descriptor, 65536)
	if e != nil || !bytes.Equal(again, raw) {
		return zero, ErrInstall
	}
	// Keep original admin/installation/MinIO head+grant shared locks until the
	// create-only source is durable. No provider/Kube/network callback in SQL.
	if e = writeOriginalRuntimeIssuerFiles(filepath.Dir(d.ProjectionFile), map[string][]byte{filepath.Base(d.ProjectionFile): wire}); e != nil {
		return zero, ErrCommitUnknown
	}
	tail, e := i.database(ctx, finalTx, op.until)
	if e != nil || tail.Before(clock) || !tail.Before(transition.OriginalProofUntil) || !tail.Before(head.head.Until) || !tail.Before(head.record.Until) || finalSQL.RequireCurrent(tail) != nil {
		return zero, ErrCommitUnknown
	}
	if finalTx.Rollback() != nil {
		return zero, ErrCommitUnknown
	}
	// Independent actual file + current SQL readback, never regenerate on failure.
	return i.QueryOriginalMinIORecoveryProjection(ctx, password, enrollment, descriptor)
}

func readOriginalMinIORecoverySQL(ctx context.Context, op *authenticatedOperator, pin ma.SQLTrustPin) (*ma.SQLCurrentSnapshot, error) {
	if op == nil || !op.live(ctx) {
		return nil, ErrInstall
	}
	tx, e := op.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return nil, ErrInstall
	}
	defer tx.Rollback()
	if _, e = op.lockAdmin(ctx, tx); e != nil {
		return nil, ErrInstall
	}
	s, e := ma.ReadSQLCurrentForInstaller(ctx, tx, pin)
	if e != nil {
		return nil, ErrInstall
	}
	_, now, e := s.Comparison()
	if e != nil || s.RequireCurrent(now) != nil || tx.Rollback() != nil {
		return nil, ErrInstall
	}
	return s, nil
}

func (i *Installer) QueryOriginalMinIORecoveryProjection(ctx context.Context, password []byte, enrollment EnrollmentPin, descriptor BootstrapSourceFilePin) (OriginalMinIORecoveryProjectionReceipt, error) {
	var zero OriginalMinIORecoveryProjectionReceipt
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(descriptor, 65536)
	if e != nil {
		return zero, ErrInstall
	}
	d, e := ma.DecodeMinIORecoveryDescriptor(raw)
	if e != nil || op.minioSQLPin(ctx, enrollment, d.Pin) != nil {
		return zero, ErrInstall
	}
	current, e := readOriginalMinIORecoverySQL(ctx, op, d.Pin)
	if e != nil {
		return zero, ErrCommitUnknown
	}
	_, now, e := current.Comparison()
	if e != nil {
		return zero, ErrCommitUnknown
	}
	wire, e := ReadPrivateFile(d.ProjectionFile, 65536)
	if e != nil {
		return zero, ErrCommitUnknown
	}
	if _, e = ma.VerifyMinIORecoveryProjection(wire, d, current, now); e != nil {
		return zero, ErrCommitUnknown
	}
	again, e := ReadPrivateFile(d.ProjectionFile, 65536)
	if e != nil || !bytes.Equal(wire, again) {
		return zero, ErrCommitUnknown
	}
	tail, e := readOriginalMinIORecoverySQL(ctx, op, d.Pin)
	if e != nil {
		return zero, ErrCommitUnknown
	}
	_, checked, e := tail.Comparison()
	if e != nil {
		return zero, ErrCommitUnknown
	}
	if _, e = ma.VerifyMinIORecoveryProjection(wire, d, tail, checked); e != nil {
		return zero, ErrCommitUnknown
	}
	descriptorTail, e := readBootstrapSourcePin(descriptor, 65536)
	if e != nil || !bytes.Equal(descriptorTail, raw) {
		return zero, ErrCommitUnknown
	}
	return OriginalMinIORecoveryProjectionReceipt{Version: ma.MinIORecoveryProjectionVersion, State: "original_whole_cold_history_projection_exact_readback_not_current_health", Projection: BootstrapSourceFilePin{File: d.ProjectionFile, SHA256: hash(wire)}}, nil
}
