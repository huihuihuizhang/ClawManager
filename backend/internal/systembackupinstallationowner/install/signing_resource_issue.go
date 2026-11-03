package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
)

const SigningResourceInstallIntentVersion = "original-signing-resource-install-intent.v1"
const SigningResourceBundleVersion = "original-signing-resource-sql-bundle.v1"

// Explicit original scope for ONE purpose. It is DATA until the actual local
// admin/enrolled Kubernetes owner signs it; native capability is checked below.
type SigningResourceInstallIntent struct {
	Version  string
	Pin      owner.SigningResourceTrustPin
	Grant    owner.SigningResourceGrant
	Material owner.SigningResourceMaterial
}
type SigningResourceBundle struct {
	Version, Action, PlanSHA256, EnrollmentDocumentSHA256 string
	Expected                                              owner.SigningResourceCAS
	Grant, GrantSignature, Head, HeadSignature            []byte
}

func (s *authenticatedOperator) signingResourcePin(ctx context.Context, enrollment EnrollmentPin, p owner.SigningResourceTrustPin) error {
	if s == nil || !s.live(ctx) || s.authority(ctx, enrollment) != nil {
		return ErrInstall
	}
	i := s.installer
	if p.Target != i.plan.Target || p.Actor != (owner.Actor{UserID: s.userID, Username: i.plan.LocalAdminUsername, OwnerSubject: i.plan.OwnerUsername}) || p.OwnerSubject != i.plan.OwnerUsername || p.EnrollmentID != i.plan.EnrollmentID || p.EnrollmentRevision != i.plan.EnrollmentRevision || p.EnrollmentDocumentSHA256 != enrollment.DocumentSHA256 || p.IssuerID != i.plan.IssuerID || !bytes.Equal(p.Issuer, i.public) || p.MinimumPermissionEpoch != 1 || p.GrantRevision != 1 || p.MinimumHeadRevision != 1 {
		return ErrInstall
	}
	return nil
}

// A dedicated original signer domain, NOT snapshot()'s capture permission.
// This read-only preparation holds admin -> exact purpose head/gap only and
// releases it before signing/provider I/O. D's importer must re-lock this exact
// gap FOR UPDATE and perform atomic insert/final readback; issuance is no import.
func signingResourceAbsent(ctx context.Context, s *authenticatedOperator, p owner.SigningResourceTrustPin, notBefore, until time.Time) error {
	if s == nil || !s.live(ctx) {
		return ErrInstall
	}
	tx, e := s.installer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	before, e := s.lockAdmin(ctx, tx)
	if e != nil || before.Before(notBefore) || !before.Before(until) {
		return ErrInstall
	}
	var revision uint64
	e = tx.QueryRowContext(ctx, `SELECT head_revision FROM system_backup_signing_resource_heads WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND purpose=? FOR SHARE`, p.Target.InstallationID, p.EnrollmentID, p.AuthorityID, p.Purpose).Scan(&revision)
	if !errors.Is(e, sql.ErrNoRows) {
		return ErrInstall
	}
	after, e := s.lockAdmin(ctx, tx)
	if e != nil || after.Before(before) || after.Before(notBefore) || !after.Before(until) {
		return ErrInstall
	}
	if tx.Rollback() != nil {
		return ErrInstall
	}
	return nil
}

// Original admin/password, exact enrollment and separate signature domain
// authorize this installed resource before any backup/task exists. Actual JWT
// login + Transit challenge signature is mandatory, with no SQL locks held.
// No capture ledger, future ConfigVersion/BackupID/task/catalog receipt is read.
func (i *Installer) IssueSigningResourceInstall(ctx context.Context, password []byte, enrollment EnrollmentPin, intentFile, intentSHA string, files RequestFiles, issuerPrivate []byte) ([]byte, error) {
	raw, e := ReadPrivateFile(intentFile, 262144)
	var intent SigningResourceInstallIntent
	if e != nil || !digestPattern.MatchString(intentSHA) || hash(raw) != intentSHA || decodeExact(raw, &intent) != nil || intent.Version != SigningResourceInstallIntentVersion {
		return nil, ErrInstall
	}
	s, e := i.authenticate(ctx, password)
	if e != nil || s.signingResourcePin(ctx, enrollment, intent.Pin) != nil {
		return nil, ErrInstall
	}
	g := intent.Grant
	if g.PlanSHA256 != i.planHash || g.EnrollmentDocumentSHA256 != enrollment.DocumentSHA256 {
		return nil, ErrInstall
	}
	if owner.CheckSigningResourceMaterial(ctx, intent.Material, g) != nil {
		return nil, ErrInstall
	}
	configRaw, e := ReadPrivateFile(files.ConfigFile, 262144)
	if e != nil || hash(configRaw) != files.ConfigFileSHA256 {
		return nil, ErrInstall
	}
	config, e := sec.DecodeBootstrapConfig(configRaw)
	var fields map[string]json.RawMessage
	if e != nil || json.Unmarshal(config.CanonicalJSON(), &fields) != nil || !bytes.Equal(fields["enabled"], []byte("false")) {
		return nil, ErrInstall
	}
	grantRaw, e := ReadPrivateFile(files.GrantFile, 16384)
	if e != nil || hash(grantRaw) != files.GrantFileSHA256 {
		return nil, ErrInstall
	}
	offline, start, end, e := sec.ReadBootstrapGrantFile(files.GrantFile, files.GrantFileSHA256)
	encodedOffline, _ := json.Marshal(offline)
	if e != nil || hash(encodedOffline) != g.BootstrapGrantSHA256 || g.ConfigSHA256 != config.SHA256() || offline.ConfigSHA256 != g.ConfigSHA256 || offline.InstallationID != i.plan.Target.InstallationID || offline.ServerUUID != i.plan.Target.ServerUUID || offline.Database != i.plan.Target.Database || offline.UserID != s.userID || offline.Username != i.plan.LocalAdminUsername || g.NotBefore.Before(start) || g.Until.After(end) {
		return nil, ErrInstall
	}
	count := 0
	for _, ref := range config.References() {
		if ref.Purpose == g.Reference.Purpose {
			if ref != g.Reference {
				return nil, ErrInstall
			}
			count++
		}
	}
	if count != 1 {
		return nil, ErrInstall
	}
	docRaw, e := ReadPrivateFile(files.ObserverFile, 262144)
	var doc observerDocument
	if e != nil || hash(docRaw) != files.ObserverFileSHA256 || decodeExact(docRaw, &doc) != nil {
		return nil, ErrInstall
	}
	ca, e := ReadPrivateFile(doc.CAFile, 65536)
	if e != nil || hash(ca) != doc.CASHA256 {
		return nil, ErrInstall
	}
	observer, e := owner.NewSigningResourceObserver(owner.SigningObserverConfig{Endpoint: doc.Endpoint, CASHA256: doc.CASHA256, CAPEM: ca, ObserverPolicy: doc.ObserverPolicy, ObserverTokenFile: doc.ObserverTokenFile, ObserverTokenSHA256: doc.ObserverTokenSHA256, RuntimeJWTFile: doc.RuntimeJWTFile, Trust: doc.Trust, Kubernetes: i.kube})
	if e != nil {
		return nil, ErrInstall
	}
	defer observer.Close()
	if signingResourceAbsent(ctx, s, intent.Pin, g.NotBefore, g.Until) != nil {
		return nil, ErrInstall
	}
	key, e := s.privateKey(issuerPrivate)
	if e != nil {
		return nil, ErrInstall
	}
	defer clear(key)
	b := SigningResourceBundle{Version: SigningResourceBundleVersion, Action: "install", PlanSHA256: i.planHash, EnrollmentDocumentSHA256: enrollment.DocumentSHA256}
	b.Grant, e = owner.EncodeSigningResourceGrant(g)
	if e != nil {
		return nil, ErrInstall
	}
	b.GrantSignature = ed25519.Sign(key, append([]byte(owner.SigningResourceGrantDomain), b.Grant...))
	verified, e := owner.InspectSigningResourceGrant(b.Grant, b.GrantSignature, intent.Pin)
	if e != nil {
		return nil, ErrInstall
	}
	head := owner.SigningResourceHead{SchemaVersion: owner.SigningResourceHeadVersion, AuthorityID: verified.AuthorityID, Purpose: verified.Binding.Purpose, EnrollmentID: verified.EnrollmentID, IssuerID: verified.IssuerID, EnrollmentRevision: verified.EnrollmentRevision, HeadRevision: 1, PermissionEpoch: 1, Target: verified.Target, OwnerSubject: verified.Actor.OwnerSubject, CurrentGrantID: verified.GrantID, CurrentGrantRevision: 1, GrantSHA256: hash(b.Grant), State: "active", NotBefore: verified.NotBefore, Until: verified.Until}
	b.Head, e = owner.EncodeSigningResourceHead(head)
	if e != nil {
		return nil, ErrInstall
	}
	b.HeadSignature = ed25519.Sign(key, append([]byte(owner.SigningResourceHeadDomain), b.Head...))
	if _, e := owner.InspectSigningResourceHead(b.Head, b.HeadSignature, intent.Pin); e != nil {
		return nil, ErrInstall
	}
	observation, e := observer.ObserveSigningResource(ctx, b.Grant, b.GrantSignature, intent.Pin)
	if e != nil {
		return nil, ErrInstall
	}
	_, observedUntil, e := observation.Window()
	if e != nil {
		return nil, ErrInstall
	}
	for _, pin := range []consumerPinnedFile{{intentFile, intentSHA, 262144}, {files.ConfigFile, files.ConfigFileSHA256, 262144}, {files.GrantFile, files.GrantFileSHA256, 16384}, {files.ObserverFile, files.ObserverFileSHA256, 262144}, {doc.CAFile, doc.CASHA256, 65536}} {
		actual, e := ReadPrivateFile(pin.path, pin.limit)
		if e != nil || hash(actual) != pin.sha {
			return nil, ErrInstall
		}
	}
	if owner.CheckSigningResourceMaterial(ctx, intent.Material, g) != nil || s.signingResourcePin(ctx, enrollment, intent.Pin) != nil || signingResourceAbsent(ctx, s, intent.Pin, g.NotBefore, minTime(g.Until, observedUntil)) != nil {
		return nil, ErrInstall
	}
	encoded, e := canonical(b)
	if e != nil || len(encoded) > 262144 {
		return nil, ErrInstall
	}
	return encoded, nil
}

func signingResourceBundle(raw []byte, sha string, p owner.SigningResourceTrustPin) (SigningResourceBundle, owner.SigningResourceGrant, owner.SigningResourceHead, error) {
	var b SigningResourceBundle
	var zeroG owner.SigningResourceGrant
	var zeroH owner.SigningResourceHead
	if !digestPattern.MatchString(sha) || hash(raw) != sha || decodeExact(raw, &b) != nil || b.Version != SigningResourceBundleVersion || b.Action != "install" && b.Action != "revoke" {
		return b, zeroG, zeroH, ErrInstall
	}
	g, e := owner.InspectSigningResourceGrant(b.Grant, b.GrantSignature, p)
	h, f := owner.InspectSigningResourceHead(b.Head, b.HeadSignature, p)
	if e != nil || f != nil || b.PlanSHA256 != g.PlanSHA256 || b.EnrollmentDocumentSHA256 != g.EnrollmentDocumentSHA256 || !g.NotBefore.Equal(h.NotBefore) || !g.Until.Equal(h.Until) {
		return b, zeroG, zeroH, ErrInstall
	}
	if b.Action == "install" && (h.State != "active" || b.Expected != (owner.SigningResourceCAS{})) {
		return b, zeroG, zeroH, ErrInstall
	}
	if b.Action == "revoke" && (h.State != "revoked" || b.Expected.HeadRevision != 1 || b.Expected.State != "active" || b.Expected.PermissionEpoch != 1 || b.Expected.GrantID != g.GrantID || b.Expected.GrantRevision != 1 || b.Expected.GrantSHA256 != p.GrantSHA256 || !digestPattern.MatchString(b.Expected.HeadSHA256) || b.Expected.HeadRowVersion < 1 || b.Expected.HeadRowVersion >= 9007199254740991 || b.Expected.GrantRowVersion < 1 || b.Expected.GrantRowVersion >= 9007199254740991) {
		return b, zeroG, zeroH, ErrInstall
	}
	return b, g, h, nil
}

// Public transport DATA only for D's strict atomic importer/resolve path.
func DecodeSigningResourceBundle(raw []byte, sha string, p owner.SigningResourceTrustPin) (SigningResourceBundle, error) {
	b, _, _, e := signingResourceBundle(raw, sha, p)
	return b, e
}
func SaveFrozenSigningResourceBundle(directory string, raw []byte, sha string, p owner.SigningResourceTrustPin) error {
	if _, _, _, e := signingResourceBundle(raw, sha, p); e != nil {
		return ErrInstall
	}
	return writeNewFiles(directory, map[string][]byte{p.Purpose + ".signing-resource.bundle.json": bytes.Clone(raw), p.Purpose + ".signing-resource.bundle.sha256": []byte(sha)})
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
