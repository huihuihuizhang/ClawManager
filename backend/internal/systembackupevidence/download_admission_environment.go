package systembackupevidence

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"path/filepath"
	"reflect"
	"time"
	"unicode/utf8"

	sec "clawreef/internal/systembackupsecurity"
)

// DownloadAdmissionOwners is the reviewed D owner/ref adapter, not an evidence
// read grant or the legacy evidence-row callback. Preview checks CURRENT target
// visibility and returns server-loaded immutable metadata without L3+ locks.
// LockOwnerReferences holds original task/owner/hold/reference rows and their
// empty ranges before nonce/capacity/audit/evidence. Recheck is read-only SQL.
type DownloadAdmissionOwners interface {
	Preview(context.Context, *sql.Tx, string, sec.RegistrationActor, string) (Record, error)
	LockOwnerReferences(context.Context, *sql.Tx, Record) error
	Recheck(context.Context, *sql.Tx, sec.RegistrationActor, Record) error
}

type PinnedDownloadAdmissionConfig struct {
	Installation      string
	Sessions          *sec.SQLLoginSessions
	Materials         *sec.ConfigMutationSecurityFiles
	RegistryDirectory string
	Issuer            string
	Owners            DownloadAdmissionOwners
	Capacity          *sec.ConfigMutationCapacity
	// Review the measured WORST physical row/index/audit/nonce cost, not JSON
	// lengths. A real bounded capacity report/reservation is still required.
	MeasuredReservationBytes                int
	MaterialsUntil, AuditMinimumRetainUntil time.Time
}
type PinnedDownloadAdmissionEnvironment struct{ config PinnedDownloadAdmissionConfig }

func NewPinnedDownloadAdmissionEnvironment(c PinnedDownloadAdmissionConfig) (*PinnedDownloadAdmissionEnvironment, error) {
	if !installationPattern.MatchString(c.Installation) || c.Sessions == nil || c.Materials == nil || c.Capacity == nil || nilSystemAdapter(c.Owners) ||
		!filepath.IsAbs(c.RegistryDirectory) || filepath.Clean(c.RegistryDirectory) != c.RegistryDirectory || c.Issuer == "" || !utf8.ValidString(c.Issuer) || utf8.RuneCountInString(c.Issuer) > 256 ||
		c.MeasuredReservationBytes < 3*MaxDownloadAdmissionContentBytes || c.MeasuredReservationBytes > 1048576 ||
		!downloadAdmissionContentTime(c.MaterialsUntil) || !downloadAdmissionContentTime(c.AuditMinimumRetainUntil) {
		return nil, ErrDownloadAdmissionNotReady
	}
	return &PinnedDownloadAdmissionEnvironment{config: c}, nil
}

type pinnedPreparedDownloadAdmission struct {
	source                  *PinnedDownloadAdmissionEnvironment
	tx                      *sql.Tx
	actor                   sec.RegistrationActor
	config                  *sec.SensitiveDownloadConfig
	hint                    Record
	proofConfig             sec.VerifyConfig
	versions                []string
	until, minimumRetention time.Time
	closed                  bool
}

func (*pinnedPreparedDownloadAdmission) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*pinnedPreparedDownloadAdmission) String() string               { return "PinnedPreparedDownloadAdmission" }
func (*pinnedPreparedDownloadAdmission) GoString() string             { return "PinnedPreparedDownloadAdmission" }

func (e *PinnedDownloadAdmissionEnvironment) Prepare(ctx context.Context, tx *sql.Tx, actor sec.RegistrationActor, config *sec.SensitiveDownloadConfig, evidenceID string, versions []string) (PreparedDownloadAdmission, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || tx == nil || config == nil || config.InstallationID() != e.config.Installation || !idPattern.MatchString(evidenceID) || len(versions) == 0 {
		return nil, ErrDownloadAdmissionNotReady
	}
	now, err := downloadIntentNow(ctx, tx, config.ObservedAt())
	if err != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	if err = e.config.Sessions.CheckConfigMutationSession(ctx, tx, e.config.Installation, actor, now); err != nil {
		return nil, err
	}
	hint, err := e.config.Owners.Preview(ctx, tx, e.config.Installation, actor, evidenceID)
	if err != nil {
		return nil, err
	}
	frozen, err := snapshotReadManifest(hint.Manifest)
	if err != nil || frozen.Identity.Installation != e.config.Installation || frozen.Identity.ID != evidenceID {
		return nil, ErrDenied
	}
	hint.Manifest = frozen
	if err = e.authorizeRBAC(actor, config.Values(), hint); err != nil {
		return nil, err
	}
	if oneOf(frozen.Identity.Classification, "public", "internal") {
		return &pinnedPreparedDownloadAdmission{source: e, tx: tx, actor: actor, config: config, hint: hint, until: actor.SessionExpiresAt, minimumRetention: e.config.AuditMinimumRetainUntil}, nil
	}
	if !now.Before(e.config.MaterialsUntil) {
		return nil, ErrDownloadAdmissionNotReady
	}
	now, err = downloadIntentNow(ctx, tx, now)
	if err != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	material, err := e.config.Materials.StrongAuth(ctx, tx, actor, e.config.Installation, config.Values(), append([]string(nil), versions...), now)
	if err != nil {
		return nil, err
	}
	if material.ExpectedSubject != actor.Subject || material.ExpectedSession != actor.Session || len(material.TrustedSigners[e.config.Issuer]) == 0 {
		wipeDownloadAdmissionMaterial(material)
		return nil, ErrDownloadAdmissionNotReady
	}
	return &pinnedPreparedDownloadAdmission{source: e, tx: tx, actor: actor, config: config, hint: hint, proofConfig: material, versions: append([]string(nil), versions...),
		until: earlier(e.config.MaterialsUntil, actor.SessionExpiresAt), minimumRetention: e.config.AuditMinimumRetainUntil}, nil
}

func (e *PinnedDownloadAdmissionEnvironment) authorizeRBAC(actor sec.RegistrationActor, values sec.ConfigValues, record Record) error {
	var pin sec.BootstrapRegistryRef
	for _, r := range values.Registries() {
		if r.Kind == "rbac_bindings" {
			pin = r
		}
	}
	if pin.Kind == "" {
		return ErrDownloadAdmissionNotReady
	}
	raw, err := (sec.RegistrationFiles{RegistryDirectory: e.config.RegistryDirectory}).RegistryBytes(pin.Kind, pin.Version, pin.SHA256)
	if err != nil {
		return ErrDownloadAdmissionNotReady
	}
	defer wipe(raw)
	return sec.AuthorizeEvidencePermissions(raw, pin.SHA256, pin.Version, e.config.Installation, actor, permissions(record.Manifest.Identity.Classification))
}
func wipeDownloadAdmissionMaterial(c sec.VerifyConfig) {
	for _, key := range c.NonceHMACKeys {
		wipe(key)
	}
}
func sameDownloadAdmissionMaterial(a, b sec.VerifyConfig) bool {
	if a.ExpectedAudience != b.ExpectedAudience || a.ExpectedSubject != b.ExpectedSubject || a.ExpectedSession != b.ExpectedSession || a.ActiveNonceHMACKeyVersion != b.ActiveNonceHMACKeyVersion ||
		a.MaxAge != b.MaxAge || a.ClockSkew != b.ClockSkew || !reflect.DeepEqual(a.TrustedSigners, b.TrustedSigners) || !reflect.DeepEqual(a.TrustedIssuerPolicies, b.TrustedIssuerPolicies) ||
		!reflect.DeepEqual(a.RequiredNonceHMACKeyVersions, b.RequiredNonceHMACKeyVersions) || len(a.NonceHMACKeys) != len(b.NonceHMACKeys) {
		return false
	}
	for version, key := range a.NonceHMACKeys {
		if len(key) != 32 || subtle.ConstantTimeCompare(key, b.NonceHMACKeys[version]) != 1 {
			return false
		}
	}
	return true
}
func (p *pinnedPreparedDownloadAdmission) valid(ctx context.Context, tx *sql.Tx) bool {
	return p != nil && !p.closed && p.source != nil && ctx != nil && ctx.Err() == nil && tx != nil && tx == p.tx && p.config != nil
}
func (p *pinnedPreparedDownloadAdmission) Preview() Record {
	if p == nil {
		return Record{}
	}
	r := p.hint
	r.Manifest.Chunks = append([]Chunk(nil), r.Manifest.Chunks...)
	return r
}
func (p *pinnedPreparedDownloadAdmission) Issuer() string {
	if p == nil || p.source == nil {
		return ""
	}
	return p.source.config.Issuer
}
func (p *pinnedPreparedDownloadAdmission) ProofConfig() sec.VerifyConfig {
	if p == nil || p.closed {
		return sec.VerifyConfig{}
	}
	return p.proofConfig
}
func (p *pinnedPreparedDownloadAdmission) ValidUntil() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.until
}
func (p *pinnedPreparedDownloadAdmission) MinimumRetainUntil() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.minimumRetention
}
func (p *pinnedPreparedDownloadAdmission) LockOwnerReferences(ctx context.Context, tx *sql.Tx) error {
	if !p.valid(ctx, tx) {
		return ErrDownloadAdmissionNotReady
	}
	return p.source.config.Owners.LockOwnerReferences(ctx, tx, p.Preview())
}
func (p *pinnedPreparedDownloadAdmission) Reserve(ctx context.Context, tx *sql.Tx, now time.Time) (DownloadAdmissionReservation, error) {
	if !p.valid(ctx, tx) {
		return nil, ErrDownloadAdmissionNotReady
	}
	return p.source.config.Capacity.Reserve(ctx, tx, p.config.Values(), p.config.Values(), p.source.config.MeasuredReservationBytes, now)
}
func (p *pinnedPreparedDownloadAdmission) Recheck(ctx context.Context, tx *sql.Tx, actor sec.RegistrationActor, current Record, notBefore time.Time) error {
	if !p.valid(ctx, tx) || !sameDownloadAdmissionActor(actor, p.actor) || !sameDownloadAdmissionImmutable(current, p.hint) {
		return ErrDownloadAdmissionNotReady
	}
	now, err := downloadIntentNow(ctx, tx, notBefore)
	if err != nil || !now.Before(p.until) {
		return ErrDownloadAdmissionNotReady
	}
	if err = p.source.config.Sessions.CheckConfigMutationSession(ctx, tx, p.source.config.Installation, actor, now); err != nil {
		return err
	}
	if err = p.source.authorizeRBAC(actor, p.config.Values(), current); err != nil {
		return err
	}
	if err = p.source.config.Owners.Recheck(ctx, tx, actor, current); err != nil {
		return err
	}
	now, err = downloadIntentNow(ctx, tx, now)
	if err != nil {
		return ErrDownloadAdmissionNotReady
	}
	material, err := p.source.config.Materials.StrongAuth(ctx, tx, actor, p.source.config.Installation, p.config.Values(), append([]string(nil), p.versions...), now)
	if err != nil {
		return err
	}
	defer wipeDownloadAdmissionMaterial(material)
	if !sameDownloadAdmissionMaterial(p.proofConfig, material) {
		return ErrDownloadAdmissionNotReady
	}
	return nil
}
func (p *pinnedPreparedDownloadAdmission) Close() {
	if p == nil || p.closed {
		return
	}
	p.closed = true
	wipeDownloadAdmissionMaterial(p.proofConfig)
}
