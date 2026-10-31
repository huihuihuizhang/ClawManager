package systembackupkekadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"

	admission "clawreef/internal/systembackupkekadmission"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const ProviderCapabilityDomain = "system-backup-original-provider-capability.v1\x00"

// ProviderCapabilityPermission names the precise installed provider ACL/role
// observation authenticated by the independent ORIGINAL permission observer.
// It is an admission observation, never a Job token or a grant to use a DEK.
type ProviderCapabilityPermission struct {
	Path, ProviderVersion                    string
	AuthMount, Role, Policy                  string
	PolicySHA256, RoleSHA256, JWTTrustSHA256 string
	Reference                                reg.TypedReference
}

type ProviderCapabilityFacts struct {
	Binding    reg.Binding
	Operation  kms.Operation
	Permission ProviderCapabilityPermission
}

// The original provider permission owner signs this record after observing
// exact ACL/role/JWT trust. Config, review plans or successful policy writes
// cannot issue it. Source.ContentSHA256 is SHA256(json.Marshal(Facts)).
type ProviderCapabilityRecord struct {
	Facts            ProviderCapabilityFacts
	Source           reg.SourceRecord
	Revision         string
	NotBefore, Until time.Time
	Revoked          bool
}

type SignedProviderCapabilityRecord struct{ Record, Signature []byte }

type ProviderCapabilityPin struct {
	Source reg.SourceRecord
	Issuer ed25519.PublicKey
}

type SQLProviderCapabilityPreparation struct {
	db               *sql.DB
	database         reg.DatabaseIdentity
	installation     string
	generate, unwrap ProviderCapabilityPin
}

// NewSQLProviderCapabilityPreparation is a concrete adapter for the existing
// installation preparation. All source locators and public issuers are pinned
// independently of candidate/committed config. It reads original immutable
// capability_snapshot evidence; it creates no evidence, table, token or grant.
func NewSQLProviderCapabilityPreparation(db *sql.DB, database reg.DatabaseIdentity, installation string, generate, unwrap ProviderCapabilityPin) (*SQLProviderCapabilityPreparation, error) {
	if db == nil || database.ServerUUID == "" || database.Database == "" || installation == "" || len(installation) > 128 || generate.Source.RecordID == unwrap.Source.RecordID {
		return nil, admission.ErrCandidate
	}
	for _, p := range []ProviderCapabilityPin{generate, unwrap} {
		if !authoritySource(p.Source) || !strings.HasPrefix(p.Source.RecordID, "sev_") || len(p.Issuer) != ed25519.PublicKeySize {
			return nil, admission.ErrCandidate
		}
	}
	generate.Issuer = append(ed25519.PublicKey(nil), generate.Issuer...)
	unwrap.Issuer = append(ed25519.PublicKey(nil), unwrap.Issuer...)
	return &SQLProviderCapabilityPreparation{db, database, installation, generate, unwrap}, nil
}

// NewSQLInstallationPreparation composes the existing original installation
// authority table and the two independent provider-purpose evidence readers on
// the SAME database. Pass this value to WireServices; original C coverage and
// bootstrap/config authorization are still mandatory and are not fabricated.
func NewSQLInstallationPreparation(db *sql.DB, database reg.DatabaseIdentity, installation string, installationIssuer ed25519.PublicKey, generate, unwrap ProviderCapabilityPin) (InstallationPreparation, error) {
	if len(installationIssuer) != ed25519.PublicKeySize {
		return InstallationPreparation{}, admission.ErrCandidate
	}
	capabilities, err := NewSQLProviderCapabilityPreparation(db, database, installation, generate, unwrap)
	if err != nil {
		return InstallationPreparation{}, err
	}
	return InstallationPreparation{Reader: SQLOriginalReader{DB: db}, Issuer: append(ed25519.PublicKey(nil), installationIssuer...), Capabilities: capabilities, Now: time.Now}, nil
}

type capabilityEvidence struct {
	raw   []byte
	until time.Time
}

func readCapabilityEvidence(ctx context.Context, view reg.SQLReadView, installation string, pin ProviderCapabilityPin, locked bool) (capabilityEvidence, error) {
	if ctx == nil || ctx.Err() != nil || nilSource(view) {
		return capabilityEvidence{}, admission.ErrCandidate
	}
	suffix := ""
	if locked {
		suffix = " FOR SHARE"
	}
	var e capabilityEvidence
	var hash string
	var size uint64
	err := view.QueryRowContext(ctx, `SELECT inline_payload,content_checksum,content_size_bytes,expires_at FROM system_backup_v2_evidence WHERE public_id=? AND owner_target_type='system' AND owner_target_public_id=? AND evidence_type='capability_snapshot' AND storage_state='inline' AND observed_health='healthy' AND encryption='none'`+suffix, pin.Source.RecordID, installation).Scan(&e.raw, &hash, &size, &e.until)
	h := sha256.Sum256(e.raw)
	if err != nil || len(e.raw) == 0 || len(e.raw) > 8192 || uint64(len(e.raw)) != size || hash != hex.EncodeToString(h[:]) || e.until.IsZero() {
		return capabilityEvidence{}, admission.ErrCandidate
	}
	return e, nil
}

func authenticateProviderCapability(e capabilityEvidence, pin ProviderCapabilityPin, binding reg.Binding, operation kms.Operation, now time.Time) (ProviderCapabilityRecord, error) {
	fail := func() (ProviderCapabilityRecord, error) { return ProviderCapabilityRecord{}, admission.ErrCandidate }
	var envelope SignedProviderCapabilityRecord
	if _, err := jsoncanonicalizer.Transform(e.raw); err != nil {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(e.raw))
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil || d.Decode(new(any)) != io.EOF || len(envelope.Record) == 0 || len(envelope.Record) > 65536 || len(pin.Issuer) != ed25519.PublicKeySize || !ed25519.Verify(pin.Issuer, append([]byte(ProviderCapabilityDomain), envelope.Record...), envelope.Signature) {
		return fail()
	}
	if _, err := jsoncanonicalizer.Transform(envelope.Record); err != nil {
		return fail()
	}
	var record ProviderCapabilityRecord
	d = json.NewDecoder(bytes.NewReader(envelope.Record))
	d.DisallowUnknownFields()
	if d.Decode(&record) != nil || d.Decode(new(any)) != io.EOF || record.Source != pin.Source || !authorityExact(record.Revision) || record.Revoked || record.NotBefore.IsZero() || now.IsZero() || now.Before(record.NotBefore) || !now.Before(record.Until) || !now.Before(e.until) || !reflect.DeepEqual(record.Facts.Binding, binding) || record.Facts.Operation != operation {
		return fail()
	}
	f := record.Facts
	p := f.Permission
	raw, err := json.Marshal(f)
	h := sha256.Sum256(raw)
	if err != nil || hex.EncodeToString(h[:]) != record.Source.ContentSHA256 || !authorityHash.MatchString(p.PolicySHA256) || !authorityHash.MatchString(p.RoleSHA256) || !authorityHash.MatchString(p.JWTTrustSHA256) ||
		!keyNameValid(p.AuthMount) || !keyNameValid(p.Role) || !keyNameValid(p.Policy) || strings.EqualFold(p.Policy, "root") || strings.EqualFold(p.Policy, "default") || p.ProviderVersion != binding.Key.ProviderVersion {
		return fail()
	}
	switch operation {
	case kms.Generate:
		if p.Path != "transit/datakey/plaintext/"+binding.Provider.KeyName || !reflect.DeepEqual(p.Reference, binding.GenerateRef) {
			return fail()
		}
	case kms.Unwrap:
		if p.Path != "transit/decrypt/"+binding.Provider.KeyName || !reflect.DeepEqual(p.Reference, binding.UnwrapRef) {
			return fail()
		}
	default:
		return fail()
	}
	return record, nil
}

func keyNameValid(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (p *SQLProviderCapabilityPreparation) PrepareCapabilities(ctx context.Context, binding reg.Binding) (admission.Capabilities, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || binding.InstallationID != p.installation {
		return admission.Capabilities{}, admission.ErrCandidate
	}
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return admission.Capabilities{}, admission.ErrCandidate
	}
	defer tx.Rollback()
	var database reg.DatabaseIdentity
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&database.ServerUUID, &database.Database, &now) != nil || database != p.database {
		return admission.Capabilities{}, admission.ErrCandidate
	}
	var prepared []admission.PreparedCapability
	for _, pair := range []struct {
		pin       ProviderCapabilityPin
		operation kms.Operation
	}{{p.generate, kms.Generate}, {p.unwrap, kms.Unwrap}} {
		e, err := readCapabilityEvidence(ctx, tx, p.installation, pair.pin, false)
		if err != nil {
			return admission.Capabilities{}, err
		}
		record, err := authenticateProviderCapability(e, pair.pin, binding, pair.operation, now)
		if err != nil {
			return admission.Capabilities{}, err
		}
		until := record.Until
		if e.until.Before(until) {
			until = e.until
		}
		prepared = append(prepared, &sqlPreparedCapability{database: p.database, record: record, pin: pair.pin, evidence: e, until: until})
	}
	return admission.Capabilities{Generate: prepared[0], Unwrap: prepared[1]}, nil
}

type sqlPreparedCapability struct {
	database reg.DatabaseIdentity
	record   ProviderCapabilityRecord
	pin      ProviderCapabilityPin
	evidence capabilityEvidence
	until    time.Time
}

func (p *sqlPreparedCapability) Source() reg.SourceRecord { return p.record.Source }
func (p *sqlPreparedCapability) Binding() reg.Binding {
	b := p.record.Facts.Binding
	b.GenerateRef.RawJSON = bytes.Clone(b.GenerateRef.RawJSON)
	b.UnwrapRef.RawJSON = bytes.Clone(b.UnwrapRef.RawJSON)
	return b
}
func (p *sqlPreparedCapability) Operation() kms.Operation { return p.record.Facts.Operation }
func (p *sqlPreparedCapability) NotBefore() time.Time     { return p.record.NotBefore }
func (p *sqlPreparedCapability) ValidUntil() time.Time    { return p.until }
func (p *sqlPreparedCapability) Recheck(ctx context.Context, view reg.SQLReadView, locked reg.LockedSnapshot, now time.Time) error {
	return p.recheck(ctx, view, locked.Facts(), now)
}
func (p *sqlPreparedCapability) recheck(ctx context.Context, view reg.SQLReadView, facts reg.Snapshot, now time.Time) error {
	if p == nil || ctx == nil || ctx.Err() != nil || facts.InstallationID != p.record.Facts.Binding.InstallationID || facts.Database != p.database || now.Before(p.record.NotBefore) || !now.Before(p.until) {
		return admission.ErrCandidate
	}
	e, err := readCapabilityEvidence(ctx, view, facts.InstallationID, p.pin, true)
	if err != nil || !bytes.Equal(e.raw, p.evidence.raw) || !e.until.Equal(p.evidence.until) {
		return admission.ErrCandidate
	}
	r, err := authenticateProviderCapability(e, p.pin, p.record.Facts.Binding, p.record.Facts.Operation, now)
	if err != nil || !reflect.DeepEqual(r, p.record) {
		return admission.ErrCandidate
	}
	return nil
}

var _ CapabilityPreparation = (*SQLProviderCapabilityPreparation)(nil)
