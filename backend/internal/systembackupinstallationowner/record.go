// Package systembackupinstallationowner consumes independently enrolled owner
// authority. It neither enrolls its own key nor supplies a default Original.
package systembackupinstallationowner

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	RecordVersion      = "system-backup-bootstrap-capture-signing-owner.v1"
	RecordDomain       = RecordVersion + "\x00"
	HeadVersion        = "system-backup-installation-owner-head.v1"
	HeadDomain         = HeadVersion + "\x00"
	ProbeVersion       = "system-backup-bootstrap-signing-probe.v1"
	ProbeDomain        = ProbeVersion + "\x00"
	ObservationVersion = "system-backup-bootstrap-signing-observation.v1"
	ObservationDomain  = ObservationVersion + "\x00"
	IdentityVersion    = "system-backup-bootstrap-signing-identity.v1"
)

var ErrOwner = errors.New("installation owner unavailable or unauthorized")
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var serverPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func nilInterface(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return r.IsNil()
	}
	return false
}

// TrustPin is independently installed by the user after authenticated enroll.
// It must never be derived from Record, candidate output or a database row.
type TrustPin struct {
	InstallationID, EnrollmentID, IssuerID  string
	EnrollmentRevision, MinimumHeadRevision uint64
	Issuer                                  ed25519.PublicKey
	ClusterID, NamespaceUID, OwnerSubject   string
	ServerUUID, Database, DatabaseAccount   string
	GrantID                                 string
	GrantRevision                           uint64
	RecordSHA256                            string
}
type Target struct{ InstallationID, ServerUUID, Database, DatabaseAccount, ClusterID, Namespace, NamespaceUID string }
type Actor struct {
	UserID                 int64
	Username, OwnerSubject string
}
type Binding struct {
	InstallationID, Purpose, KeyID, KeyVersion, Endpoint, ProviderClusterID, TransitMount, KeyName, ProviderVersion    string
	AuthMount, Role, Policy, Audience, Namespace, NamespaceUID, PodName, PodUID, ServiceAccountName, ServiceAccountUID string
	CASHA256, RoleSHA256, PolicySHA256, JWTConfigSHA256                                                                string
}
type PublicKey struct {
	Version, PublicKey string
	ProtectedUntil     time.Time
}
type PurposeKeys struct {
	Purpose, KeyName string
	Keys             []PublicKey
}
type Probe struct {
	Challenge string
	Until     time.Time
}
type Record struct {
	SchemaVersion                                                                                       string
	EnrollmentID, IssuerID, GrantID                                                                     string
	EnrollmentRevision, Revision                                                                        uint64
	NotBefore, Until                                                                                    time.Time
	Target                                                                                              Target
	Actor                                                                                               Actor
	Endpoint, IdempotencyKey, MatrixKey                                                                 string
	GrantSHA256, ConfigSHA256, RegistrySetSHA256, ReferenceSetSHA256, SelectionSHA256, CanonicalProfile string
	Reference                                                                                           sec.BootstrapSecretRef
	Binding                                                                                             Binding
	Histories                                                                                           []PurposeKeys
	Probe                                                                                               Probe
}
type Head struct {
	SchemaVersion, InstallationID, EnrollmentID, IssuerID, OwnerSubject string
	EnrollmentRevision, Revision                                        uint64
	GrantID                                                             string
	GrantRevision                                                       uint64
	RecordSHA256, State                                                 string
	NotBefore, Until                                                    time.Time
}
type AuthenticatedRecord struct {
	record         Record
	raw, signature []byte
	pin            TrustPin
}

func (*AuthenticatedRecord) MarshalJSON() ([]byte, error) { return nil, ErrOwner }
func (*AuthenticatedRecord) String() string               { return "AuthenticatedInstallationOwnerRecord" }

func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func canonical(v any) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, ErrOwner
	}
	b, e := jsoncanonicalizer.Transform(raw)
	if e != nil {
		return nil, ErrOwner
	}
	return b, nil
}
func jsoncanonical(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, ErrOwner
	}
	c, e := jsoncanonicalizer.Transform(raw)
	if e != nil {
		return nil, ErrOwner
	}
	var v any
	if json.Unmarshal(raw, &v) != nil || !foldUnique(v) {
		return nil, ErrOwner
	}
	return c, nil
}
func foldUnique(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		seen := map[string]bool{}
		for k, v := range x {
			f := strings.ToLower(k)
			if seen[f] || !foldUnique(v) {
				return false
			}
			seen[f] = true
		}
	case []any:
		for _, v := range x {
			if !foldUnique(v) {
				return false
			}
		}
	}
	return true
}
func exactFields(raw []byte, t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		return exactFields(raw, t.Elem())
	}
	if t == reflect.TypeOf(time.Time{}) {
		return len(raw) > 1 && raw[0] == '"'
	}
	switch t.Kind() {
	case reflect.Struct:
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil || len(m) != t.NumField() {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := f.Name
			if tag, ok := f.Tag.Lookup("json"); ok {
				if tagged, _, _ := strings.Cut(tag, ","); tagged != "" {
					name = tagged
				}
			}
			// Match the declared wire spelling exactly, including nested types
			// such as BootstrapSecretRef; encoding/json accepts case aliases.
			if f.PkgPath != "" || name == "-" {
				return false
			}
			v, ok := m[name]
			if !ok || !exactFields(v, f.Type) {
				return false
			}
		}
	case reflect.Slice:
		var list []json.RawMessage
		if json.Unmarshal(raw, &list) != nil || bytes.Equal(raw, []byte("null")) {
			return false
		}
		for _, v := range list {
			if !exactFields(v, t.Elem()) {
				return false
			}
		}
	}
	return true
}
func decodeCanonical(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 262144 || !utf8.Valid(raw) {
		return ErrOwner
	}
	c, e := jsoncanonical(raw)
	if e != nil || !bytes.Equal(c, raw) || !exactFields(raw, reflect.TypeOf(out)) {
		return ErrOwner
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrOwner
	}
	return nil
}
func validTime(t time.Time) bool {
	_, o := t.Zone()
	return !t.IsZero() && t.Year() >= 1000 && t.Year() <= 9999 && o == 0 && t.Nanosecond()%1000 == 0
}
func validWindow(a, b time.Time) bool {
	return validTime(a) && validTime(b) && b.After(a) && b.Sub(a) <= 24*time.Hour
}
func validText(s string) bool {
	return s != "" && len(s) <= 512 && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func numericVersion(s string) bool {
	v, e := strconv.ParseUint(s, 10, 32)
	return e == nil && v > 0 && strconv.FormatUint(v, 10) == s
}
func publicBytes(s string) ([]byte, error) {
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s {
		return nil, ErrOwner
	}
	return b, nil
}
func (p TrustPin) valid() bool {
	return regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`).MatchString(p.InstallationID) && safeName.MatchString(p.EnrollmentID) && safeName.MatchString(p.IssuerID) && p.EnrollmentRevision > 0 && p.MinimumHeadRevision > 0 && len(p.Issuer) == 32 && validText(p.ClusterID) && validText(p.NamespaceUID) && validText(p.OwnerSubject) && serverPattern.MatchString(p.ServerUUID) && regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`).MatchString(p.Database) && validText(p.DatabaseAccount) && safeName.MatchString(p.GrantID) && p.GrantRevision > 0 && hashPattern.MatchString(p.RecordSHA256)
}
func ReferenceIdentity(b Binding) (string, error) {
	if !validText(b.InstallationID) || b.Purpose != "capture_certificate" || !validText(b.ProviderClusterID) || !safeName.MatchString(b.TransitMount) || !safeName.MatchString(b.KeyName) {
		return "", ErrOwner
	}
	raw, e := canonical(struct{ SchemaVersion, InstallationID, Provider, ProviderClusterID, Endpoint, TransitMount, KeyName, BootstrapPurpose, SigningPurpose string }{IdentityVersion, b.InstallationID, "vault-transit-ed25519", b.ProviderClusterID, b.Endpoint, b.TransitMount, b.KeyName, "capture_signing", b.Purpose})
	if e != nil {
		return "", e
	}
	return digest(raw), nil
}
func validRecord(r Record, p TrustPin) bool {
	if !p.valid() || r.SchemaVersion != RecordVersion || r.EnrollmentID != p.EnrollmentID || r.EnrollmentRevision != p.EnrollmentRevision || r.IssuerID != p.IssuerID || r.GrantID != p.GrantID || r.Revision != p.GrantRevision || !validWindow(r.NotBefore, r.Until) || r.Target.InstallationID != p.InstallationID || r.Target.ServerUUID != p.ServerUUID || r.Target.Database != p.Database || r.Target.DatabaseAccount != p.DatabaseAccount || r.Target.ClusterID != p.ClusterID || r.Target.NamespaceUID != p.NamespaceUID || !validText(r.Target.Namespace) || r.Actor.OwnerSubject != p.OwnerSubject || r.Actor.UserID < 1 || !validText(r.Actor.Username) || r.Endpoint != sec.BootstrapConfigEndpoint || !validText(r.IdempotencyKey) || !validText(r.MatrixKey) || r.CanonicalProfile != "system-backup-config-values.v1" {
		return false
	}
	for _, h := range []string{r.GrantSHA256, r.ConfigSHA256, r.RegistrySetSHA256, r.ReferenceSetSHA256, r.SelectionSHA256, r.Probe.Challenge} {
		if !hashPattern.MatchString(h) {
			return false
		}
	}
	b := r.Binding
	if b.InstallationID != p.InstallationID || b.Purpose != "capture_certificate" || b.Namespace != r.Target.Namespace || b.NamespaceUID != r.Target.NamespaceUID || !validText(b.ProviderClusterID) || !validText(b.PodUID) || !validText(b.ServiceAccountUID) {
		return false
	}
	for _, s := range []string{b.KeyID, b.KeyVersion, b.TransitMount, b.KeyName, b.AuthMount, b.Role, b.Policy, b.PodName, b.ServiceAccountName, b.Namespace} {
		if !safeName.MatchString(s) || strings.EqualFold(s, "latest") || strings.EqualFold(s, "current") || strings.EqualFold(s, "default") || strings.EqualFold(s, "root") {
			return false
		}
	}
	if !numericVersion(b.ProviderVersion) || !validText(b.Audience) {
		return false
	}
	for _, h := range []string{b.CASHA256, b.RoleSHA256, b.PolicySHA256, b.JWTConfigSHA256} {
		if !hashPattern.MatchString(h) {
			return false
		}
	}
	identity, e := ReferenceIdentity(b)
	// Physical dependency may already have expired when a current owner grants
	// exact historical readback. Only observe/resource checks demand it live.
	if e != nil || r.Reference.Purpose != "capture_signing" || r.Reference.IdentityHash != identity || r.Reference.Version != b.KeyVersion || !validTime(r.Probe.Until) || r.Probe.Until.After(r.Until) {
		return false
	}
	if len(r.Histories) != 3 {
		return false
	}
	purposes := []string{"acceptance_record", "capture_certificate", "catalog_record"}
	names := map[string]bool{}
	keys := map[string]bool{}
	current := false
	for i, h := range r.Histories {
		if h.Purpose != purposes[i] || !safeName.MatchString(h.KeyName) || names[h.KeyName] || len(h.Keys) == 0 || len(h.Keys) > 1000 {
			return false
		}
		names[h.KeyName] = true
		var prior uint64
		for _, k := range h.Keys {
			v, e := strconv.ParseUint(k.Version, 10, 32)
			pub, pe := publicBytes(k.PublicKey)
			if e != nil || !numericVersion(k.Version) || v <= prior || pe != nil || keys[k.PublicKey] || bytes.Equal(pub, p.Issuer) || !validTime(k.ProtectedUntil) || k.ProtectedUntil.Before(r.Until) {
				return false
			}
			keys[k.PublicKey] = true
			prior = v
			if h.Purpose == b.Purpose && h.KeyName == b.KeyName && k.Version == b.ProviderVersion {
				current = true
			}
		}
	}
	return current
}

// EncodeRecord produces canonical comparison bytes, never an approval/signature.
func EncodeRecord(r Record) ([]byte, error) { return canonical(r) }
func EncodeHead(h Head) ([]byte, error)     { return canonical(h) }
func VerifyRecord(raw, sig []byte, p TrustPin) (*AuthenticatedRecord, error) {
	var r Record
	if !p.valid() || digest(raw) != p.RecordSHA256 || len(sig) != 64 || !ed25519.Verify(p.Issuer, append([]byte(RecordDomain), raw...), sig) || decodeCanonical(raw, &r) != nil || !validRecord(r, p) {
		return nil, ErrOwner
	}
	p.Issuer = bytes.Clone(p.Issuer)
	return &AuthenticatedRecord{r, bytes.Clone(raw), bytes.Clone(sig), p}, nil
}
func verifyHead(raw, sig []byte, p TrustPin) (Head, error) {
	var h Head
	if !p.valid() || len(sig) != 64 || !ed25519.Verify(p.Issuer, append([]byte(HeadDomain), raw...), sig) || decodeCanonical(raw, &h) != nil || h.SchemaVersion != HeadVersion || h.InstallationID != p.InstallationID || h.EnrollmentID != p.EnrollmentID || h.EnrollmentRevision != p.EnrollmentRevision || h.IssuerID != p.IssuerID || h.OwnerSubject != p.OwnerSubject || h.Revision < p.MinimumHeadRevision || h.GrantID != p.GrantID || h.GrantRevision != p.GrantRevision || h.RecordSHA256 != p.RecordSHA256 || h.State != "active" || !validWindow(h.NotBefore, h.Until) {
		return Head{}, ErrOwner
	}
	return h, nil
}
func matchConfig(a *AuthenticatedRecord, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig) bool {
	if a == nil {
		return false
	}
	r := a.record
	grant, _ := json.Marshal(g)
	var fields map[string]json.RawMessage
	if json.Unmarshal(c.CanonicalJSON(), &fields) != nil {
		return false
	}
	if g.InstallationID != r.Target.InstallationID || g.ServerUUID != r.Target.ServerUUID || g.Database != r.Target.Database || g.UserID != r.Actor.UserID || g.Username != r.Actor.Username || g.ConfigSHA256 != r.ConfigSHA256 || c.SHA256() != r.ConfigSHA256 || g.IdempotencyKey != r.IdempotencyKey || g.MatrixKey != r.MatrixKey || digest(grant) != r.GrantSHA256 || digest(fields["registries"]) != r.RegistrySetSHA256 || digest(fields["references"]) != r.ReferenceSetSHA256 {
		return false
	}
	n := 0
	for _, ref := range c.References() {
		if ref.Purpose == "capture_signing" {
			if ref != r.Reference {
				return false
			}
			n++
		}
	}
	return n == 1
}
