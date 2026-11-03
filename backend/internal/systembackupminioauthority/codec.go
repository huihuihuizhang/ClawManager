package systembackupminioauthority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var ErrRecord = errors.New("original MinIO SQL record invalid or unauthenticated")

const maximumCounter = uint64(9007199254740991)

var digestSyntax = regexp.MustCompile(`^[a-f0-9]{64}$`)
var idSyntax = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var versionSyntax = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var installationSyntax = regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`)
var uuidSyntax = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var databaseSyntax = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
var bucketSyntax = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func digest(raw []byte) Digest  { v := sha256.Sum256(raw); return Digest(hex.EncodeToString(v[:])) }
func validDigest(v Digest) bool { return digestSyntax.MatchString(string(v)) }
func counter(v uint64) bool     { return v > 0 && v <= maximumCounter }
func text(v string) bool {
	if v == "" || len(v) > 512 || !utf8.ValidString(v) {
		return false
	}
	for _, c := range v {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func validTime(v time.Time) bool {
	return !v.IsZero() && v.Equal(v.UTC()) && v.Location() == time.UTC && v.Year() >= 1000 && v.Year() <= 9999 && v.Nanosecond()%1000 == 0
}
func window(start, end time.Time) bool {
	return validTime(start) && validTime(end) && start.Before(end)
}
func canonical(v any) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, ErrRecord
	}
	raw, e = jsoncanonicalizer.Transform(raw)
	if e != nil {
		return nil, ErrRecord
	}
	return raw, nil
}

// Strict complete canonical decoding is for signed record syntax only. It
// does not establish a SQL row, current state, permission or admission.
func decode(raw []byte, maximum int, out any) error {
	if len(raw) == 0 || len(raw) > maximum || !utf8.Valid(raw) {
		return ErrRecord
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 32 {
			return ErrRecord
		}
		t, e := d.Token()
		if e != nil {
			return ErrRecord
		}
		opening, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if opening != '{' && opening != '[' {
			return ErrRecord
		}
		seen := map[string]bool{}
		count := 0
		for d.More() {
			count++
			if count > 256 {
				return ErrRecord
			}
			if opening == '{' {
				key, e := d.Token()
				s, ok := key.(string)
				if e != nil || !ok || seen[strings.ToLower(s)] {
					return ErrRecord
				}
				seen[strings.ToLower(s)] = true
			}
			if visit(depth+1) != nil {
				return ErrRecord
			}
		}
		closing, e := d.Token()
		if e != nil || opening == '{' && closing != json.Delim('}') || opening == '[' && closing != json.Delim(']') {
			return ErrRecord
		}
		return nil
	}
	if visit(0) != nil {
		return ErrRecord
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrRecord
	}
	c, e := jsoncanonicalizer.Transform(raw)
	if e != nil || !bytes.Equal(c, raw) {
		return ErrRecord
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrRecord
	}
	round, e := canonical(out)
	if e != nil || !bytes.Equal(round, raw) {
		return ErrRecord
	}
	return nil
}

func validTarget(t Target) bool {
	return installationSyntax.MatchString(t.InstallationID) && uuidSyntax.MatchString(t.ServerUUID) && databaseSyntax.MatchString(t.Database) && text(t.ConsumerDatabaseAccount) && text(t.ClusterUID) && idSyntax.MatchString(t.Namespace) && text(t.NamespaceUID)
}
func validEnrollment(e Enrollment) bool {
	return idSyntax.MatchString(e.ID) && counter(e.Revision) && idSyntax.MatchString(e.ConfigMapName) && text(e.ConfigMapUID) && validDigest(e.DocumentSHA256) && validDigest(e.PlanSHA256) && idSyntax.MatchString(e.IssuerID) && validDigest(e.IssuerPublicSHA256) && text(e.OwnerSubject) && e.OwnerSubject != "system:anonymous" && (e.OwnerUID == "" || text(e.OwnerUID)) && validDigest(e.OwnerGroupsSHA256)
}
func validObject(v ObjectIdentity) bool { return idSyntax.MatchString(v.Name) && text(v.UID) }
func validProvider(p Provider) bool {
	u, e := url.Parse(p.Endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(p.Endpoint, "?#\r\n") || !validDigest(p.IdentityHash) || !versionSyntax.MatchString(p.IdentityProfile) || !versionSyntax.MatchString(p.Region) || !text(p.DeploymentID) || !validDigest(p.CASHA256) || !validDigest(p.SPKISHA256) || !nativeProviderVersion(p) || !validDigest(p.ImageProvenanceSHA256) || !text(p.Container) || !text(p.ImageID) || !text(p.Node) || !text(p.NodeUID) {
		return false
	}
	for _, o := range []ObjectIdentity{p.Deployment, p.ReplicaSet, p.Pod, p.Service, p.ServiceAccount} {
		if !validObject(o) {
			return false
		}
	}
	return true
}
func validPermissionSource(p PermissionSource) bool {
	return (p.Profile == PermissionProfile || p.Profile == SeptemberPermissionProfile) && validObject(p.Grant) && validObject(p.Head) && p.Grant.Name != p.Head.Name && validDigest(p.GrantSHA256) && validDigest(p.InitialHeadSHA256) && validDigest(p.ObserverAccountSHA256) && validDigest(p.ObserverCredentialFileSHA256) && validDigest(p.ObserverLocatorSHA256) && idSyntax.MatchString(p.ObserverPolicyName) && validDigest(p.ObserverNormalizedPolicySHA256)
}
func validPrefix(v string) bool {
	return v != "" && len(v) <= 512 && strings.HasSuffix(v, "/") && !strings.HasPrefix(v, "/") && !strings.ContainsAny(v, "*?[]\\\x00\r\n") && !strings.Contains(v, "../") && !strings.Contains(v, "//")
}
func validReference(r Reference) bool {
	for _, d := range []Digest{r.IdentityHash, r.DescriptorSHA256, r.ProviderIdentityHash, r.ScopeSHA256, r.AccountSHA256, r.CredentialFileSHA256, r.CredentialLocatorSHA256, r.NormalizedPolicySHA256, r.CapabilityIntentSHA256} {
		if !validDigest(d) {
			return false
		}
	}
	if !versionSyntax.MatchString(r.IdentityVersion) || r.IdentityVersion == "current" || r.IdentityVersion == "latest" || r.IdentityVersion == "default" || !versionSyntax.MatchString(r.IdentityProfile) || !versionSyntax.MatchString(r.ScopeProfile) || !versionSyntax.MatchString(r.CapabilityProfile) || !idSyntax.MatchString(r.PolicyName) || !bucketSyntax.MatchString(r.Bucket) || strings.Contains(r.Bucket, "..") || !validPrefix(r.Root) || !window(r.NotBefore, r.Until) || !validTime(r.ProtectedUntil) || r.ProtectedUntil.Before(r.Until) {
		return false
	}
	switch r.Purpose {
	case ArtifactRead:
		return (r.Capability == "exact_read" || r.Capability == "range_read") && validPrefix(r.StagingRoot)
	case ArtifactWrite:
		return r.Capability == "conditional_create" && validPrefix(r.StagingRoot)
	case ArtifactDelete:
		return r.Capability == "exact_delete" && validPrefix(r.StagingRoot)
	case CatalogRead:
		return r.Capability == "exact_read" && r.StagingRoot == ""
	case CatalogAppend:
		return r.Capability == "append_record" && r.StagingRoot == ""
	}
	return false
}
func purposes() []Purpose {
	return []Purpose{ArtifactDelete, ArtifactRead, ArtifactWrite, CatalogAppend, CatalogRead}
}

// EncodeSQLReference performs structural/profile validation, not original
// resource authorization. Only a verified original enrolled issuer may sign.
func EncodeSQLReference(r SQLReferenceRecord) ([]byte, error) {
	if r.Version != SQLReferenceVersion || !idSyntax.MatchString(r.AuthorityID) || !idSyntax.MatchString(r.GrantID) || r.RecordRevision != 1 || r.PermissionEpoch != 1 || !validTarget(r.Target) || !validEnrollment(r.Enrollment) || !validDigest(r.ConfigSHA256) || !validReference(r.Reference) {
		return nil, ErrRecord
	}
	return canonical(r)
}
func EncodeSQLGrant(g SQLGrant) ([]byte, error) {
	if g.Version != SQLGrantVersion || !idSyntax.MatchString(g.AuthorityID) || !idSyntax.MatchString(g.GrantID) || g.RecordRevision != 1 || g.PermissionEpoch != 1 || !validTarget(g.Target) || !validEnrollment(g.Enrollment) || g.Actor.LocalAdminUserID < 1 || !text(g.Actor.LocalAdminUsername) || !text(g.Actor.InstallerDatabaseAccount) || g.Actor.InstallerDatabaseAccount == g.Target.ConsumerDatabaseAccount || !validDigest(g.ConfigSHA256) || !validDigest(g.BootstrapGrantSHA256) || !validDigest(g.ReferenceSetSHA256) || !validProvider(g.Provider) || !validPermissionSource(g.PermissionSource) || !window(g.NotBefore, g.Until) || g.Until.Sub(g.NotBefore) > 24*time.Hour || !nativeGrantProfile(g) || !validDigest(g.Observation.DefinitionSHA256) || !validDigest(g.Observation.CapabilityIntentSHA256) || g.Observation.MaximumAgeMicroseconds == 0 || g.Observation.MaximumAgeMicroseconds > MaximumObservationAgeMicroseconds || len(g.References) != 5 {
		return nil, ErrRecord
	}
	for n, p := range purposes() {
		if g.References[n].Purpose != p || !validDigest(g.References[n].SHA256) {
			return nil, ErrRecord
		}
	}
	raw, e := canonical(g.References)
	if e != nil || digest(raw) != g.ReferenceSetSHA256 {
		return nil, ErrRecord
	}
	return canonical(g)
}
func EncodeSQLHead(h SQLHead) ([]byte, error) {
	if h.Version != SQLHeadVersion || !idSyntax.MatchString(h.AuthorityID) || !validTarget(h.Target) || !validEnrollment(h.Enrollment) || h.PermissionEpoch != 1 || h.CurrentGrantRevision != 1 || !idSyntax.MatchString(h.CurrentGrantID) || !validDigest(h.GrantSHA256) || !validDigest(h.ReferenceSetSHA256) || !window(h.NotBefore, h.Until) || h.State == StateActive && h.HeadRevision != 1 || h.State == StateRevoked && h.HeadRevision != 2 || h.State != StateActive && h.State != StateRevoked {
		return nil, ErrRecord
	}
	return canonical(h)
}

func validPin(p SQLTrustPin) bool {
	return validTarget(p.Target) && validEnrollment(p.Enrollment) && idSyntax.MatchString(p.AuthorityID) && idSyntax.MatchString(p.GrantID) && p.GrantRevision == 1 && counter(p.MinimumHeadRevision) && p.MinimumHeadRevision <= 2 && p.MinimumPermissionEpoch == 1 && validDigest(p.GrantSHA256) && validDigest(p.ReferenceSetSHA256) && len(p.IssuerPublic) == ed25519.PublicKeySize && digest(p.IssuerPublic) == p.Enrollment.IssuerPublicSHA256
}

// SQLRecordSet authenticates signed original declarations ONLY. It is not a
// current SQL read, ready check or permission/capability observation. Private
// bytes/fields prevent source records from being silently changed after verify.
type SQLRecordSet struct {
	grant                                            SQLGrant
	head                                             SQLHead
	references                                       []SQLReferenceRecord
	grantRaw, headRaw, grantSignature, headSignature []byte
	signedReferences                                 []SQLSignedReference
}

func (*SQLRecordSet) MarshalJSON() ([]byte, error) { return nil, ErrRecord }
func (*SQLRecordSet) String() string               { return "VerifiedOriginalMinIOSQLDeclarations" }

// VerifySQLRecordSet authenticates all seven original payloads against an
// INDEPENDENT pin, including exact hash DAG and purpose/ref/profile separation.
// It intentionally does not decide current time/state for original revoke or
// authorized history; actual controlled SQL consumers must still do that.
func VerifySQLRecordSet(pin SQLTrustPin, grant, grantSignature, head, headSignature []byte, refs []SQLSignedReference) (*SQLRecordSet, error) {
	if !validPin(pin) || len(refs) != 5 || len(grantSignature) != 64 || len(headSignature) != 64 || digest(grant) != pin.GrantSHA256 || !ed25519.Verify(pin.IssuerPublic, append([]byte(SQLGrantDomain), grant...), grantSignature) || !ed25519.Verify(pin.IssuerPublic, append([]byte(SQLHeadDomain), head...), headSignature) {
		return nil, ErrRecord
	}
	s := &SQLRecordSet{}
	if decode(grant, 262144, &s.grant) != nil || decode(head, 262144, &s.head) != nil {
		return nil, ErrRecord
	}
	g, h := s.grant, s.head
	if _, e := EncodeSQLGrant(g); e != nil {
		return nil, ErrRecord
	}
	if _, e := EncodeSQLHead(h); e != nil {
		return nil, ErrRecord
	}
	if g.Target != pin.Target || g.Enrollment != pin.Enrollment || g.AuthorityID != pin.AuthorityID || g.GrantID != pin.GrantID || g.RecordRevision != pin.GrantRevision || g.ReferenceSetSHA256 != pin.ReferenceSetSHA256 || h.Target != g.Target || h.Enrollment != g.Enrollment || h.AuthorityID != g.AuthorityID || h.CurrentGrantID != g.GrantID || h.CurrentGrantRevision != g.RecordRevision || h.PermissionEpoch != g.PermissionEpoch || h.PermissionEpoch < pin.MinimumPermissionEpoch || h.HeadRevision < pin.MinimumHeadRevision || h.GrantSHA256 != pin.GrantSHA256 || h.ReferenceSetSHA256 != g.ReferenceSetSHA256 || !h.NotBefore.Equal(g.NotBefore) || !h.Until.Equal(g.Until) {
		return nil, ErrRecord
	}
	seen := map[Digest]bool{g.PermissionSource.ObserverAccountSHA256: true}
	for n, purpose := range purposes() {
		v := refs[n]
		var r SQLReferenceRecord
		if v.Purpose != purpose || len(v.Signature) != 64 || digest(v.Record) != g.References[n].SHA256 || !ed25519.Verify(pin.IssuerPublic, append([]byte(SQLReferenceDomain), v.Record...), v.Signature) || decode(v.Record, 65536, &r) != nil {
			return nil, ErrRecord
		}
		if _, e := EncodeSQLReference(r); e != nil {
			return nil, ErrRecord
		}
		vref := r.Reference
		if r.Target != g.Target || r.Enrollment != g.Enrollment || r.AuthorityID != g.AuthorityID || r.GrantID != g.GrantID || r.RecordRevision != g.RecordRevision || r.PermissionEpoch != g.PermissionEpoch || r.ConfigSHA256 != g.ConfigSHA256 || vref.Purpose != purpose || vref.ProviderIdentityHash != g.Provider.IdentityHash || vref.NotBefore.After(g.NotBefore) || vref.Until.Before(g.Until) || seen[vref.AccountSHA256] || !nativeReferenceProfile(g, vref) {
			return nil, ErrRecord
		}
		seen[vref.AccountSHA256] = true
		s.references = append(s.references, r)
		s.signedReferences = append(s.signedReferences, SQLSignedReference{Purpose: purpose, Record: bytes.Clone(v.Record), Signature: bytes.Clone(v.Signature)})
	}
	artifact, catalog := s.references[0].Reference, s.references[3].Reference
	if artifact.Bucket == catalog.Bucket || artifact.Root != g.Target.InstallationID+"/" || !strings.HasPrefix(catalog.Root, g.Target.InstallationID+"/") || catalog.Root == artifact.Root || strings.HasPrefix(artifact.StagingRoot, artifact.Root) || strings.HasPrefix(artifact.Root, artifact.StagingRoot) {
		return nil, ErrRecord
	}
	for n, r := range s.references {
		v := r.Reference
		if n < 3 {
			if v.Bucket != artifact.Bucket || v.Root != artifact.Root || v.StagingRoot != artifact.StagingRoot {
				return nil, ErrRecord
			}
		} else if v.Bucket != catalog.Bucket || v.Root != catalog.Root {
			return nil, ErrRecord
		}
	}
	s.grantRaw, s.headRaw, s.grantSignature, s.headSignature = bytes.Clone(grant), bytes.Clone(head), bytes.Clone(grantSignature), bytes.Clone(headSignature)
	return s, nil
}

// Detached exposes comparison data only, never a SQL/native admission token.
func (s *SQLRecordSet) Detached() (SQLGrant, SQLHead, []SQLReferenceRecord, error) {
	if s == nil {
		return SQLGrant{}, SQLHead{}, nil, ErrRecord
	}
	var g SQLGrant
	var h SQLHead
	if decode(s.grantRaw, 262144, &g) != nil || decode(s.headRaw, 262144, &h) != nil {
		return SQLGrant{}, SQLHead{}, nil, ErrRecord
	}
	refs := []SQLReferenceRecord{}
	for _, v := range s.signedReferences {
		var r SQLReferenceRecord
		if decode(v.Record, 65536, &r) != nil {
			return SQLGrant{}, SQLHead{}, nil, ErrRecord
		}
		refs = append(refs, r)
	}
	return g, h, refs, nil
}

// EncodeSQLBundle freezes bounded canonical transport. It does NOT verify
// original issuer, current SQL CAS, native evidence or installation success.
func EncodeSQLBundle(b SQLBundle) ([]byte, error) {
	if b.Version != SQLBundleVersion || b.Action != SQLActionInstall && b.Action != SQLActionRevoke || !validDigest(b.PlanSHA256) || !validDigest(b.EnrollmentDocumentSHA256) || len(b.Grant) == 0 || len(b.Grant) > 262144 || len(b.Head) == 0 || len(b.Head) > 262144 || len(b.GrantSignature) != 64 || len(b.HeadSignature) != 64 || len(b.References) != 5 {
		return nil, ErrRecord
	}
	if b.Action == SQLActionInstall {
		if !reflect.DeepEqual(b.Expected, SQLExpected{}) {
			return nil, ErrRecord
		}
	} else {
		e := b.Expected
		if e.HeadRevision != 1 || e.PermissionEpoch != 1 || e.CurrentGrantRevision != 1 || !counter(e.HeadRowVersion) || !counter(e.GrantRowVersion) || !idSyntax.MatchString(e.CurrentGrantID) || e.State != StateActive || !validDigest(e.HeadSHA256) || !validDigest(e.GrantSHA256) || !validDigest(e.ReferenceSetSHA256) || len(e.ReferenceRows) != 5 {
			return nil, ErrRecord
		}
		for n, p := range purposes() {
			if e.ReferenceRows[n].Purpose != p || !validDigest(e.ReferenceRows[n].SHA256) || !counter(e.ReferenceRows[n].RowVersion) {
				return nil, ErrRecord
			}
		}
	}
	for n, p := range purposes() {
		v := b.References[n]
		if v.Purpose != p || len(v.Record) == 0 || len(v.Record) > 65536 || len(v.Signature) != 64 {
			return nil, ErrRecord
		}
	}
	raw, e := canonical(b)
	if e != nil || len(raw) > 2<<20 {
		return nil, ErrRecord
	}
	return raw, nil
}

func DecodeSQLBundle(raw []byte, expected Digest) (SQLBundle, error) {
	var b SQLBundle
	if !validDigest(expected) || digest(raw) != expected || decode(raw, 2<<20, &b) != nil {
		return SQLBundle{}, ErrRecord
	}
	if _, e := EncodeSQLBundle(b); e != nil {
		return SQLBundle{}, ErrRecord
	}
	return b, nil
}
