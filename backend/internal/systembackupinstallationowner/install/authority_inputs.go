package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	a "clawreef/internal/systembackupkekadapter"
	sec "clawreef/internal/systembackupsecurity"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RequestFiles are pinned offline sources, not approvals. The existing grant
// reader and config decoder authenticate their original complete request form.
type RequestFiles struct{ ConfigFile, ConfigFileSHA256, GrantFile, GrantFileSHA256, ObserverFile, ObserverFileSHA256 string }
type observerDocument struct {
	Endpoint, CASHA256, CAFile, ObserverPolicy, ObserverTokenFile, ObserverTokenSHA256, RuntimeJWTFile string
	Trust                                                                                              a.VaultJWTTrust
}
type originalRequest struct {
	files         RequestFiles
	grant         sec.OfflineBootstrapGrant
	config        sec.BootstrapConfig
	start, end    time.Time
	observer      *owner.CaptureSigningObserver
	caFile, caSHA string
}

func (s *authenticatedOperator) authority(ctx context.Context, pin EnrollmentPin) error {
	if !s.live(ctx) || s.installer.plan.InstallerDatabaseAccount == s.installer.plan.Target.DatabaseAccount || s.readEnrollment(ctx, pin) != nil {
		return ErrInstall
	}
	p := s.installer.plan
	access, e := s.installer.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: p.Target.Namespace, Verb: "update", Resource: "configmaps", Name: p.EnrollmentName}}}, metav1.CreateOptions{})
	if e != nil || !access.Status.Allowed || access.Status.Denied || access.Status.EvaluationError != "" {
		return ErrInstall
	}
	return nil
}
func readRequest(i *Installer, f RequestFiles) (*originalRequest, error) {
	raw, e := ReadPrivateFile(f.ConfigFile, 262144)
	if e != nil || hash(raw) != f.ConfigFileSHA256 {
		return nil, ErrInstall
	}
	c, e := sec.DecodeBootstrapConfig(raw)
	if e != nil {
		return nil, ErrInstall
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(c.CanonicalJSON(), &fields) != nil || !bytes.Equal(fields["enabled"], []byte("false")) {
		return nil, ErrInstall
	}
	grantRaw, e := ReadPrivateFile(f.GrantFile, 16384)
	if e != nil || hash(grantRaw) != f.GrantFileSHA256 {
		return nil, ErrInstall
	}
	g, start, end, e := sec.ReadBootstrapGrantFile(f.GrantFile, f.GrantFileSHA256)
	if e != nil || g.ConfigSHA256 != c.SHA256() {
		return nil, ErrInstall
	}
	docRaw, e := ReadPrivateFile(f.ObserverFile, 262144)
	if e != nil || hash(docRaw) != f.ObserverFileSHA256 {
		return nil, ErrInstall
	}
	var doc observerDocument
	if decodeExact(docRaw, &doc) != nil {
		return nil, ErrInstall
	}
	ca, e := ReadPrivateFile(doc.CAFile, 65536)
	if e != nil || hash(ca) != doc.CASHA256 {
		return nil, ErrInstall
	}
	o, e := owner.NewCaptureSigningObserver(owner.SigningObserverConfig{Endpoint: doc.Endpoint, CASHA256: doc.CASHA256, CAPEM: ca, ObserverPolicy: doc.ObserverPolicy, ObserverTokenFile: doc.ObserverTokenFile, ObserverTokenSHA256: doc.ObserverTokenSHA256, RuntimeJWTFile: doc.RuntimeJWTFile, Trust: doc.Trust, Kubernetes: i.kube})
	if e != nil {
		return nil, ErrInstall
	}
	return &originalRequest{files: f, grant: g, config: c, start: start, end: end, observer: o, caFile: doc.CAFile, caSHA: doc.CASHA256}, nil
}

// Local bounded byte checks only; safe before the final SQL clock. No
// observer construction, API/provider request or password hashing occurs here.
func (r *originalRequest) checkPinnedFiles() error {
	for _, entry := range []struct {
		path, sha string
		limit     int64
	}{{r.files.ConfigFile, r.files.ConfigFileSHA256, 262144}, {r.files.GrantFile, r.files.GrantFileSHA256, 16384}, {r.files.ObserverFile, r.files.ObserverFileSHA256, 262144}, {r.caFile, r.caSHA, 65536}} {
		raw, e := ReadPrivateFile(entry.path, entry.limit)
		if e != nil || hash(raw) != entry.sha {
			return ErrInstall
		}
	}
	return nil
}
func (r *originalRequest) recheck(i *Installer) error {
	again, e := readRequest(i, r.files)
	if e != nil {
		return e
	}
	defer again.observer.Close()
	if again.grant != r.grant || !bytes.Equal(again.config.CanonicalJSON(), r.config.CanonicalJSON()) || !again.start.Equal(r.start) || !again.end.Equal(r.end) {
		return ErrInstall
	}
	return nil
}
func (r *originalRequest) matchesDraft(record owner.Record) bool {
	g := r.grant
	grantJSON, e := json.Marshal(g)
	if e != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(r.config.CanonicalJSON(), &fields) != nil {
		return false
	}
	if g.InstallationID != record.Target.InstallationID || g.ServerUUID != record.Target.ServerUUID || g.Database != record.Target.Database || g.UserID != record.Actor.UserID || g.Username != record.Actor.Username || g.ConfigSHA256 != record.ConfigSHA256 || r.config.SHA256() != record.ConfigSHA256 || g.IdempotencyKey != record.IdempotencyKey || g.MatrixKey != record.MatrixKey || hash(grantJSON) != record.GrantSHA256 || hash(fields["registries"]) != record.RegistrySetSHA256 || hash(fields["references"]) != record.ReferenceSetSHA256 {
		return false
	}
	count := 0
	for _, ref := range r.config.References() {
		if ref.Purpose == "capture_signing" {
			if ref != record.Reference {
				return false
			}
			count++
		}
	}
	return count == 1
}
func (s *authenticatedOperator) matchesRecord(r owner.Record) bool {
	p := s.installer.plan
	return r.Target == p.Target && r.EnrollmentID == p.EnrollmentID && r.EnrollmentRevision == p.EnrollmentRevision && r.IssuerID == p.IssuerID && r.Actor.UserID == s.userID && r.Actor.Username == p.LocalAdminUsername && r.Actor.OwnerSubject == p.OwnerUsername
}
func (s *authenticatedOperator) pinFor(r owner.Record, recordSHA string, headRevision uint64) owner.TrustPin {
	p := s.installer.plan
	return owner.TrustPin{InstallationID: p.Target.InstallationID, EnrollmentID: p.EnrollmentID, IssuerID: p.IssuerID, EnrollmentRevision: p.EnrollmentRevision, MinimumHeadRevision: headRevision, Issuer: bytes.Clone(s.installer.public), ClusterID: p.Target.ClusterID, NamespaceUID: p.Target.NamespaceUID, OwnerSubject: p.OwnerUsername, ServerUUID: p.Target.ServerUUID, Database: p.Target.Database, DatabaseAccount: p.Target.DatabaseAccount, GrantID: r.GrantID, GrantRevision: r.Revision, RecordSHA256: recordSHA}
}
func (s *authenticatedOperator) privateKey(key []byte) (ed25519.PrivateKey, error) {
	if !s.live(s.ctx) || len(key) != ed25519.PrivateKeySize {
		return nil, ErrInstall
	}
	canonical := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(canonical, key) || !bytes.Equal(canonical[ed25519.SeedSize:], s.installer.public) {
		clear(canonical)
		return nil, ErrInstall
	}
	return canonical, nil
}
func samePin(a, b owner.TrustPin) bool { return reflect.DeepEqual(a, b) }
