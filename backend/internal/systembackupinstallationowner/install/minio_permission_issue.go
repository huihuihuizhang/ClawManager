package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const MinIOPermissionProfileV2 = "minio-2025-04-22-builtin-flat.v2"
const MinIOPermissionDefinitionVersion = "original-minio-permission-definition.v2"
const minioGrantDomain = "system-backup-minio-permission-owner.v1\x00"
const minioHeadDomain = "system-backup-minio-permission-head.v1\x00"

// These transport declarations match the consumer wire schema. Neither a
// declaration nor an owner signature is a claim about native permissions.
type MinIOPermissionObject struct{ Name, UID string }
type MinIOPermissionProvider struct {
	Endpoint, Region, CAFile, CASHA256, SPKISHA256, DeploymentID string
	Deployment, ReplicaSet, Pod, Service, ServiceAccount         MinIOPermissionObject
	Container, ImageID, Node, NodeUID                            string
}
type MinIOPermissionPrincipal struct {
	Purpose, IdentityHash, RefVersion, AccountSHA256, PolicyName, PolicySHA256 string
}
type MinIOPermissionGrant struct {
	Version, Installation, Namespace, NamespaceUID, ConfigSHA256, Profile string
	Epoch                                                                 uint64
	NotBefore, Until                                                      time.Time
	Provider                                                              MinIOPermissionProvider
	Principals                                                            []MinIOPermissionPrincipal
}
type MinIOPermissionHead struct {
	Version, Installation, State, GrantSHA256, EngineSHA256 string
	Epoch                                                   uint64
	NotBefore, Until                                        time.Time
}

// Existing original material locators; no credentials, private signing key,
// inferred current/latest reference or caller Passed field belongs here.
type MinIOPermissionDefinition struct {
	Version, ConfigFile, ConfigSHA256, TargetFile, TargetSHA256     string
	GrantName, HeadName                                             string
	Grant                                                           MinIOPermissionGrant
	ObserverCredentialFile, ObserverCredentialSHA256                string
	ObserverAccountSHA256, ObserverPolicyName, ObserverPolicySHA256 string
}

type MinIOPermissionIssuer struct {
	operator   *authenticatedOperator
	enrollment EnrollmentPin
	definition MinIOPermissionDefinition
	file, sha  string
	initial    HeadCAS
}

func (*MinIOPermissionIssuer) String() string               { return "AuthenticatedMinIOPermissionIssuer" }
func (*MinIOPermissionIssuer) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

func DecodeMinIOPermissionDefinition(raw []byte, sha string) (MinIOPermissionDefinition, error) {
	var d MinIOPermissionDefinition
	if !digestPattern.MatchString(sha) || hash(raw) != sha || decodeExact(raw, &d) != nil || !minioPermissionDefinitionProfile(d) || d.Grant.Version != "minio-permission-grant.v1" || d.Grant.Epoch != 1 || d.GrantName == d.HeadName || len(validation.IsDNS1123Subdomain(d.GrantName)) != 0 || len(validation.IsDNS1123Subdomain(d.HeadName)) != 0 || d.GrantName == "" || d.HeadName == "" || d.Grant.ConfigSHA256 != d.ConfigSHA256 || len(d.Grant.Principals) != 5 || d.Grant.NotBefore.IsZero() || !d.Grant.NotBefore.Before(d.Grant.Until) || d.Grant.Until.Sub(d.Grant.NotBefore) > 24*time.Hour || !namePattern.MatchString(d.ObserverPolicyName) {
		return MinIOPermissionDefinition{}, ErrInstall
	}
	for _, v := range []string{d.ConfigSHA256, d.TargetSHA256, d.ObserverCredentialSHA256, d.ObserverAccountSHA256, d.ObserverPolicySHA256, d.Grant.Provider.CASHA256, d.Grant.Provider.SPKISHA256} {
		if !digestPattern.MatchString(v) {
			return MinIOPermissionDefinition{}, ErrInstall
		}
	}
	seen := map[string]bool{d.ObserverAccountSHA256: true}
	purposes := map[string]bool{}
	for _, p := range d.Grant.Principals {
		if !digestPattern.MatchString(p.IdentityHash) || !digestPattern.MatchString(p.AccountSHA256) || !digestPattern.MatchString(p.PolicySHA256) || !namePattern.MatchString(p.PolicyName) || p.RefVersion == "" || p.RefVersion == "current" || p.RefVersion == "latest" || seen[p.AccountSHA256] || purposes[p.Purpose] {
			return MinIOPermissionDefinition{}, ErrInstall
		}
		seen[p.AccountSHA256] = true
		purposes[p.Purpose] = true
	}
	for _, p := range []string{"artifact_read", "artifact_write", "artifact_delete", "catalog_read", "catalog_append"} {
		if !purposes[p] {
			return MinIOPermissionDefinition{}, ErrInstall
		}
	}
	return d, nil
}

// Authenticate an EXISTING enrollment and the real original SQL local admin
// and Kubernetes subject. No enrollment, user, policy or SQL mutation occurs.
func (i *Installer) PrepareMinIOPermissionIssue(ctx context.Context, password []byte, enrollment EnrollmentPin, file, sha string) (*MinIOPermissionIssuer, error) {
	raw, e := ReadSourceMaterialFile(file)
	if e != nil {
		return nil, ErrInstall
	}
	d, e := DecodeMinIOPermissionDefinition(raw, sha)
	if e != nil {
		return nil, ErrInstall
	}
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil || d.Grant.Installation != i.plan.Target.InstallationID || d.Grant.Namespace != i.plan.Target.Namespace || d.Grant.NamespaceUID != i.plan.Target.NamespaceUID {
		return nil, ErrInstall
	}
	current, now, e := snapshot(ctx, s)
	if e != nil || current.cas.State == "revoked" || now.Before(d.Grant.NotBefore) || !now.Before(d.Grant.Until) || current.cas.HeadRevision > 0 && (now.Before(current.head.NotBefore) || !now.Before(current.head.Until) || d.Grant.Until.After(current.head.Until)) {
		return nil, ErrInstall
	}
	p := &MinIOPermissionIssuer{s, enrollment, d, file, sha, current.cas}
	if p.Recheck(ctx) != nil {
		return nil, ErrInstall
	}
	for _, name := range []string{d.GrantName, d.HeadName} {
		_, e := i.kube.CoreV1().ConfigMaps(d.Grant.Namespace).Get(ctx, name, metav1.GetOptions{})
		if !apierrors.IsNotFound(e) {
			return nil, ErrInstall
		}
	}
	return p, nil
}

func (p *MinIOPermissionIssuer) Recheck(ctx context.Context) error {
	if p == nil || p.operator == nil || p.operator.authority(ctx, p.enrollment) != nil {
		return ErrInstall
	}
	raw, e := ReadSourceMaterialFile(p.file)
	if e != nil || hash(raw) != p.sha {
		return ErrInstall
	}
	for _, f := range [][2]string{{p.definition.ConfigFile, p.definition.ConfigSHA256}, {p.definition.TargetFile, p.definition.TargetSHA256}, {p.definition.ObserverCredentialFile, p.definition.ObserverCredentialSHA256}} {
		raw, e := ReadSourceMaterialFile(f[0])
		if e != nil || hash(raw) != f[1] {
			clear(raw)
			return ErrInstall
		}
		clear(raw)
	}
	c, now, e := snapshot(ctx, p.operator)
	if e != nil || c.cas != p.initial || c.cas.State == "revoked" || now.Before(p.definition.Grant.NotBefore) || !now.Before(p.definition.Grant.Until) {
		return ErrInstall
	}
	return nil
}

type MinIOPermissionCommit struct {
	Issuer                  ed25519.PublicKey
	Grant, Head             MinIOPermissionObject
	GrantSHA256, HeadSHA256 string
	Epoch                   uint64
}

// CreateOriginal is deliberately initial-install-only. It signs exactly the
// independently pinned definition with the existing enrolled key, then uses
// Kubernetes Create (never Apply/Update) for two NEW owner-named resources.
// Partial/unknown commits return ErrCommitUnknown and must be inspected; a
// retry never overwrites a previous resource or invents a new epoch.
func (p *MinIOPermissionIssuer) CreateOriginal(ctx context.Context, issuerPrivate []byte) (MinIOPermissionCommit, error) {
	var zero MinIOPermissionCommit
	if p.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	key, e := p.operator.privateKey(issuerPrivate)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	d := p.definition
	grant, e := canonical(d.Grant)
	if e != nil {
		return zero, ErrInstall
	}
	head, e := canonical(MinIOPermissionHead{Version: "minio-permission-head.v1", Installation: d.Grant.Installation, State: "active", GrantSHA256: hash(grant), Epoch: 1, NotBefore: d.Grant.NotBefore, Until: d.Grant.Until})
	if e != nil {
		return zero, ErrInstall
	}
	values := []struct {
		name      string
		raw       []byte
		domain    string
		immutable bool
	}{{d.GrantName, grant, minioGrantDomain, true}, {d.HeadName, head, minioHeadDomain, false}}
	committed := []MinIOPermissionObject{}
	for _, v := range values {
		if p.Recheck(ctx) != nil {
			if len(committed) > 0 {
				return zero, ErrCommitUnknown
			}
			return zero, ErrInstall
		}
		sig := ed25519.Sign(key, append([]byte(v.domain), v.raw...))
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: v.name, Namespace: d.Grant.Namespace}, Immutable: &v.immutable, Data: map[string]string{"record.json": string(v.raw)}, BinaryData: map[string][]byte{"signature": sig}}
		created, e := p.operator.installer.kube.CoreV1().ConfigMaps(d.Grant.Namespace).Create(ctx, cm, metav1.CreateOptions{})
		if e != nil || created == nil || created.UID == "" {
			return zero, ErrCommitUnknown
		}
		back, e := p.operator.installer.kube.CoreV1().ConfigMaps(d.Grant.Namespace).Get(ctx, v.name, metav1.GetOptions{})
		if e != nil || back == nil || back.UID != created.UID || back.ResourceVersion == "" || back.DeletionTimestamp != nil || back.Namespace != d.Grant.Namespace || len(back.Data) != 1 || len(back.BinaryData) != 1 || back.Data["record.json"] != string(v.raw) || !bytes.Equal(back.BinaryData["signature"], sig) || back.Immutable == nil || *back.Immutable != v.immutable {
			return zero, ErrCommitUnknown
		}
		committed = append(committed, MinIOPermissionObject{v.name, string(back.UID)})
	}
	if p.Recheck(ctx) != nil {
		return zero, ErrCommitUnknown
	}
	// Re-read BOTH after the head exists, including exact epoch/signatures.
	for n, v := range values {
		back, e := p.operator.installer.kube.CoreV1().ConfigMaps(d.Grant.Namespace).Get(ctx, v.name, metav1.GetOptions{})
		if e != nil || back == nil || string(back.UID) != committed[n].UID || back.ResourceVersion == "" || back.DeletionTimestamp != nil || len(back.Data) != 1 || len(back.BinaryData) != 1 || back.Data["record.json"] != string(v.raw) || !ed25519.Verify(p.operator.installer.public, append([]byte(v.domain), v.raw...), back.BinaryData["signature"]) {
			return zero, ErrCommitUnknown
		}
	}
	return MinIOPermissionCommit{bytes.Clone(p.operator.installer.public), committed[0], committed[1], hash(grant), hash(head), 1}, nil
}

// Export only generated startup bytes. The caller must still use the native
// permission producer/consumer; exporting is never permission admission.
func SaveMinIOPermissionStartup(directory string, raw []byte) error {
	var fields map[string]json.RawMessage
	if len(raw) > 65536 || json.Unmarshal(raw, &fields) != nil || fields["Version"] == nil {
		return ErrInstall
	}
	return writeNewFiles(directory, map[string][]byte{"minio-permission.source.json": raw})
}

func CheckNewMinIOPermissionDirectory(directory string) error {
	if privateDirectory(directory) != nil {
		return ErrInstall
	}
	if _, err := os.Lstat(filepath.Join(directory, "minio-permission.source.json")); !os.IsNotExist(err) {
		return ErrInstall
	}
	return nil
}
