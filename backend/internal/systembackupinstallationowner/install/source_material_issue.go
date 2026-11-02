package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"clawreef/internal/systembackup/worker"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SourceMaterialIntent is the independently selected original installation
// declaration. It authenticates who issues exact scoped metadata grants, not
// Redis/S3 permissions or source completeness. Those require actual observers.
type SourceMaterialIntent struct {
	DefinitionFile, DefinitionSHA256                         string
	InstallationID, Namespace, NamespaceUID, Purpose         string
	ServerUUID, Database, DatabaseAccount                    string
	DeploymentConfigSHA256, CaptureGrantSHA256, ConfigSHA256 string
	ControllerOwner                                          string
	ControllerDeployment, ControllerDeploymentUID            string
	ControllerServiceAccount, ControllerServiceAccountUID    string
	WorkerServiceAccount, WorkerServiceAccountUID            string
	SourceServiceAccount, SourceServiceAccountUID            string
	RedisScopeSHA256, RedisCredentialSHA256                  string
	ObjectScopeSHA256, ObjectCredentialSHA256                string
	NotBefore, Until                                         time.Time
}

// Same existing wire record as the production controller metadata consumer.
// This grant is domain-separated from capture certificates and owner records.
type ControllerSourceMetadataGrant struct {
	Version, InstallationID, ControllerOwner                              string
	DeploymentConfigSHA256, CaptureGrantSHA256, ConfigSHA256, ScopeSHA256 string
	Namespace, NamespaceUID                                               string
	ControllerDeployment, ControllerDeploymentUID                         string
	ControllerServiceAccount, ControllerServiceAccountUID                 string
	NotBefore, Until                                                      time.Time
	Revoked                                                               bool
}

type SourceMaterialIssuer struct {
	operator   *authenticatedOperator
	enrollment EnrollmentPin
	intent     SourceMaterialIntent
	initial    HeadCAS
}

func (*SourceMaterialIssuer) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*SourceMaterialIssuer) String() string               { return "AuthenticatedSourceMaterialIssuer" }

// PrepareSourceMaterialIssue uses the real original local administrator,
// Kubernetes subject/namespace/enrollment and current owner ledger sources.
// No capture-signing record is interpreted as a Redis/S3 capability.
func (i *Installer) PrepareSourceMaterialIssue(ctx context.Context, password []byte, enrollment EnrollmentPin, intent SourceMaterialIntent) (*SourceMaterialIssuer, error) {
	s, err := i.authenticate(ctx, password)
	if err != nil || s.authority(ctx, enrollment) != nil || intent.Purpose != "functional_test" || intent.InstallationID != i.plan.Target.InstallationID || intent.ServerUUID != i.plan.Target.ServerUUID || intent.Database != i.plan.Target.Database || intent.DatabaseAccount != i.plan.Target.DatabaseAccount || intent.Namespace != i.plan.Target.Namespace || intent.NamespaceUID != i.plan.Target.NamespaceUID || intent.ControllerOwner == "" || intent.ControllerDeployment == "" || intent.ControllerDeploymentUID == "" || intent.ControllerServiceAccount == "" || intent.ControllerServiceAccountUID == "" || intent.WorkerServiceAccount == "" || intent.WorkerServiceAccountUID == "" || intent.SourceServiceAccount == "" || intent.SourceServiceAccountUID == "" || intent.NotBefore.IsZero() || !intent.NotBefore.Before(intent.Until) || intent.Until.Sub(intent.NotBefore) > 24*time.Hour {
		return nil, ErrInstall
	}
	for _, hash := range []string{intent.DefinitionSHA256, intent.DeploymentConfigSHA256, intent.CaptureGrantSHA256, intent.ConfigSHA256, intent.RedisScopeSHA256, intent.RedisCredentialSHA256, intent.ObjectScopeSHA256, intent.ObjectCredentialSHA256} {
		if !digestPattern.MatchString(hash) {
			return nil, ErrInstall
		}
	}
	current, now, err := snapshot(ctx, s)
	if err != nil || now.Before(intent.NotBefore) || !now.Before(intent.Until) || current.cas.State == "revoked" || current.cas.HeadRevision > 0 && (now.Before(current.head.NotBefore) || !now.Before(current.head.Until) || intent.Until.After(current.head.Until)) {
		return nil, ErrInstall
	}
	p := &SourceMaterialIssuer{operator: s, enrollment: enrollment, intent: intent, initial: current.cas}
	if p.Recheck(ctx) != nil {
		return nil, ErrInstall
	}
	return p, nil
}

func (p *SourceMaterialIssuer) Recheck(ctx context.Context) error {
	if p == nil || p.operator == nil || !p.operator.live(ctx) || p.operator.authority(ctx, p.enrollment) != nil {
		return ErrInstall
	}
	raw, err := ReadSourceMaterialFile(p.intent.DefinitionFile)
	if err != nil || hash(raw) != p.intent.DefinitionSHA256 {
		return ErrInstall
	}
	current, now, err := snapshot(ctx, p.operator)
	if err != nil || current.cas != p.initial || now.Before(p.intent.NotBefore) || !now.Before(p.intent.Until) || current.cas.State == "revoked" {
		return ErrInstall
	}
	return p.checkActors(ctx)
}

// ReadSourceMaterialFile applies the same private regular-file identity checks
// as the installer input reader, with the controller's bounded 8 MiB material
// size. It never widens the existing installer plan/key/credential limits.
func ReadSourceMaterialFile(path string) ([]byte, error) {
	const limit = 8 << 20
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInstall
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit || runtime.GOOS == "linux" && before.Mode().Perm()&0077 != 0 {
		return nil, ErrInstall
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrInstall
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, ErrInstall
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || len(raw) > limit {
		clear(raw)
		return nil, ErrInstall
	}
	return raw, nil
}

// These are authenticated API reads, not caller-supplied UID claims. They
// establish the named delegation recipients, not running-writer completeness.
func (p *SourceMaterialIssuer) checkActors(ctx context.Context) error {
	i := p.intent
	kube := p.operator.installer.kube
	d, err := kube.AppsV1().Deployments(i.Namespace).Get(ctx, i.ControllerDeployment, metav1.GetOptions{})
	if err != nil || d == nil || d.DeletionTimestamp != nil || string(d.UID) != i.ControllerDeploymentUID || d.Namespace != i.Namespace || d.Spec.Template.Spec.ServiceAccountName != i.ControllerServiceAccount {
		return ErrInstall
	}
	for _, identity := range [][2]string{{i.ControllerServiceAccount, i.ControllerServiceAccountUID}, {i.WorkerServiceAccount, i.WorkerServiceAccountUID}, {i.SourceServiceAccount, i.SourceServiceAccountUID}} {
		sa, err := kube.CoreV1().ServiceAccounts(i.Namespace).Get(ctx, identity[0], metav1.GetOptions{})
		if err != nil || sa == nil || sa.DeletionTimestamp != nil || sa.Namespace != i.Namespace || string(sa.UID) != identity[1] {
			return ErrInstall
		}
	}
	return nil
}

func (p *SourceMaterialIssuer) SignWorkerSource(ctx context.Context, grant worker.FormalSourceGrant, issuerPrivate []byte) ([]byte, error) {
	if p.Recheck(ctx) != nil {
		return nil, ErrInstall
	}
	i := p.intent
	scope, credential := i.RedisScopeSHA256, i.RedisCredentialSHA256
	switch grant.Operation {
	case "capture-source-redis":
	case "capture-skill-objects":
		scope, credential = i.ObjectScopeSHA256, i.ObjectCredentialSHA256
	default:
		return nil, ErrInstall
	}
	if grant.Version != worker.FormalSourceGrantVersion || grant.InstallationID != i.InstallationID || grant.ConfigSHA256 != i.ConfigSHA256 || grant.WorkerNamespace != i.Namespace || grant.WorkerServiceAccountUID != i.WorkerServiceAccountUID || grant.ScopeSHA256 != scope || grant.CredentialSHA256 != credential || !grant.NotBefore.Equal(i.NotBefore) || !grant.Until.Equal(i.Until) || grant.Revoked {
		return nil, ErrInstall
	}
	key, err := p.operator.privateKey(issuerPrivate)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	record, err := json.Marshal(grant)
	if err != nil {
		return nil, ErrInstall
	}
	signature := ed25519.Sign(key, append([]byte(worker.FormalSourceGrantDomain), record...))
	if p.Recheck(ctx) != nil {
		return nil, ErrInstall
	}
	return json.Marshal(worker.SignedFormalSourceGrant{Record: record, Signature: signature})
}

func (p *SourceMaterialIssuer) SignControllerMetadata(ctx context.Context, grant ControllerSourceMetadataGrant, issuerPrivate []byte) ([]byte, error) {
	if p.Recheck(ctx) != nil {
		return nil, ErrInstall
	}
	i := p.intent
	if grant.Version != "system-backup-original-source-metadata-grant.v1" || grant.InstallationID != i.InstallationID || grant.ControllerOwner != i.ControllerOwner || grant.DeploymentConfigSHA256 != i.DeploymentConfigSHA256 || grant.CaptureGrantSHA256 != i.CaptureGrantSHA256 || grant.ConfigSHA256 != i.ConfigSHA256 || !digestPattern.MatchString(grant.ScopeSHA256) || grant.Namespace != i.Namespace || grant.NamespaceUID != i.NamespaceUID || grant.ControllerDeployment != i.ControllerDeployment || grant.ControllerDeploymentUID != i.ControllerDeploymentUID || grant.ControllerServiceAccount != i.ControllerServiceAccount || grant.ControllerServiceAccountUID != i.ControllerServiceAccountUID || !grant.NotBefore.Equal(i.NotBefore) || !grant.Until.Equal(i.Until) || grant.Revoked {
		return nil, ErrInstall
	}
	key, err := p.operator.privateKey(issuerPrivate)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	record, err := json.Marshal(grant)
	if err != nil {
		return nil, ErrInstall
	}
	signature := ed25519.Sign(key, append([]byte("system-backup-controller-source-metadata.v1\x00"), record...))
	if !bytes.Equal(key.Public().(ed25519.PublicKey), p.operator.installer.public) || p.Recheck(ctx) != nil {
		return nil, ErrInstall
	}
	return json.Marshal(struct{ Record, Signature []byte }{record, signature})
}
