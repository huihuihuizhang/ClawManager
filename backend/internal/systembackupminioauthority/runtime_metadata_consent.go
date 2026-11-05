package systembackupminioauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"os"
	"reflect"
	"time"

	c "clawreef/internal/systembackupcontroller"
	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const RuntimeMetadataConsentVersion = "original-minio-runtime-metadata-select-consent.v1"
const RuntimeMetadataConsentDomain = RuntimeMetadataConsentVersion + "\x00"

// This consent has exactly one fixed purpose: original MinIO metadata SELECT.
// It grants no capture, Generate, Unwrap, configuration or database DML.
type RuntimeMetadataWorkload struct {
	NamespaceUID, ControllerOwner               string
	Deployment, ReplicaSet, Pod, ServiceAccount ObjectIdentity
}
type RuntimeMetadataConsent struct {
	Version                                                                          string
	PinSHA256, RecoveryDescriptorSHA256, OriginalConfigSHA256, OriginalForwardSHA256 Digest
	ForwardIssuer                                                                    ed25519.PublicKey
	RuntimeDatabaseAccount                                                           string
	Workload                                                                         RuntimeMetadataWorkload
	Actor                                                                            Actor
	NotBefore, Until, SignedAt                                                       time.Time
}
type SignedRuntimeMetadataConsent struct{ Record, Signature []byte }
type RuntimeMetadataConsentSource struct {
	File, SHA256, OriginalForwardFile, OriginalForwardSHA256 string
}
type VerifiedRuntimeMetadataRead struct {
	origin            *VerifiedRuntimeMetadataRead
	ctx               context.Context
	source            RuntimeMetadataConsentSource
	raw               []byte
	descriptor        MinIORecoveryDescriptor
	record            RuntimeMetadataConsent
	current, original *c.PinnedExecutionIdentity
	until             time.Time
}

func (*VerifiedRuntimeMetadataRead) MarshalJSON() ([]byte, error) { return nil, ErrRecord }
func RuntimeMetadataPinSHA256(pin SQLTrustPin) (Digest, error) {
	raw, e := canonical(pin)
	if e != nil || !validPin(pin) {
		return "", ErrRecord
	}
	return digest(raw), nil
}
func DecodeRuntimeMetadataConsent(raw []byte, d MinIORecoveryDescriptor, descriptorSHA Digest) (RuntimeMetadataConsent, error) {
	var envelope SignedRuntimeMetadataConsent
	var r RuntimeMetadataConsent
	pin, e := RuntimeMetadataPinSHA256(d.Pin)
	if e != nil || !validRecoveryDescriptor(d) || !validDigest(descriptorSHA) || decode(raw, 65536, &envelope) != nil || !ed25519.Verify(d.Pin.IssuerPublic, append([]byte(RuntimeMetadataConsentDomain), envelope.Record...), envelope.Signature) || decode(envelope.Record, 32768, &r) != nil {
		return r, ErrRecord
	}
	if r.Version != RuntimeMetadataConsentVersion || r.PinSHA256 != pin || r.RecoveryDescriptorSHA256 != descriptorSHA || r.Actor != d.Actor || !validDigest(r.OriginalConfigSHA256) || !validDigest(r.OriginalForwardSHA256) || len(r.ForwardIssuer) != ed25519.PublicKeySize || !text(r.RuntimeDatabaseAccount) || r.RuntimeDatabaseAccount == d.Pin.Target.ConsumerDatabaseAccount || r.RuntimeDatabaseAccount == d.Actor.InstallerDatabaseAccount || !window(r.NotBefore, r.Until) || !validTime(r.SignedAt) || !r.SignedAt.Equal(r.NotBefore) || !r.SignedAt.Before(r.Until) || r.Workload.NamespaceUID != d.Pin.Target.NamespaceUID || !text(r.Workload.ControllerOwner) {
		return RuntimeMetadataConsent{}, ErrRecord
	}
	for _, id := range []ObjectIdentity{r.Workload.Deployment, r.Workload.ReplicaSet, r.Workload.Pod, r.Workload.ServiceAccount} {
		if !text(id.Name) || !text(id.UID) {
			return RuntimeMetadataConsent{}, ErrRecord
		}
	}
	return r, nil
}
func runtimeMetadataFile(path, sha string) ([]byte, error) {
	if !recoveryAbsolute(path) || !validDigest(Digest(sha)) {
		return nil, ErrRecord
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrRecord
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > 65536 {
		return nil, ErrRecord
	}
	raw, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(raw) == 0 || len(raw) > 65536 || digest(raw) != Digest(sha) {
		return nil, ErrRecord
	}
	return raw, nil
}

// Native comparison data only; issuance must authenticate its actual owner.
func CollectRuntimeMetadataWorkload(ctx context.Context, k kubernetes.Interface, target Target, deployment, podName, controllerOwner string) (RuntimeMetadataWorkload, error) {
	var zero RuntimeMetadataWorkload
	if ctx == nil || ctx.Err() != nil || k == nil {
		return zero, ErrRecord
	}
	ns, e := k.CoreV1().Namespaces().Get(ctx, target.Namespace, metav1.GetOptions{})
	if e != nil || string(ns.UID) != target.NamespaceUID || ns.DeletionTimestamp != nil {
		return zero, ErrRecord
	}
	dep, e := k.AppsV1().Deployments(target.Namespace).Get(ctx, deployment, metav1.GetOptions{})
	if e != nil || dep.UID == "" || dep.DeletionTimestamp != nil {
		return zero, ErrRecord
	}
	pod, e := k.CoreV1().Pods(target.Namespace).Get(ctx, podName, metav1.GetOptions{})
	if e != nil || pod.UID == "" || pod.DeletionTimestamp != nil || pod.Status.Phase != "Running" || pod.Spec.ServiceAccountName != dep.Spec.Template.Spec.ServiceAccountName || len(pod.OwnerReferences) != 1 {
		return zero, ErrRecord
	}
	owner := pod.OwnerReferences[0]
	if owner.Controller == nil || !*owner.Controller || owner.APIVersion != "apps/v1" || owner.Kind != "ReplicaSet" {
		return zero, ErrRecord
	}
	rs, e := k.AppsV1().ReplicaSets(target.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
	if e != nil || rs.DeletionTimestamp != nil || rs.UID != owner.UID || !recoveryOwned(rs.OwnerReferences, "Deployment", ObjectIdentity{dep.Name, string(dep.UID)}) {
		return zero, ErrRecord
	}
	sa, e := k.CoreV1().ServiceAccounts(target.Namespace).Get(ctx, pod.Spec.ServiceAccountName, metav1.GetOptions{})
	if e != nil || sa.UID == "" || sa.DeletionTimestamp != nil {
		return zero, ErrRecord
	}
	return RuntimeMetadataWorkload{target.NamespaceUID, controllerOwner, ObjectIdentity{dep.Name, string(dep.UID)}, ObjectIdentity{rs.Name, string(rs.UID)}, ObjectIdentity{pod.Name, string(pod.UID)}, ObjectIdentity{sa.Name, string(sa.UID)}}, nil
}

// Only trusted deployment locators and actual current Records.Keys are inputs.
// Native Kube work finishes before the caller opens its original SQL view.
func PrepareRuntimeMetadataRead(ctx context.Context, k kubernetes.Interface, d MinIORecoveryDescriptor, descriptorSHA Digest, source RuntimeMetadataConsentSource, current *c.PinnedExecutionIdentity) (*VerifiedRuntimeMetadataRead, error) {
	if ctx == nil || ctx.Err() != nil || !reflect.ValueOf(ctx).Comparable() || current == nil {
		return nil, ErrRecord
	}
	end, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrRecord
	}
	raw, e := runtimeMetadataFile(source.File, source.SHA256)
	if e != nil {
		return nil, ErrRecord
	}
	r, e := DecodeRuntimeMetadataConsent(raw, d, descriptorSHA)
	if e != nil || source.OriginalForwardSHA256 != string(r.OriginalForwardSHA256) {
		return nil, ErrRecord
	}
	old := current
	if current.GrantSHA256() != string(r.OriginalForwardSHA256) {
		old, e = current.OpenOriginalEnabledOnlyPredecessor(source.OriginalForwardFile, source.OriginalForwardSHA256)
		if e != nil {
			return nil, ErrRecord
		}
	} else {
		if _, e = runtimeMetadataFile(source.OriginalForwardFile, source.OriginalForwardSHA256); e != nil {
			return nil, ErrRecord
		}
	}
	g := old.DeploymentBinding()
	t := d.Pin.Target
	if g.ConfigVersion != 1 || g.ConfigSHA256 != string(r.OriginalConfigSHA256) || g.InstallationID != t.InstallationID || g.ServerUUID != t.ServerUUID || g.Database != t.Database || g.DatabaseAccount != r.RuntimeDatabaseAccount || g.ControllerOwner != r.Workload.ControllerOwner || r.Until.After(g.ExpiresAt) || r.NotBefore.Before(g.NotBefore) {
		return nil, ErrRecord
	}
	actual, e := CollectRuntimeMetadataWorkload(ctx, k, t, r.Workload.Deployment.Name, r.Workload.Pod.Name, g.ControllerOwner)
	if e != nil || actual != r.Workload {
		return nil, ErrRecord
	}
	if r.Until.Before(end) {
		end = r.Until
	}
	limit := time.Now().Add(25 * time.Second)
	if limit.Before(end) {
		end = limit
	}
	p := &VerifiedRuntimeMetadataRead{ctx: ctx, source: source, raw: bytes.Clone(raw), descriptor: d, record: r, current: current, original: old, until: end}
	p.origin = p
	if p.CheckLocal() != nil {
		return nil, ErrRecord
	}
	return p, nil
}
func (p *VerifiedRuntimeMetadataRead) CheckLocal() error {
	if p == nil || p.origin != p || p.ctx.Err() != nil || !time.Now().Before(p.until) {
		return ErrRecord
	}
	raw, e := runtimeMetadataFile(p.source.File, p.source.SHA256)
	if e != nil || !bytes.Equal(raw, p.raw) {
		return ErrRecord
	}
	if _, e = runtimeMetadataFile(p.source.OriginalForwardFile, p.source.OriginalForwardSHA256); e != nil {
		return ErrRecord
	}
	return nil
}
func (p *VerifiedRuntimeMetadataRead) Fingerprint() (Digest, error) {
	if p.CheckLocal() != nil {
		return "", ErrRecord
	}
	return digest(append(bytes.Clone(p.raw), []byte(p.current.GrantSHA256())...)), nil
}

// Private same-view account selection, never caller-supplied Passed/account.
type runtimeMetadataSQLUse struct {
	ctx       context.Context
	view      reg.SQLReadView
	authority *VerifiedRuntimeMetadataRead
}

func ReadSQLCurrentForOriginalRuntimeMetadata(ctx context.Context, view reg.SQLReadView, pin SQLTrustPin, p *VerifiedRuntimeMetadataRead) (*SQLCurrentSnapshot, string, error) {
	if p == nil || p.CheckLocal() != nil || ctx == nil || !reflect.ValueOf(ctx).Comparable() || view == nil || !reflect.ValueOf(view).Comparable() || ctx != p.ctx || !reflect.DeepEqual(pin, p.descriptor.Pin) {
		return nil, "", ErrRecord
	}
	account, server, database, now, e := sampleSQL(ctx, view)
	if e != nil || account != p.record.RuntimeDatabaseAccount || server != pin.Target.ServerUUID || database != pin.Target.Database || now.Before(p.record.NotBefore) || !now.Before(p.record.Until) {
		return nil, "", ErrRecord
	}
	var name, protocol string
	var secure bool
	if view.QueryRowContext(ctx, "SELECT @@require_secure_transport").Scan(&secure) != nil || !secure || view.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_version'").Scan(&name, &protocol) != nil || name != "Ssl_version" || protocol != "TLSv1.3" {
		return nil, "", ErrRecord
	}
	if p.original.CheckDeploymentInViewWithIssuer(ctx, view, p.record.ForwardIssuer) != nil || p.current.CheckDeploymentInViewWithIssuer(ctx, view, p.record.ForwardIssuer) != nil {
		return nil, "", ErrRecord
	}
	current := p.current.DeploymentBinding()
	fingerprint := ""
	var lineageUntil time.Time
	if p.current != p.original {
		if p.current.CheckOriginalEnabledOnlyPredecessorInView(ctx, view, p.original) != nil {
			return nil, "", ErrRecord
		}
		// State comes BEFORE original admin/head/ref locks, avoiding writer inversion.
		proof, e := sec.ReadOriginalEnabledOnlyLineage(ctx, view, pin.Target.InstallationID, string(p.record.OriginalConfigSHA256), current.ConfigVersion, current.ConfigSHA256)
		if e != nil {
			return nil, "", ErrRecord
		}
		sha, e := proof.AuthorizationConfigSHA256(ctx, view)
		actor, ae := proof.ActorID()
		until, ue := proof.OriginalDiagnosticUntil(ctx, view)
		if e != nil || ae != nil || ue != nil || sha != string(p.record.OriginalConfigSHA256) || actor != p.record.Actor.LocalAdminUserID || !now.Before(until) {
			return nil, "", ErrRecord
		}
		lineageUntil = until
		fingerprint, e = proof.Fingerprint()
		if e != nil {
			return nil, "", ErrRecord
		}
	}
	var username, role, provider string
	var active bool
	if view.QueryRowContext(ctx, `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE`, p.record.Actor.LocalAdminUserID).Scan(&username, &role, &active, &provider) != nil || username != p.record.Actor.LocalAdminUsername || role != "admin" || !active || provider != "local" {
		return nil, "", ErrRecord
	}
	use := &runtimeMetadataSQLUse{ctx: ctx, view: view, authority: p}
	snapshot, e := readSQLCurrentRuntime(ctx, view, pin, false, use)
	if e != nil {
		return nil, "", ErrRecord
	}
	g, h, _, e := snapshot.Declarations()
	_, clock, ce := snapshot.Comparison()
	if e != nil || ce != nil || snapshot.RequireCurrent(clock) != nil || g.Actor != p.record.Actor || g.ConfigSHA256 != p.record.OriginalConfigSHA256 || p.record.Until.After(g.Until) || p.record.Until.After(h.Until) || (!lineageUntil.IsZero() && !clock.Before(lineageUntil)) || !clock.Before(p.record.Until) || p.CheckLocal() != nil {
		return nil, "", ErrRecord
	}
	if p.original.CheckDeploymentInViewWithIssuer(ctx, view, p.record.ForwardIssuer) != nil || p.current.CheckDeploymentInViewWithIssuer(ctx, view, p.record.ForwardIssuer) != nil {
		return nil, "", ErrRecord
	}
	return snapshot, fingerprint, nil
}
