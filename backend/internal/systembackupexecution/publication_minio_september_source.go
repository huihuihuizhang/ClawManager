package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	ma "clawreef/internal/systembackupminioauthority"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// September has a separate original source version and signed permission profile.
func newMinIOSeptemberPermissionReader(input MinIOPublicationPermissionInput) (*MinIOPublicationPermissionReader, error) {
	raw, err := pinnedDeploymentFile(input.File, input.SHA256, 65536)
	var cfg minioEffectivePermissionConfiguration
	if err != nil || decodePublicationCanonical(raw, &cfg) != nil || cfg.Version != "minio-publication-september-effective-permission-source.v1" || cfg.Installation == "" || cfg.Namespace == "" || cfg.NamespaceUID == "" || len(cfg.Issuer) != ed25519.PublicKeySize || cfg.MinimumEpoch == 0 || !formalCandidateDigest(cfg.GrantSHA256) || !formalCandidateDigest(cfg.ObserverCredentialSHA256) || !formalCandidateDigest(cfg.ObserverAccountSHA256) || !formalCandidateDigest(cfg.ObserverPolicySHA256) || !minioPermissionName(cfg.ObserverPolicyName) || !minioPermissionName(cfg.Grant.Name) || !minioPermissionName(cfg.Head.Name) || cfg.Grant.UID == "" || cfg.Head.UID == "" || cfg.Grant.Name == cfg.Head.Name {
		return nil, minioPermissionFailure("effective-independent-source-pin")
	}
	shared := minioPermissionConfiguration{Version: cfg.Version, Installation: cfg.Installation, Namespace: cfg.Namespace, NamespaceUID: cfg.NamespaceUID, Issuer: cfg.Issuer, MinimumEpoch: cfg.MinimumEpoch, Grant: cfg.Grant, Head: cfg.Head, GrantSHA256: cfg.GrantSHA256, ObserverCredentialFile: cfg.ObserverCredentialFile, ObserverCredentialSHA256: cfg.ObserverCredentialSHA256, ObserverAccountSHA256: cfg.ObserverAccountSHA256, ObserverPolicyName: cfg.ObserverPolicyName, ObserverPolicySHA256: cfg.ObserverPolicySHA256}
	return &MinIOPublicationPermissionReader{input: input, configuration: shared}, nil
}

// Read the ORIGINAL externally pinned permission owner and current revocable
// head. EngineSHA256 is intentionally not used as a permission assertion in
// this source: current effective policy comes from actual native self reads.
// This method neither creates a source nor signs/enrolls a grant or head.
func (r *MinIOPublicationPermissionReader) effectiveOwnerSeptember(ctx context.Context, k kubernetes.Interface, now time.Time) (minioPermissionOwnerState, error) {
	var out minioPermissionOwnerState
	if ctx == nil || ctx.Err() != nil || r == nil || k == nil {
		return out, minioPermissionFailure("effective-owner-source")
	}
	current, err := newMinIOSeptemberPermissionReader(r.input)
	if err != nil {
		return out, err
	}
	want, _ := ce.Canonical(r.configuration)
	got, _ := ce.Canonical(current.configuration)
	if string(want) != string(got) {
		return out, minioPermissionFailure("effective-source-pin-drift")
	}
	cfg := r.configuration
	ns, err := k.CoreV1().Namespaces().Get(ctx, cfg.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != cfg.NamespaceUID || ns.DeletionTimestamp != nil {
		return out, minioPermissionFailure("effective-original-namespace")
	}
	read := func(ref minioPermissionObject, domain string, dst any) ([]byte, string, error) {
		cm, err := k.CoreV1().ConfigMaps(cfg.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil || cm.Namespace != cfg.Namespace || string(cm.UID) != ref.UID || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || len(cm.Data) != 1 || len(cm.BinaryData) != 1 {
			return nil, "", minioPermissionFailure("effective-owner-object")
		}
		raw := []byte(cm.Data["record.json"])
		sig := cm.BinaryData["signature"]
		if len(raw) == 0 || len(raw) > 32768 || decodePublicationCanonical(raw, dst) != nil || !ed25519.Verify(cfg.Issuer, append([]byte(domain), raw...), sig) {
			return nil, "", minioPermissionFailure("effective-owner-signature")
		}
		return raw, cm.ResourceVersion, nil
	}
	g, gv, err := read(cfg.Grant, minioPermissionOwnerDomain, &out.grant)
	if err != nil || hash(g) != cfg.GrantSHA256 {
		return out, minioPermissionFailure("effective-original-owner-grant")
	}
	var head minioPermissionHead
	h, hv, err := read(cfg.Head, minioPermissionHeadDomain, &head)
	if err != nil || head.Version != "minio-permission-head.v1" || head.Installation != cfg.Installation || head.State != "active" || head.GrantSHA256 != cfg.GrantSHA256 || head.Epoch < cfg.MinimumEpoch || out.grant.Version != "minio-permission-grant.v1" || out.grant.Installation != cfg.Installation || out.grant.Namespace != cfg.Namespace || out.grant.NamespaceUID != cfg.NamespaceUID || out.grant.Epoch != head.Epoch || out.grant.Profile != ma.SeptemberPermissionProfile || out.window.include(now, out.grant.NotBefore, out.grant.Until) != nil || out.window.include(now, head.NotBefore, head.Until) != nil {
		return out, minioPermissionFailure("effective-current-owner-head")
	}
	stamp, _ := ce.Canonical([]string{cfg.NamespaceUID, cfg.Grant.UID, cfg.Head.UID, hash(g), hash(h), gv, hv})
	out.stamp = hash(stamp)
	return out, nil
}
