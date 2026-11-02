package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"regexp"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// A candidate compatibility profile, NOT an observation of the installed
// server. The original release/tag and madmin v3.0.109 sources are pinned in
// the accompanying source evidence. Unknown versions/forks are refused.
const minioPermissionProfile = "minio-2025-04-22-builtin-flat.v1"
const minioPermissionVersion = "2025-04-22T22:12:26Z"
const minioPermissionCommit = "0d7408fc9969caf07de6a8c3a84f9fbb10a6739e"
const minioPermissionOwnerDomain = "system-backup-minio-permission-owner.v1\x00"
const minioPermissionHeadDomain = "system-backup-minio-permission-head.v1\x00"
const minioPermissionEngineDomain = "system-backup-minio-owner-configuration-observation.v1\x00"

// Input must be an independently installed startup pin, never an HTTP task,
// artifact field or pin calculated from the document being imported.
type MinIOPublicationPermissionInput struct{ File, SHA256 string }

type minioPermissionObject struct{ Name, UID string }
type minioPermissionProvider struct {
	Endpoint, Region, CAFile, CASHA256, SPKISHA256, DeploymentID string
	Deployment, ReplicaSet, Pod, Service, ServiceAccount         minioPermissionObject
	Container, ImageID, Node, NodeUID                            string
}
type minioPermissionPrincipal struct {
	Purpose, IdentityHash, RefVersion, AccountSHA256, PolicyName, PolicySHA256 string
}

// This config installs only an external public trust pin and read credential
// locator. It contains no signing private key and issues no permission. The
// owner grant/head/engine observation are read from the real configured API.
type minioPermissionConfiguration struct {
	Version, Installation, Namespace, NamespaceUID                  string
	Issuer                                                          ed25519.PublicKey
	MinimumEpoch                                                    uint64
	Grant, Head, Engine                                             minioPermissionObject
	GrantSHA256                                                     string
	ObserverCredentialFile, ObserverCredentialSHA256                string
	ObserverAccountSHA256, ObserverPolicyName, ObserverPolicySHA256 string
}
type minioPermissionGrant struct {
	Version, Installation, Namespace, NamespaceUID, ConfigSHA256, Profile string
	Epoch                                                                 uint64
	NotBefore, Until                                                      time.Time
	Provider                                                              minioPermissionProvider
	Principals                                                            []minioPermissionPrincipal
}
type minioPermissionHead struct {
	Version, Installation, State, GrantSHA256, EngineSHA256 string
	Epoch                                                   uint64
	NotBefore, Until                                        time.Time
}

// Native account/policy APIs do NOT expose a complete policy-engine state or
// an effective-permission oracle. This mandatory observation is issued by the
// independent ORIGINAL MinIO configuration owner after its authenticated
// get-config-kv observation. A missing native configuration observation is not
// replaced with a caller's disabled-plugin/Passed boolean. A/D must install
// this actual source and original current head; this reader cannot create it.
type minioPermissionEngine struct {
	Version, Installation, Endpoint, DeploymentID, ServerVersion, ServerCommit string
	SourceMethod, NativeResponseSHA256                                         string
	ObservedAt, Until                                                          time.Time
}
type minioPermissionOwnerState struct {
	grant  minioPermissionGrant
	engine minioPermissionEngine
	window publicationDependencyWindow
	stamp  string
}

type MinIOPublicationPermissionReader struct {
	input         MinIOPublicationPermissionInput
	configuration minioPermissionConfiguration
}

func minioPermissionFailure(stage string) error {
	return publicationDependencyFailure("minio-"+stage, nil)
}

func NewMinIOPublicationPermissionReader(input MinIOPublicationPermissionInput) (*MinIOPublicationPermissionReader, error) {
	raw, err := pinnedDeploymentFile(input.File, input.SHA256, 65536)
	var cfg minioPermissionConfiguration
	if err != nil || decodePublicationCanonical(raw, &cfg) != nil || cfg.Version != "minio-publication-permission-source.v1" || cfg.Installation == "" || cfg.Namespace == "" || cfg.NamespaceUID == "" || len(cfg.Issuer) != ed25519.PublicKeySize || cfg.MinimumEpoch == 0 || !formalCandidateDigest(cfg.GrantSHA256) || !formalCandidateDigest(cfg.ObserverCredentialSHA256) || !formalCandidateDigest(cfg.ObserverAccountSHA256) || !formalCandidateDigest(cfg.ObserverPolicySHA256) || !minioPermissionName(cfg.ObserverPolicyName) {
		return nil, minioPermissionFailure("independent-source-pin")
	}
	seen := map[string]bool{}
	for _, ref := range []minioPermissionObject{cfg.Grant, cfg.Head, cfg.Engine} {
		if !minioPermissionName(ref.Name) || ref.UID == "" || seen[ref.Name] {
			return nil, minioPermissionFailure("original-source-object-pin")
		}
		seen[ref.Name] = true
	}
	return &MinIOPublicationPermissionReader{input: input, configuration: cfg}, nil
}

func minioPermissionName(s string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(s)
}

func (r *MinIOPublicationPermissionReader) originalOwner(ctx context.Context, k kubernetes.Interface, now time.Time) (minioPermissionOwnerState, error) {
	var out minioPermissionOwnerState
	if r == nil || ctx == nil || ctx.Err() != nil || k == nil {
		return out, minioPermissionFailure("owner-source")
	}
	current, err := NewMinIOPublicationPermissionReader(r.input)
	if err != nil {
		return out, err
	}
	want, _ := ce.Canonical(r.configuration)
	got, _ := ce.Canonical(current.configuration)
	if string(want) != string(got) {
		return out, minioPermissionFailure("source-pin-drift")
	}
	cfg := r.configuration
	ns, err := k.CoreV1().Namespaces().Get(ctx, cfg.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != cfg.NamespaceUID || ns.DeletionTimestamp != nil {
		return out, minioPermissionFailure("owner-namespace")
	}
	read := func(ref minioPermissionObject, domain string, destination any) ([]byte, string, error) {
		cm, err := k.CoreV1().ConfigMaps(cfg.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil || string(cm.UID) != ref.UID || cm.Namespace != cfg.Namespace || cm.DeletionTimestamp != nil || cm.ResourceVersion == "" || len(cm.BinaryData) != 1 || len(cm.Data) != 1 {
			return nil, "", minioPermissionFailure("owner-object")
		}
		raw, signature := []byte(cm.Data["record.json"]), cm.BinaryData["signature"]
		if len(raw) == 0 || len(raw) > 32768 || len(signature) != ed25519.SignatureSize || !ed25519.Verify(cfg.Issuer, append([]byte(domain), raw...), signature) || decodePublicationCanonical(raw, destination) != nil {
			return nil, "", minioPermissionFailure("original-owner-signature")
		}
		return raw, string(cm.UID) + "/" + cm.ResourceVersion, nil
	}
	grantRaw, gs, err := read(cfg.Grant, minioPermissionOwnerDomain, &out.grant)
	if err != nil || hash(grantRaw) != cfg.GrantSHA256 {
		return out, minioPermissionFailure("original-owner-grant")
	}
	var head minioPermissionHead
	headRaw, hs, err := read(cfg.Head, minioPermissionHeadDomain, &head)
	if err != nil || head.Version != "minio-permission-head.v1" || head.Installation != cfg.Installation || head.Epoch < cfg.MinimumEpoch || head.State != "active" || head.GrantSHA256 != cfg.GrantSHA256 {
		return out, minioPermissionFailure("current-owner-head")
	}
	engineRaw, es, err := read(cfg.Engine, minioPermissionEngineDomain, &out.engine)
	if err != nil || hash(engineRaw) != head.EngineSHA256 {
		return out, minioPermissionFailure("policy-engine-observation-source")
	}
	g, e := out.grant, out.engine
	if g.Version != "minio-permission-grant.v1" || g.Installation != cfg.Installation || g.Namespace != cfg.Namespace || g.NamespaceUID != cfg.NamespaceUID || g.Epoch != head.Epoch || g.Profile != minioPermissionProfile {
		return out, minioPermissionFailure("owner-grant-binding")
	}
	if e.Version != "minio-owner-configuration-observation.v1" || e.Installation != g.Installation || e.Endpoint != g.Provider.Endpoint || e.DeploymentID != g.Provider.DeploymentID || e.ServerVersion != minioPermissionVersion || e.ServerCommit != minioPermissionCommit || e.SourceMethod != "minio-admin-v3/get-config-kv:identity+policy" || !formalCandidateDigest(e.NativeResponseSHA256) || e.Until.Sub(e.ObservedAt) > 30*time.Second {
		return out, minioPermissionFailure("effective-policy-engine-profile")
	}
	for _, bounds := range [][2]time.Time{{g.NotBefore, g.Until}, {head.NotBefore, head.Until}, {e.ObservedAt, e.Until}} {
		if out.window.include(now, bounds[0], bounds[1]) != nil {
			return out, minioPermissionFailure("original-owner-window")
		}
	}
	stamp, _ := ce.Canonical([]string{gs, hs, es, hash(grantRaw), hash(headRaw), hash(engineRaw)})
	out.stamp = hash(stamp)
	return out, nil
}
