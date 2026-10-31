package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	c "clawreef/internal/systembackup"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const sourceMetadataGrantVersion = "system-backup-original-source-metadata-grant.v1"
const sourceMetadataGrantDomain = "system-backup-controller-source-metadata.v1\x00"

// An independently source-owner-signed controller delegation. It has no
// Invocation, future Job, key-use nonce or permission to Generate/Unwrap.
type productionSourceDiscovery struct {
	GrantFile, GrantSHA256                                string
	Issuer                                                ed25519.PublicKey
	ControllerDeployment, ControllerDeploymentUID         string
	ControllerServiceAccount, ControllerServiceAccountUID string
	SourceAPI                                             worker.ResourceSourceMount
	SourceAPITokenSHA256                                  string
	SourceAPIServiceAccount, SourceAPIServiceAccountUID   string
	Redis                                                 c.RedisCapturePolicy
	RuntimePolicies                                       []worker.RuntimePolicy
	ResourceActors                                        map[string]productionSourceActor
	TeamPlatformUnits                                     map[string][]string
	RuntimeImageReferences                                map[string]string
}

type productionSourceActor struct{ Name, UID string }

type originalSourceMetadataGrant struct {
	Version, InstallationID, ControllerOwner                              string
	DeploymentConfigSHA256, CaptureGrantSHA256, ConfigSHA256, ScopeSHA256 string
	Namespace, NamespaceUID                                               string
	ControllerDeployment, ControllerDeploymentUID                         string
	ControllerServiceAccount, ControllerServiceAccountUID                 string
	NotBefore, Until                                                      time.Time
	Revoked                                                               bool
}

type signedSourceMetadataGrant struct{ Record, Signature []byte }

type originalSourceMetadataAuthority struct {
	service *DeploymentService
	owner   *PublicJobOwner
	input   d.Input
	grant   originalSourceMetadataGrant
	scope   string
	until   time.Time
}

func sourceMetadataScope(materials productionCaptureMaterials) (string, error) {
	if materials.Discovery == nil {
		return "", d.ErrNotReady
	}
	copy := *materials.Discovery
	// Only the later signed envelope is omitted: core -> Forward -> worker
	// sources -> metadata scope -> owner envelope -> independently pinned bundle.
	copy.GrantFile, copy.GrantSHA256 = "", ""
	materials.Discovery = &copy
	raw, err := json.Marshal(materials)
	if err != nil || len(raw) > 8<<20 {
		return "", d.ErrNotReady
	}
	return hash(raw), nil
}

func (x productionSourceDiscovery) validate() error {
	if len(x.Issuer) != ed25519.PublicKeySize || !filepath.IsAbs(x.GrantFile) || filepath.Clean(x.GrantFile) != x.GrantFile || !formalCandidateDigest(x.GrantSHA256) || x.ControllerDeployment == "" || x.ControllerDeploymentUID == "" || x.ControllerServiceAccount == "" || x.ControllerServiceAccountUID == "" || x.SourceAPIServiceAccount == "" || x.SourceAPIServiceAccountUID == "" || !formalCandidateDigest(x.SourceAPITokenSHA256) || x.Redis.Validate() != nil || len(x.RuntimePolicies) < 1 || len(x.RuntimePolicies) > 128 || len(x.ResourceActors) != 2 {
		return d.ErrNotReady
	}
	u, err := url.Parse(x.SourceAPI.Server)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" || !validMetadataFile(x.SourceAPI.CAFile) || !validMetadataFile(x.SourceAPI.TokenFile) || !formalCandidateDigest(x.SourceAPI.CASHA256) || len(x.TeamPlatformUnits) == 0 || len(x.TeamPlatformUnits) > 128 {
		return d.ErrNotReady
	}
	units := map[string]bool{}
	for _, unit := range b.TeamsWorkUnits() {
		units[unit] = false
	}
	for id, list := range x.TeamPlatformUnits {
		if !strings.HasPrefix(id, "deployment/") || len(list) == 0 || len(list) > len(units) {
			return d.ErrNotReady
		}
		seen := map[string]bool{}
		for _, unit := range list {
			if _, ok := units[unit]; !ok || seen[unit] {
				return d.ErrNotReady
			}
			seen[unit] = true
			units[unit] = true
		}
	}
	for _, covered := range units {
		if !covered {
			return d.ErrNotReady
		}
	}
	images := map[string]bool{}
	for _, part := range []string{"deployment_resources", "secret_bundle"} {
		if x.ResourceActors[part].Name == "" || x.ResourceActors[part].UID == "" {
			return d.ErrNotReady
		}
	}
	for _, p := range x.RuntimePolicies {
		if p.Validate() != nil {
			return d.ErrNotReady
		}
		images[p.Image] = true
	}
	for ref, image := range x.RuntimeImageReferences {
		var source productionRuntimeImageSource
		if ref == "" || len(ref) > 4096 || strings.ContainsAny(ref, "\x00\r\n") || !images[image] || decodeMetadataCanonical([]byte(ref), &source) != nil || source.Version != productionRuntimeImageSourceVersion {
			return d.ErrNotReady
		}
		matched := false
		for _, policy := range x.RuntimePolicies {
			matched = matched || policy.Image == image && policy.Runtime == source.Runtime
		}
		if !matched {
			return d.ErrNotReady
		}
	}
	if x.ResourceActors["deployment_resources"].UID == x.ResourceActors["secret_bundle"].UID || x.SourceAPIServiceAccountUID == x.ResourceActors["deployment_resources"].UID || x.SourceAPIServiceAccountUID == x.ResourceActors["secret_bundle"].UID {
		return d.ErrNotReady
	}
	return nil
}

func (s *DeploymentService) sourceMetadataAuthority(ctx context.Context, owner *PublicJobOwner, in d.Input) (*originalSourceMetadataAuthority, error) {
	if s == nil || owner == nil || in.Authority.TaskType != "backup" || in.Authority.Phase != "capture" || s.checkProductionCaptureMaterials() != nil || s.captureMaterials.Discovery == nil || s.captureMaterials.Discovery.validate() != nil {
		return nil, d.ErrNotReady
	}
	scope, err := sourceMetadataScope(*s.captureMaterials)
	if err != nil {
		return nil, err
	}
	raw, err := pinnedDeploymentFile(s.captureMaterials.Discovery.GrantFile, s.captureMaterials.Discovery.GrantSHA256, 65536)
	if err != nil {
		return nil, d.ErrNotReady
	}
	var envelope signedSourceMetadataGrant
	if decodeMetadataCanonical(raw, &envelope) != nil || len(envelope.Record) < 2 || len(envelope.Record) > 32768 || len(envelope.Signature) != ed25519.SignatureSize || !ed25519.Verify(s.captureMaterials.Discovery.Issuer, append([]byte(sourceMetadataGrantDomain), envelope.Record...), envelope.Signature) {
		return nil, d.ErrNotReady
	}
	var grant originalSourceMetadataGrant
	if decodeMetadataCanonical(envelope.Record, &grant) != nil {
		return nil, d.ErrNotReady
	}
	x := &originalSourceMetadataAuthority{service: s, owner: owner, input: in, grant: grant, scope: scope, until: in.Authority.DeadlineAt}
	if grant.Until.Before(x.until) {
		x.until = grant.Until
	}
	if x.Recheck(ctx) != nil {
		return nil, d.ErrNotReady
	}
	return x, nil
}

func decodeMetadataCanonical(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return d.ErrNotReady
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, raw) {
		return d.ErrNotReady
	}
	return nil
}

func (x *originalSourceMetadataAuthority) checkLocal(ctx context.Context) error {
	if x == nil || ctx == nil || ctx.Err() != nil || x.service == nil || x.owner == nil || x.owner.Client == nil || !time.Now().Before(x.until) || x.service.checkProductionCaptureMaterials() != nil {
		return d.ErrNotReady
	}
	s, m, g := x.service, x.service.captureMaterials, x.grant
	if m.Discovery == nil || m.Discovery.validate() != nil {
		return d.ErrNotReady
	}
	p := m.Discovery
	for _, mount := range []worker.FormalSourceMount{m.Redis, m.Objects} {
		raw, err := readPrivate(mount.CredentialFile, 64<<10)
		if err != nil || hash(raw) != mount.CredentialSHA256 {
			clear(raw)
			return d.ErrNotReady
		}
		clear(raw)
		if _, err := pinnedDeploymentFile(mount.GrantFile, mount.GrantSHA256, 65536); err != nil {
			return d.ErrNotReady
		}
		mapping := mount.Redis
		if mapping == nil {
			mapping = mount.Objects
		}
		if mapping == nil {
			return d.ErrNotReady
		}
		if _, err := sourceMetadataTLS(*mapping); err != nil {
			return d.ErrNotReady
		}
	}
	token, err := readPrivate(p.SourceAPI.TokenFile, 64<<10)
	if err != nil || hash(token) != p.SourceAPITokenSHA256 {
		clear(token)
		return d.ErrNotReady
	}
	clear(token)
	if _, err := pinnedDeploymentFile(p.SourceAPI.CAFile, p.SourceAPI.CASHA256, 1<<20); err != nil {
		return d.ErrNotReady
	}
	observed, err := sourceMetadataScope(*m)
	if err != nil || observed != x.scope || g.ScopeSHA256 != x.scope || g.Version != sourceMetadataGrantVersion || g.InstallationID != s.Config.InstallationID || g.ControllerOwner != s.Config.ControllerOwner || g.DeploymentConfigSHA256 != s.ConfigDigest || g.CaptureGrantSHA256 != s.Forward.GrantSHA256() || g.ConfigSHA256 != x.input.Authority.ConfigSHA256 || g.Namespace != s.Config.Namespace || g.NamespaceUID != s.Config.NamespaceUID || g.ControllerDeployment != p.ControllerDeployment || g.ControllerDeploymentUID != p.ControllerDeploymentUID || g.ControllerServiceAccount != p.ControllerServiceAccount || g.ControllerServiceAccountUID != p.ControllerServiceAccountUID || g.Revoked || g.NotBefore.IsZero() || time.Now().Before(g.NotBefore) || g.Until.Sub(g.NotBefore) > 24*time.Hour {
		return d.ErrNotReady
	}
	raw, err := pinnedDeploymentFile(p.GrantFile, p.GrantSHA256, 65536)
	if err != nil {
		return d.ErrNotReady
	}
	var signed signedSourceMetadataGrant
	var original originalSourceMetadataGrant
	if decodeMetadataCanonical(raw, &signed) != nil || decodeMetadataCanonical(signed.Record, &original) != nil || original != g || !ed25519.Verify(p.Issuer, append([]byte(sourceMetadataGrantDomain), signed.Record...), signed.Signature) {
		return d.ErrNotReady
	}
	return x.owner.Gate.Authority.Check(ctx, x.input.Authority)
}

func (x *originalSourceMetadataAuthority) Recheck(ctx context.Context) error {
	if x.checkLocal(ctx) != nil {
		return d.ErrNotReady
	}
	s, p := x.service, x.service.captureMaterials.Discovery
	actor := s.controllerActor
	if actor.PodName == "" || actor.PodUID == "" || actor.ServiceAccountName != p.ControllerServiceAccount {
		return d.ErrNotReady
	}
	ns, err := x.owner.Client.CoreV1().Namespaces().Get(ctx, s.Config.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != s.Config.NamespaceUID || ns.DeletionTimestamp != nil {
		return d.ErrNotReady
	}
	pod, err := x.owner.Client.CoreV1().Pods(s.Config.Namespace).Get(ctx, actor.PodName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != actor.PodUID || pod.Spec.ServiceAccountName != p.ControllerServiceAccount || pod.Status.Phase != "Running" || pod.DeletionTimestamp != nil {
		return d.ErrNotReady
	}
	rsOwner := metav1.GetControllerOf(pod)
	if rsOwner == nil || rsOwner.Kind != "ReplicaSet" {
		return d.ErrNotReady
	}
	rs, err := x.owner.Client.AppsV1().ReplicaSets(s.Config.Namespace).Get(ctx, rsOwner.Name, metav1.GetOptions{})
	if err != nil || rs.UID != rsOwner.UID || rs.DeletionTimestamp != nil {
		return d.ErrNotReady
	}
	depOwner := metav1.GetControllerOf(rs)
	if depOwner == nil || depOwner.Kind != "Deployment" || depOwner.Name != p.ControllerDeployment || string(depOwner.UID) != p.ControllerDeploymentUID {
		return d.ErrNotReady
	}
	dep, err := x.owner.Client.AppsV1().Deployments(s.Config.Namespace).Get(ctx, p.ControllerDeployment, metav1.GetOptions{})
	if err != nil || string(dep.UID) != p.ControllerDeploymentUID || dep.Spec.Template.Spec.ServiceAccountName != p.ControllerServiceAccount || dep.DeletionTimestamp != nil {
		return d.ErrNotReady
	}
	sa, err := x.owner.Client.CoreV1().ServiceAccounts(s.Config.Namespace).Get(ctx, p.ControllerServiceAccount, metav1.GetOptions{})
	if err != nil || string(sa.UID) != p.ControllerServiceAccountUID || sa.DeletionTimestamp != nil {
		return d.ErrNotReady
	}
	sourceSA, err := x.owner.Client.CoreV1().ServiceAccounts(s.Config.Namespace).Get(ctx, p.SourceAPIServiceAccount, metav1.GetOptions{})
	if err != nil || string(sourceSA.UID) != p.SourceAPIServiceAccountUID || sourceSA.DeletionTimestamp != nil {
		return d.ErrNotReady
	}
	// No provider/source IO after this original SQL and file recheck. A renewal,
	// revocation or replacement during the last workload GET closes this object.
	return x.checkLocal(ctx)
}
