package systembackupexecution

import (
	"bytes"
	"context"
	"reflect"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	ma "clawreef/internal/systembackupminioauthority"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const minioTerminalReferenceProfile = "original-minio-terminal-reference.v1"
const minioTerminalScopeProfile = "original-minio-terminal-scope.v1"
const minioTerminalProtocolProfile = "original-minio-terminal-s3-protocol.v1"
const minioTerminalProviderProfile = "original-minio-terminal-provider.v1"

func (r *MinIOBootstrapTerminalResource) terminalInitialHead(ctx context.Context) error {
	p := r.grant.PermissionSource
	cm, e := r.kube.CoreV1().ConfigMaps(r.grant.Target.Namespace).Get(ctx, p.Head.Name, metav1.GetOptions{})
	if e != nil || cm == nil || string(cm.UID) != p.Head.UID || ma.Digest(hash([]byte(cm.Data["record.json"]))) != p.InitialHeadSHA256 {
		return minioPermissionFailure("terminal-original-head-bytes")
	}
	return nil
}

// This original descriptor omits its own digest to avoid a digest cycle. Its
// identity is the owner's independent reference identity, never a secret hash.
type MinIOBootstrapReferenceDescriptor struct {
	Version   string
	Reference ma.Reference
}
type MinIOBootstrapImageProvenance struct{ Version, ImageID, ServerVersion, ServerCommit string }

func (r *MinIOBootstrapTerminalResource) bindTerminalInputs(p *minioPermissionProductionInputs, reader *MinIOPublicationPermissionReader) error {
	g := r.grant
	c := reader.configuration
	d := p.definition
	v := g.PermissionSource
	if p.grant.Installation != g.Target.InstallationID || p.grant.Namespace != g.Target.Namespace || p.grant.NamespaceUID != g.Target.NamespaceUID || p.grant.ConfigSHA256 != string(g.ConfigSHA256) || p.grant.Profile != ma.PermissionProfile || p.grant.Epoch != g.PermissionEpoch || c.Installation != p.grant.Installation || c.Namespace != p.grant.Namespace || c.NamespaceUID != p.grant.NamespaceUID || !bytes.Equal(c.Issuer, r.input.Pin.IssuerPublic) || c.MinimumEpoch != g.PermissionEpoch || c.Grant.Name != v.Grant.Name || c.Grant.UID != v.Grant.UID || c.Head.Name != v.Head.Name || c.Head.UID != v.Head.UID || c.GrantSHA256 != string(v.GrantSHA256) || c.ObserverAccountSHA256 != string(v.ObserverAccountSHA256) || c.ObserverCredentialSHA256 != string(v.ObserverCredentialFileSHA256) || c.ObserverPolicyName != v.ObserverPolicyName || c.ObserverPolicySHA256 != string(v.ObserverNormalizedPolicySHA256) || c.ObserverCredentialFile != d.ObserverCredentialFile || c.ObserverCredentialSHA256 != d.ObserverCredentialSHA256 || c.ObserverAccountSHA256 != d.ObserverAccountSHA256 || c.ObserverPolicyName != d.ObserverPolicyName || c.ObserverPolicySHA256 != d.ObserverPolicySHA256 || hash([]byte(c.ObserverCredentialFile)) != string(v.ObserverLocatorSHA256) {
		return minioPermissionFailure("terminal-original-source-binding")
	}
	provider := p.grant.Provider
	want := g.Provider
	providerIdentity := want
	providerIdentity.IdentityHash = ""
	identityBytes, identityErr := ce.Canonical(struct {
		Version  string
		Provider ma.Provider
	}{minioTerminalProviderProfile, providerIdentity})
	if identityErr != nil || want.IdentityProfile != minioTerminalProviderProfile || ma.Digest(hash(identityBytes)) != want.IdentityHash {
		return minioPermissionFailure("terminal-original-provider-profile")
	}
	if provider.Endpoint != want.Endpoint || provider.Region != want.Region || provider.DeploymentID != want.DeploymentID || provider.CASHA256 != string(want.CASHA256) || provider.SPKISHA256 != string(want.SPKISHA256) || provider.Container != want.Container || provider.ImageID != want.ImageID || provider.Node != want.Node || provider.NodeUID != want.NodeUID || provider.Deployment.Name != want.Deployment.Name || provider.Deployment.UID != want.Deployment.UID || provider.ReplicaSet.Name != want.ReplicaSet.Name || provider.ReplicaSet.UID != want.ReplicaSet.UID || provider.Pod.Name != want.Pod.Name || provider.Pod.UID != want.Pod.UID || provider.Service.Name != want.Service.Name || provider.Service.UID != want.Service.UID || provider.ServiceAccount.Name != want.ServiceAccount.Name || provider.ServiceAccount.UID != want.ServiceAccount.UID || provider.CAFile != p.target.CAFile || provider.CAFile != p.catalog.CAFile {
		return minioPermissionFailure("terminal-provider-binding")
	}
	// The native release and actual pod imageID are observed separately. This
	// file is the independently signed owner's provenance mapping, not a claim
	// that registry provenance can be inferred from an arbitrary image label.
	raw, e := pinnedDeploymentFile(r.input.ProvenanceFile, string(want.ImageProvenanceSHA256), 16384)
	var provenance MinIOBootstrapImageProvenance
	if e != nil || decodePublicationCanonical(raw, &provenance) != nil || provenance.Version != "original-minio-image-provenance.v1" || provenance.ImageID != want.ImageID || provenance.ServerVersion != minioPermissionVersion || provenance.ServerCommit != minioPermissionCommit {
		return minioPermissionFailure("terminal-original-image-provenance")
	}
	uses := map[string]minioPermissionUse{}
	for _, u := range p.uses {
		uses[u.principal.Purpose] = u
	}
	for i, record := range r.refs {
		ref := record.Reference
		u := uses[string(ref.Purpose)]
		var file, pin string
		switch ref.Purpose {
		case ma.ArtifactDelete:
			file, pin = p.target.DeleteCredentialFile, p.target.DeleteCredentialSHA256
		case ma.ArtifactRead:
			file, pin = p.target.ReadCredentialFile, p.target.ReadCredentialSHA256
		case ma.ArtifactWrite:
			file, pin = p.target.WriteCredentialFile, p.target.WriteCredentialSHA256
		case ma.CatalogAppend:
			file, pin = p.catalog.AppendCredentialFile, p.catalog.AppendCredentialSHA256
		case ma.CatalogRead:
			file, pin = p.catalog.ReadCredentialFile, p.catalog.ReadCredentialSHA256
		}
		if u.principal.Purpose != string(ref.Purpose) || u.principal.IdentityHash != string(ref.IdentityHash) || u.principal.RefVersion != ref.IdentityVersion || u.principal.AccountSHA256 != string(ref.AccountSHA256) || u.principal.PolicyName != ref.PolicyName || u.principal.PolicySHA256 != string(ref.NormalizedPolicySHA256) || u.bucket != ref.Bucket || u.root != ref.Root || u.staging != ref.StagingRoot || ma.Digest(pin) != ref.CredentialFileSHA256 || ma.Digest(hash([]byte(file))) != ref.CredentialLocatorSHA256 || ref.CapabilityIntentSHA256 != g.Observation.CapabilityIntentSHA256 || ref.IdentityProfile != minioTerminalReferenceProfile || ref.ScopeProfile != minioTerminalScopeProfile || ref.CapabilityProfile != minioTerminalProtocolProfile || ref.Purpose == ma.ArtifactRead && ref.Capability != "range_read" {
			return minioPermissionFailure("terminal-original-reference-binding")
		}
		scope, _ := ce.Canonical(struct {
			Version                   string
			Purpose                   ma.Purpose
			Provider                  ma.Digest
			Bucket, Root, StagingRoot string
		}{minioTerminalScopeProfile, ref.Purpose, g.Provider.IdentityHash, ref.Bucket, ref.Root, ref.StagingRoot})
		if ma.Digest(hash(scope)) != ref.ScopeSHA256 {
			return minioPermissionFailure("terminal-original-reference-scope")
		}
		raw, e = pinnedDeploymentFile(r.input.ReferenceFiles[i].File, string(ref.DescriptorSHA256), 65536)
		var descriptor MinIOBootstrapReferenceDescriptor
		withoutSelf := ref
		withoutSelf.DescriptorSHA256 = ""
		if e != nil || decodePublicationCanonical(raw, &descriptor) != nil || descriptor.Version != minioTerminalReferenceProfile || !reflect.DeepEqual(descriptor.Reference, withoutSelf) {
			return minioPermissionFailure("terminal-original-reference-descriptor")
		}
	}
	return nil
}

func (r *MinIOBootstrapTerminalResource) observeTerminal(ctx context.Context, started, deadline time.Time, inventory *[]MinIOBootstrapProbeObject) (time.Time, error) {
	zero := time.Time{}
	p, e := readMinIOPermissionProductionInputs(r.input.DefinitionFile, r.input.DefinitionSHA256)
	if e != nil {
		return zero, e
	}
	defer p.clear()
	reader, e := NewMinIOEffectivePublicationPermissionV2Reader(r.input.PermissionSource)
	if e != nil {
		return zero, e
	}
	if e = r.bindTerminalInputs(p, reader); e != nil {
		return zero, e
	}
	owner, e := reader.effectiveOwnerV2(ctx, r.kube, started)
	if e != nil || !reflect.DeepEqual(owner.grant, p.grant) {
		return zero, minioPermissionFailure("terminal-current-permission-owner")
	}
	// Bind the exact original initial head bytes as well as its live signature.
	// effectiveOwnerV2 supplies the signature/window/RV checks; this extra read
	// prevents a differently signed active declaration from being substituted.
	if e = r.terminalInitialHead(ctx); e != nil {
		return zero, e
	}
	if e = p.window.include(started, owner.window.notBefore, owner.window.until); e != nil {
		return zero, e
	}
	for _, ref := range r.refs {
		v := ref.Reference
		if p.window.include(started, v.NotBefore, v.Until) != nil || !started.Before(v.ProtectedUntil) {
			return zero, minioPermissionFailure("terminal-reference-window")
		}
		if v.ProtectedUntil.Before(deadline) {
			deadline = v.ProtectedUntil
		}
	}
	if p.window.until.Before(deadline) {
		deadline = p.window.until
	}
	if !started.Before(deadline) {
		return zero, minioPermissionFailure("terminal-original-deadline")
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	before, e := observeOriginalMinIOPermissions(bounded, r.kube, p, r.input.DefinitionSHA256)
	if e != nil {
		return zero, e
	}
	if e = r.probeTerminalProtocol(bounded, p, deadline, inventory); e != nil {
		return zero, e
	}
	// Real provider/source and actual file tails remain OUTSIDE SQL locks.
	after, e := observeOriginalMinIOPermissions(bounded, r.kube, p, r.input.DefinitionSHA256)
	if e != nil || before.NativeSourcesSHA256 != after.NativeSourcesSHA256 || before.ResourcesSHA256 != after.ResourcesSHA256 {
		return zero, minioPermissionFailure("terminal-provider-tail")
	}
	tailOwner, e := reader.effectiveOwnerV2(bounded, r.kube, time.Now())
	if e != nil || tailOwner.stamp != owner.stamp || r.terminalInitialHead(bounded) != nil {
		return zero, minioPermissionFailure("terminal-owner-tail")
	}
	tail, e := readMinIOPermissionProductionInputs(r.input.DefinitionFile, r.input.DefinitionSHA256)
	if e != nil {
		return zero, e
	}
	defer tail.clear()
	if r.bindTerminalInputs(tail, reader) != nil || !time.Now().Before(deadline) || bounded.Err() != nil {
		return zero, minioPermissionFailure("terminal-original-file-tail")
	}
	// NEVER slide from completion time or return the wider signed grant window.
	return deadline, nil
}
