package install

import (
	refs "clawreef/internal/systembackupbootstrapsecurity"
	caNative "clawreef/internal/systembackupcatrust"
	ev "clawreef/internal/systembackupevidence"
	nonceNative "clawreef/internal/systembackupnoncebootstrap"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"database/sql"
	"time"
)

// Aliases are INPUT DATA only; they do not deserialize the real validators.
// Actual original local-admin/enrollment/config owner selects these controlled
// exact-version deployment mounts, then the native constructors verify them.
type originalC1NonceKeyWire nonceNative.Key
type originalC1NonceWire struct {
	OwnerMaterial                                      BootstrapSourceFilePin
	InstallationID, ServerUUID, Database, ConfigSHA256 string
	NotBefore, ExpiresAt                               time.Time
	Keys                                               []originalC1NonceKeyWire
}
type originalC1CAWire caNative.Binding

func (p *OriginalC1Production) newNonceObservation(ctx context.Context, in OriginalC1SigningPipelineInputs, pin BootstrapSourceFilePin) (*originalC1NativeObservation, error) {
	n, err := p.newSigningObservation(ctx, in.SigningMaterial, in.ControllerDeployment, in.ControllerPod)
	if err != nil {
		return nil, err
	}
	raw, err := readBootstrapSourcePin(pin, 262144)
	var w originalC1NonceWire
	if err != nil || decodeExact(raw, &w) != nil || w.InstallationID != string(p.domain.Scope.Installation) || w.ServerUUID != string(p.domain.Scope.ServerUUID) || w.Database != string(p.domain.Scope.Database) || w.ConfigSHA256 != p.request.config.SHA256() || time.Now().Before(w.NotBefore) {
		return nil, ErrInstall
	}
	if !bootstrapSourcePinValid(w.OwnerMaterial) {
		return nil, ErrInstall
	}
	ownerSource, ownerMount, err := p.operator.installer.readOriginalNonceMount(ctx, p.enrollment, w.OwnerMaterial, p.input.Request, n.actor.PodName, n.actor.PodUID)
	if err != nil || ownerMount.ControllerDeployment != in.ControllerDeployment || len(w.Keys) != 1 {
		return nil, ErrInstall
	}
	key := w.Keys[0]
	if key.IdentityHash != ownerSource.Reference.IdentityHash || key.Version != ownerSource.Reference.Version || key.ProviderIdentityHash != ownerSource.ProviderIdentityHash || key.ScopeHash != ownerSource.ScopeHash || key.DescriptorFile != ownerSource.Descriptor.File || key.DescriptorSHA256 != ownerSource.Descriptor.SHA256 || key.MaterialFile != ownerSource.Material.File || key.MaterialSHA256 != ownerSource.Material.SHA256 || key.ProtectedUntil.After(ownerSource.Until) || w.ExpiresAt.After(ownerMount.Until) {
		return nil, ErrInstall
	}
	b := nonceNative.Binding{InstallationID: w.InstallationID, ServerUUID: w.ServerUUID, Database: w.Database, ConfigSHA256: w.ConfigSHA256, NotBefore: w.NotBefore, ExpiresAt: w.ExpiresAt}
	for _, k := range w.Keys {
		b.Keys = append(b.Keys, nonceNative.Key(k))
	}
	v, err := nonceNative.New(b)
	if err != nil {
		return nil, err
	}
	selected := []sec.BootstrapSecretRef{}
	for _, ref := range p.request.config.References() {
		if ref.Purpose == "nonce_hmac" {
			selected = append(selected, ref)
		}
	}
	if len(selected) != 1 {
		return nil, ErrInstall
	}
	n.kind = "nonce-original-controlled-exact-version"
	n.nonce = v
	n.nonceWire = &w
	n.groupSource = pin
	n.references = selected
	n.groupCodes = []string{"exact_version_read"}
	if w.ExpiresAt.Before(n.until) {
		n.until = w.ExpiresAt
	}
	if err = n.bindGroupTarget([]pd.ID{"attestation"}); err != nil {
		return nil, err
	}
	if n.recheckLocalGroupInputs(ctx) != nil {
		return nil, ErrInstall
	}
	return n, nil
}
func (p *OriginalC1Production) newEvidenceCAObservation(ctx context.Context, in OriginalC1SigningPipelineInputs, pin, sixPin BootstrapSourceFilePin) (*originalC1NativeObservation, error) {
	n, err := p.newSigningObservation(ctx, in.SigningMaterial, in.ControllerDeployment, in.ControllerPod)
	if err != nil {
		return nil, err
	}
	raw, err := readBootstrapSourcePin(pin, 262144)
	var w originalC1CAWire
	if err != nil || decodeExact(raw, &w) != nil || w.InstallationID != string(p.domain.Scope.Installation) || w.ServerUUID != string(p.domain.Scope.ServerUUID) || w.Database != string(p.domain.Scope.Database) || w.ConfigSHA256 != p.request.config.SHA256() || w.Purpose != "evidence_ca" || time.Now().Before(w.NotBefore) {
		return nil, ErrInstall
	}
	raw, err = readBootstrapSourcePin(sixPin, 262144)
	var six SixReferenceDefinition
	if err != nil || decodeExact(raw, &six) != nil || validateSixReference(six) != nil || six.S3.Installation != w.InstallationID || six.S3.NamespaceUID != n.actor.NamespaceUID || w.Endpoint != six.S3.Provider.Endpoint || w.CAFile != six.S3.Provider.CAFile || w.CASHA256 != six.S3.Provider.CASHA256 {
		return nil, ErrInstall
	}
	v, err := caNative.New(caNative.Binding(w))
	if err != nil || v.InspectInputs(ctx, p.request.grant, p.request.config) != nil {
		return nil, ErrInstall
	}
	selected := []sec.BootstrapSecretRef{}
	for _, ref := range p.request.config.References() {
		if ref.Purpose == "evidence_ca" {
			selected = append(selected, ref)
		}
	}
	if len(selected) != 1 {
		return nil, ErrInstall
	}
	n.six = &six
	n.kind = "evidence-ca-actual-tls"
	n.ca = v
	n.caWire = &w
	n.groupSource = pin
	n.fiveFiles = []BootstrapSourceFilePin{sixPin}
	n.references = selected
	n.groupCodes = []string{"exact_version_read"}
	if w.ExpiresAt.Before(n.until) {
		n.until = w.ExpiresAt
	}
	if err = n.verifyEvidenceCATarget(ctx); err != nil {
		return nil, err
	}
	if err = n.bindGroupTarget([]pd.ID{"ca"}); err != nil {
		return nil, err
	}
	return n, nil
}
func (n *originalC1NativeObservation) recheckLocalGroupInputs(ctx context.Context) error {
	switch n.kind {
	case "nonce-original-controlled-exact-version":
		if n.nonceWire == nil {
			return ErrInstall
		}
		source, mount, err := n.parent.operator.installer.readOriginalNonceMount(ctx, n.parent.enrollment, n.nonceWire.OwnerMaterial, n.parent.input.Request, n.actor.PodName, n.actor.PodUID)
		if err != nil || mount.ControllerDeployment != n.deployment || len(n.nonceWire.Keys) != 1 {
			return ErrInstall
		}
		actual := n.nonceWire.Keys[0]
		if actual.MaterialFile != source.Material.File || actual.MaterialSHA256 != source.Material.SHA256 || actual.DescriptorFile != source.Descriptor.File || actual.DescriptorSHA256 != source.Descriptor.SHA256 || actual.IdentityHash != source.Reference.IdentityHash || actual.Version != source.Reference.Version {
			return ErrInstall
		}
		if n.nonce == nil || n.nonceWire == nil {
			return ErrInstall
		}
		for _, key := range n.nonceWire.Keys {
			descriptor, err := readBootstrapSourcePin(BootstrapSourceFilePin{File: key.DescriptorFile, SHA256: key.DescriptorSHA256}, 16384)
			if err != nil {
				return ErrInstall
			}
			ref, err := refs.DecodeSecurityReference(descriptor, key.DescriptorSHA256)
			if err != nil || ref.Kind() != "external_secret" || ref.Purpose() != "strong_auth_nonce_hmac" || ref.IdentityHash() != key.IdentityHash || ref.Version() != key.Version || ref.ProviderIdentity() != key.ProviderIdentityHash || ref.ScopeHash() != key.ScopeHash {
				return ErrInstall
			}
			material, err := readBootstrapSourcePin(BootstrapSourceFilePin{File: key.MaterialFile, SHA256: key.MaterialSHA256}, 32)
			valid := err == nil && len(material) == 32
			clear(material)
			if !valid {
				return ErrInstall
			}
		}
	case "evidence-ca-actual-tls":
		if n.ca == nil || n.caWire == nil || n.verifyEvidenceCATarget(ctx) != nil || n.ca.InspectInputs(ctx, n.parent.request.grant, n.parent.request.config) != nil {
			return ErrInstall
		}
		for _, pin := range n.fiveFiles {
			raw, err := readBootstrapSourcePin(pin, 262144)
			clear(raw)
			if err != nil {
				return ErrInstall
			}
		}
	default:
		return ErrInstall
	}
	return nil
}
func (p *OriginalC1Production) ProduceOriginalC1Nonce(ctx context.Context, capacityDB *sql.DB, channel *ev.OriginalC1OwnerChannel, in OriginalC1SigningPipelineInputs, definition BootstrapSourceFilePin, password, issuerPrivate []byte) (*OriginalC1SigningProduction, error) {
	n, err := p.newNonceObservation(ctx, in, definition)
	if err != nil {
		return nil, err
	}
	return p.produceOriginalC1Observed(ctx, capacityDB, channel, in, n, password, issuerPrivate)
}
func (p *OriginalC1Production) ProduceOriginalC1EvidenceCA(ctx context.Context, capacityDB *sql.DB, channel *ev.OriginalC1OwnerChannel, in OriginalC1SigningPipelineInputs, definition, six BootstrapSourceFilePin, password, issuerPrivate []byte) (*OriginalC1SigningProduction, error) {
	n, err := p.newEvidenceCAObservation(ctx, in, definition, six)
	if err != nil {
		return nil, err
	}
	return p.produceOriginalC1Observed(ctx, capacityDB, channel, in, n, password, issuerPrivate)
}
