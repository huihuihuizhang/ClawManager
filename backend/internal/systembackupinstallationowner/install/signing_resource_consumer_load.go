package install

import (
	"bytes"
	"context"
	"sync/atomic"

	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// One explicitly loaded consumer assembly. It owns the observers until Close;
// it exposes no password/DSN/private issuer key or successful permission flag.
// Load afresh for each original deployment attempt; don't reuse after Close.
type SigningResourceConsumer struct {
	ctx       context.Context
	files     []consumerPinnedFile
	resource  *owner.SigningResources
	observers []*owner.SigningResourceObserver
	closed    atomic.Bool
}

func (*SigningResourceConsumer) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (c *SigningResourceConsumer) Close() {
	if c != nil && c.closed.CompareAndSwap(false, true) {
		for _, observer := range c.observers {
			observer.Close()
		}
	}
}
func (c *SigningResourceConsumer) current(ctx context.Context) error {
	if c == nil || c.closed.Load() || !consumerSameContext(c.ctx, ctx) || ctx.Err() != nil {
		return ErrInstall
	}
	for _, pin := range c.files {
		raw, err := ReadPrivateFile(pin.path, pin.limit)
		if err != nil || hash(raw) != pin.sha {
			c.Close()
			return ErrInstall
		}
	}
	if ctx.Err() != nil {
		c.Close()
		return ErrInstall
	}
	return nil
}

// OpenSigningResourceConsumer uses an independently deployed exact source pin.
// It loads only public authority/material records and consumer credentials,
// checks the real immutable enrollment through a pinned static Kube client,
// and constructs one concrete A owner. It opens no SQL/installer credentials,
// does not probe a provider and grants no retained terminal approval.
func OpenSigningResourceConsumer(ctx context.Context, sourceFile, sourcePinFile string) (*SigningResourceConsumer, error) {
	return openSigningResourceConsumer(ctx, sourceFile, sourcePinFile, "")
}

// Compare the main composition's independently selected source hash BEFORE
// opening any nested consumer credential or API endpoint.
func OpenPinnedSigningResourceConsumer(ctx context.Context, sourceFile, sourcePinFile, expectedSHA string) (*SigningResourceConsumer, error) {
	if !digestPattern.MatchString(expectedSHA) {
		return nil, ErrInstall
	}
	return openSigningResourceConsumer(ctx, sourceFile, sourcePinFile, expectedSHA)
}

func openSigningResourceConsumer(ctx context.Context, sourceFile, sourcePinFile, expectedSHA string) (*SigningResourceConsumer, error) {
	if consumerNil(ctx) || ctx.Err() != nil {
		return nil, ErrInstall
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, ErrInstall
	}
	independent, err := ReadPrivateFile(sourcePinFile, 64)
	if err != nil || !digestPattern.Match(independent) || expectedSHA != "" && string(independent) != expectedSHA {
		return nil, ErrInstall
	}
	var document SigningResourceConsumerFiles
	if signingResourcePinnedJSON(sourceFile, string(independent), &document) != nil || document.Version != SigningResourceConsumerVersion || len(document.Items) != 2 {
		return nil, ErrInstall
	}
	c := &SigningResourceConsumer{ctx: ctx, files: []consumerPinnedFile{{sourcePinFile, hash(independent), 64}, {sourceFile, string(independent), 262144}}}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	read := func(path, sha string, limit int64) ([]byte, error) {
		raw, err := ReadPrivateFile(path, limit)
		if err != nil || !digestPattern.MatchString(sha) || hash(raw) != sha {
			return nil, ErrInstall
		}
		c.files = append(c.files, consumerPinnedFile{path, sha, limit})
		return raw, nil
	}
	planRaw, err := read(document.PlanFile, document.PlanSHA256, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	plan, err := DecodePlan(planRaw, document.PlanSHA256)
	if err != nil || plan.InstallerDatabaseAccount == plan.Target.DatabaseAccount {
		return nil, ErrInstall
	}
	public, err := read(document.IssuerPublicFile, document.IssuerPublicSHA256, 32)
	if err != nil || len(public) != 32 || document.IssuerPublicSHA256 != plan.IssuerPublicKeySHA256 {
		return nil, ErrInstall
	}
	enrolRaw, err := read(document.EnrollmentPinFile, document.EnrollmentPinSHA256, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	enrollment, err := DecodeEnrollmentPin(enrolRaw, document.EnrollmentPinSHA256)
	if err != nil {
		return nil, ErrInstall
	}
	kube, err := openCaptureConsumerKubernetes(plan, document.KubeconfigFile, document.KubeconfigSHA256)
	if err != nil {
		return nil, ErrInstall
	}
	c.files = append(c.files, consumerPinnedFile{document.KubeconfigFile, document.KubeconfigSHA256, 262144})
	var inputs []owner.SigningResourceInput
	var actor int64
	for n, item := range document.Items {
		pinRaw, err := read(item.PinFile, item.PinSHA256, 262144)
		var pin owner.SigningResourceTrustPin
		if err != nil || decodeExact(pinRaw, &pin) != nil || pin.Purpose != owner.SigningResourcePurposes()[n] || pin.Target != plan.Target || pin.EnrollmentID != plan.EnrollmentID || pin.EnrollmentRevision != plan.EnrollmentRevision || pin.IssuerID != plan.IssuerID || pin.EnrollmentDocumentSHA256 != enrollment.DocumentSHA256 || pin.Actor.Username != plan.LocalAdminUsername || pin.Actor.OwnerSubject != plan.OwnerUsername || pin.OwnerSubject != plan.OwnerUsername || !bytes.Equal(pin.Issuer, public) || n != 0 && actor != pin.Actor.UserID {
			return nil, ErrInstall
		}
		actor = pin.Actor.UserID
		raw, err := read(item.RecordFile, pin.GrantSHA256, 262144)
		if err != nil {
			return nil, ErrInstall
		}
		signature, err := ReadPrivateFile(item.SignatureFile, 64)
		if err != nil {
			return nil, ErrInstall
		}
		c.files = append(c.files, consumerPinnedFile{item.SignatureFile, hash(signature), 64})
		grant, err := owner.InspectSigningResourceGrant(raw, signature, pin)
		if err != nil || grant.PlanSHA256 != document.PlanSHA256 {
			return nil, ErrInstall
		}
		doc, err := readSigningResourceAsset(ctx, item.Asset, grant)
		if err != nil {
			return nil, ErrInstall
		}
		c.files = append(c.files, consumerPinnedFile{item.Asset.ObserverFile, item.Asset.ObserverSHA256, 262144}, consumerPinnedFile{doc.CAFile, doc.CASHA256, 65536})
		ca, err := read(doc.CAFile, doc.CASHA256, 65536)
		if err != nil {
			return nil, ErrInstall
		}
		observer, err := owner.NewSigningResourceObserver(owner.SigningObserverConfig{Endpoint: doc.Endpoint, CASHA256: doc.CASHA256, CAPEM: ca, ObserverPolicy: doc.ObserverPolicy, ObserverTokenFile: doc.ObserverTokenFile, ObserverTokenSHA256: doc.ObserverTokenSHA256, RuntimeJWTFile: doc.RuntimeJWTFile, Trust: doc.Trust, Kubernetes: kube})
		if err != nil {
			return nil, ErrInstall
		}
		c.observers = append(c.observers, observer)
		inputs = append(inputs, owner.SigningResourceInput{Pin: pin, Files: owner.RecordFiles{RecordFile: item.RecordFile, SignatureFile: item.SignatureFile}, Material: item.Asset.Material, Observer: observer})
	}
	// Compare the exact independently retained immutable registration. Neither
	// an embedded public key nor a record-supplied UID enrolls a new issuer.
	expected, err := canonical(enrollmentDocument{EnrollmentVersion, plan, actor, public})
	if err != nil || hash(expected) != enrollment.DocumentSHA256 {
		return nil, ErrInstall
	}
	cm, err := kube.CoreV1().ConfigMaps(plan.Target.Namespace).Get(ctx, plan.EnrollmentName, metav1.GetOptions{})
	if err != nil || cm == nil || cm.Name != plan.EnrollmentName || cm.Namespace != plan.Target.Namespace || string(cm.UID) != enrollment.ConfigMapUID || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 1 || len(cm.BinaryData) != 0 || !bytes.Equal([]byte(cm.Data["enrollment.json"]), expected) {
		return nil, ErrInstall
	}
	c.resource, err = owner.NewSigningResources(inputs)
	if err != nil || c.current(ctx) != nil {
		return nil, ErrInstall
	}
	ok = true
	return c, nil
}

// WithSigningResourceConsumer preserves the original capture/files and every
// existing resource pointer. Both aliases retain the one already constructed
// A SigningResources pointer; no observer/provider preparation repeats here.
func (a *BootstrapTerminalOriginal) WithSigningResourceConsumer(c *SigningResourceConsumer) (*BootstrapTerminalOriginal, *owner.SigningResources, error) {
	if a == nil || a.capture == nil || c == nil || c.closed.Load() || c.resource == nil || c.current(c.ctx) != nil {
		return nil, nil, ErrInstall
	}
	resources := make(map[string]sec.BootstrapTerminalResource, len(a.resources)+2)
	for key, resource := range a.resources {
		resources[key] = resource
	}
	for _, key := range c.resource.TerminalKeys() {
		if _, exists := resources[key]; exists {
			return nil, nil, ErrInstall
		}
		resources[key] = c.resource
	}
	terminal, err := NewBootstrapTerminalOriginal(a.capture, a.files, resources)
	if err != nil {
		return nil, nil, ErrInstall
	}
	return terminal, c.resource, nil
}
