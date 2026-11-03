package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/url"
	"path/filepath"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

const StatusRelayReferenceVersion = "original-status-relay-transport-reference.v1"
const statusRelayReferenceDomain = StatusRelayReferenceVersion + "\x00"

// This defines a CURRENT transport credential reference, not a future worker
// identity or permission to send a task/Job relay. Every runtime guard remains.
// Its exact hash is selected BEFORE final config/capture association signing.
type StatusRelayReferenceDefinition struct {
	Version, ReferenceVersion                                                 string
	Deployment                                                                BootstrapSourceFilePin
	Controller                                                                BootstrapSourceController
	Service, ServiceUID, Endpoint, Container, ContainerImageID, PodSpecSHA256 string
	CA, ClientCertificate, ClientPrivateKey                                   BootstrapSourceFilePin
	ServerLeafSHA256, ServerSPKISHA256                                        string
	NotBefore, Until                                                          time.Time
}

type StatusRelayReferenceFiles struct{ RecordFile, RecordSHA256, SignatureFile string }
type SignedStatusRelayReference struct{ Record, Signature []byte }
type statusRelayReferenceRecord struct {
	Version, PlanSHA256, CaptureRecordSHA256, DefinitionSHA256, NativeIdentitySHA256 string
	Target                                                                           owner.Target
	Actor                                                                            owner.Actor
	Enrollment                                                                       EnrollmentPin
	Selection                                                                        pd.BootstrapConsumptionRequest
	Reference                                                                        sec.BootstrapSecretRef
	Definition                                                                       StatusRelayReferenceDefinition
	NotBefore, Until                                                                 time.Time
}

func validateStatusRelayReference(d StatusRelayReferenceDefinition) error {
	u, err := url.Parse(d.Endpoint)
	if d.Version != StatusRelayReferenceVersion || !namePattern.MatchString(d.ReferenceVersion) || d.ReferenceVersion == "current" || d.ReferenceVersion == "latest" || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "/relay" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || d.Service == "" || d.ServiceUID == "" || d.Container == "" || d.ContainerImageID == "" || d.NotBefore.IsZero() || !d.NotBefore.Before(d.Until) || d.Until.Sub(d.NotBefore) > 24*time.Hour {
		return ErrInstall
	}
	for _, pin := range []BootstrapSourceFilePin{d.Deployment, d.CA, d.ClientCertificate, d.ClientPrivateKey} {
		if !bootstrapSourcePinValid(pin) {
			return ErrInstall
		}
	}
	for _, sha := range []string{d.PodSpecSHA256, d.ServerLeafSHA256, d.ServerSPKISHA256} {
		if !digestPattern.MatchString(sha) {
			return ErrInstall
		}
	}
	for _, value := range []string{d.Controller.Namespace, d.Controller.NamespaceUID, d.Controller.Deployment, d.Controller.DeploymentUID, d.Controller.ReplicaSet, d.Controller.ReplicaSetUID, d.Controller.Pod, d.Controller.PodUID, d.Controller.ServiceAccount, d.Controller.ServiceAccountUID} {
		if value == "" {
			return ErrInstall
		}
	}
	return nil
}

// Detached reference selection DATA only. Native observation and the distinct
// original issuer action below are mandatory before terminal consumption.
func StatusRelayReferenceIdentity(raw []byte, expectedSHA string) (sec.BootstrapSecretRef, error) {
	var d StatusRelayReferenceDefinition
	if hash(raw) != expectedSHA || decodeExact(raw, &d) != nil || validateStatusRelayReference(d) != nil {
		return sec.BootstrapSecretRef{}, ErrInstall
	}
	encoded, err := canonical(d)
	if err != nil || !bytes.Equal(raw, encoded) {
		return sec.BootstrapSecretRef{}, ErrInstall
	}
	return sec.BootstrapSecretRef{Purpose: "status_relay", IdentityHash: expectedSHA, Version: d.ReferenceVersion}, nil
}

func statusRelayConfigReference(config sec.BootstrapConfig) (sec.BootstrapSecretRef, error) {
	var found sec.BootstrapSecretRef
	for _, ref := range config.References() {
		if ref.Purpose == "status_relay" {
			if found.Purpose != "" {
				return found, ErrInstall
			}
			found = ref
		}
	}
	if found.Purpose == "" {
		return found, ErrInstall
	}
	return found, nil
}

// Separate original purpose association. The capture record is used solely as
// current enrollment/revocation anchor; it does not grant relay task authority.
func (i *Installer) IssueStatusRelayReference(ctx context.Context, password []byte, enrollment EnrollmentPin, bundleRaw []byte, bundleSHA, definitionFile, definitionSHA string, selection pd.BootstrapConsumptionRequest, files RequestFiles, issuerPrivate []byte) (SignedStatusRelayReference, error) {
	var zero SignedStatusRelayReference
	bundleRaw = bytes.Clone(bundleRaw)
	selectionRaw, e := json.Marshal(selection)
	var frozen pd.BootstrapConsumptionRequest
	if e != nil || len(selectionRaw) > 262144 || json.Unmarshal(selectionRaw, &frozen) != nil {
		return zero, ErrInstall
	}
	selection = frozen
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	b, capture, _, e := s.decodeBundle(bundleRaw, bundleSHA, enrollment)
	if e != nil || b.SchemaVersion != AuthorityBundleVersion || !functionalSelectionMatches(capture, selection) {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(BootstrapSourceFilePin{definitionFile, definitionSHA}, 262144)
	var d StatusRelayReferenceDefinition
	ref, re := StatusRelayReferenceIdentity(raw, definitionSHA)
	if e != nil || re != nil || decodeExact(raw, &d) != nil || d.Controller.Namespace != capture.Target.Namespace || d.Controller.NamespaceUID != capture.Target.NamespaceUID {
		return zero, ErrInstall
	}
	request, e := readConsumerCaptureRequest(i, files)
	if e != nil {
		return zero, ErrInstall
	}
	defer request.observer.Close()
	actualRef, e := statusRelayConfigReference(request.config)
	if e != nil || actualRef != ref || !request.matchesDraft(capture) {
		return zero, ErrInstall
	}
	before, now, e := snapshot(ctx, s)
	if e != nil || !exactCommitted(before, b) || now.Before(d.NotBefore) || !now.Before(d.Until) || now.Before(capture.NotBefore) || !now.Before(capture.Until) {
		return zero, ErrInstall
	}
	native, e := observeStatusRelayReference(ctx, i.kube, capture.Target, d)
	if e != nil {
		return zero, ErrInstall
	}
	end := capture.Until
	if d.Until.Before(end) {
		end = d.Until
	}
	start := capture.NotBefore
	if d.NotBefore.After(start) {
		start = d.NotBefore
	}
	r := statusRelayReferenceRecord{Version: StatusRelayReferenceVersion, PlanSHA256: i.planHash, CaptureRecordSHA256: hash(b.Record), DefinitionSHA256: definitionSHA, NativeIdentitySHA256: native.identity, Target: capture.Target, Actor: capture.Actor, Enrollment: enrollment, Selection: selection, Reference: ref, Definition: d, NotBefore: start, Until: end}
	encoded, e := canonical(r)
	if e != nil || len(encoded) > 262144 {
		return zero, ErrInstall
	}
	key, e := s.privateKey(issuerPrivate)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	signature := ed25519.Sign(key, append([]byte(statusRelayReferenceDomain), encoded...))
	for _, pin := range []BootstrapSourceFilePin{{definitionFile, definitionSHA}, {files.ConfigFile, files.ConfigFileSHA256}, {files.GrantFile, files.GrantFileSHA256}, {files.ObserverFile, files.ObserverFileSHA256}} {
		v, e := readBootstrapSourcePin(pin, 262144)
		clear(v)
		if e != nil {
			return zero, ErrInstall
		}
	}
	tail, e := observeStatusRelayReference(ctx, i.kube, capture.Target, d)
	if e != nil || tail.identity != native.identity || !time.Now().Before(native.until) || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	after, now, e := snapshot(ctx, s)
	if e != nil || after.cas != before.cas || !exactCommitted(after, b) || now.Before(start) || !now.Before(end) || !now.Before(native.until) || !s.live(ctx) {
		return zero, ErrInstall
	}
	return SignedStatusRelayReference{Record: encoded, Signature: signature}, nil
}

func SaveFrozenStatusRelayReference(directory string, signed SignedStatusRelayReference) error {
	var r statusRelayReferenceRecord
	if len(signed.Record) == 0 || len(signed.Record) > 262144 || len(signed.Signature) != ed25519.SignatureSize || decodeExact(signed.Record, &r) != nil || r.Version != StatusRelayReferenceVersion {
		return ErrInstall
	}
	return writeNewFiles(directory, map[string][]byte{"status-relay-reference.record.json": bytes.Clone(signed.Record), "status-relay-reference.signature": bytes.Clone(signed.Signature), "status-relay-reference.sha256": []byte(hash(signed.Record))})
}

type OriginalStatusRelayReference struct {
	capture *CaptureSigningConsumer
	files   StatusRelayReferenceFiles
}

func NewOriginalStatusRelayReference(capture *CaptureSigningConsumer, files StatusRelayReferenceFiles) (*OriginalStatusRelayReference, error) {
	if capture == nil || !digestPattern.MatchString(files.RecordSHA256) || files.RecordFile == files.SignatureFile {
		return nil, ErrInstall
	}
	for _, p := range []string{files.RecordFile, files.SignatureFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, ErrInstall
		}
	}
	return &OriginalStatusRelayReference{capture: capture, files: files}, nil
}
func (*OriginalStatusRelayReference) TerminalKeys() []string {
	return []string{"reference:status_relay"}
}
func (*OriginalStatusRelayReference) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*OriginalStatusRelayReference) Prepare(context.Context, sec.OfflineBootstrapGrant, sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	return nil, ErrInstall
}
func (p *OriginalStatusRelayReference) BindingSHA256() (string, error) {
	if p == nil || p.capture == nil {
		return "", ErrInstall
	}
	raw, e := canonical(struct {
		Version, Capture, Pin string
		Files                 StatusRelayReferenceFiles
	}{StatusRelayReferenceVersion, p.capture.sourceFile, p.capture.sourcePinFile, p.files})
	if e != nil {
		return "", ErrInstall
	}
	return hash(raw), nil
}
