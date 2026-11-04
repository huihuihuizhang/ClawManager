package install

import (
	caNative "clawreef/internal/systembackupcatrust"
	ev "clawreef/internal/systembackupevidence"
	owner "clawreef/internal/systembackupinstallationowner"
	kekNative "clawreef/internal/systembackupkekadapter"
	nonceNative "clawreef/internal/systembackupnoncebootstrap"
	pd "clawreef/internal/systembackupproducer"
	probe "clawreef/internal/systembackupreferenceprobe"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"
)

type originalC1NativeObservation struct {
	backup                                              *kekNative.VaultPermissionObserver
	backupWire                                          *originalC1BackupKEKInputs
	backupRecord, backupSignature                       []byte
	backupStored                                        bool
	catalog                                             *originalC1CatalogCheckpointInputs
	catalogEnvelope                                     []byte
	nonce                                               *nonceNative.Validator
	nonceWire                                           *originalC1NonceWire
	ca                                                  *caNative.Validator
	caWire                                              *originalC1CAWire
	groupCodes                                          []string
	five                                                *probe.OriginalFiveProfile
	fiveFiles                                           []BootstrapSourceFilePin
	kind                                                string
	six                                                 *SixReferenceDefinition
	status                                              *StatusRelayReferenceDefinition
	groupSource                                         BootstrapSourceFilePin
	groupProof                                          string
	origin                                              *originalC1NativeObservation
	parent                                              *OriginalC1Production
	signing                                             OriginalPublicationSigningFiles
	signed                                              sec.InstallationSigningRecord
	actor                                               owner.Binding
	deployment                                          string
	source                                              BootstrapSourceFilePin
	target                                              pd.Target
	host                                                pd.Host
	subject                                             pd.Hash
	identityVersion, referenceHash, policy, attestation string
	started, until, retention                           time.Time
	observed                                            bool
	body                                                []byte
	results                                             pd.Results
	references                                          []sec.BootstrapSecretRef
}

func (n *originalC1NativeObservation) local(ctx context.Context) error {
	if n == nil || n.origin != n || n.parent == nil || !n.parent.live(ctx) || !time.Now().Before(n.until) || n.subject == "" || n.referenceHash == "" {
		return ErrInstall
	}
	return nil
}
func (n *originalC1NativeObservation) recheckFiles(ctx context.Context) error {
	if n.kind != "signing" {
		return n.recheckGroupFiles(ctx)
	}
	if n.local(ctx) != nil {
		return ErrInstall
	}
	if _, err := readBootstrapSourcePin(n.source, 262144); err != nil {
		return ErrInstall
	}
	for _, pin := range n.signing.JWTFiles {
		raw, e := readBootstrapSourcePin(pin, 16384)
		clear(raw)
		if e != nil {
			return ErrInstall
		}
	}
	actor, e := n.parent.operator.installer.originalPublicationActor(ctx, n.deployment, n.actor.PodName)
	if e != nil || actor != n.actor {
		return ErrInstall
	}
	return n.parent.recheckPrepared()
}

// This constructor selects the real original signed three-key material and
// authenticates its exact current actor/reference relationship BEFORE commands.
// It does not infer a provider capability from a secret/status availability.
func (p *OriginalC1Production) newSigningObservation(ctx context.Context, material BootstrapSourceFilePin, deployment, pod string) (*originalC1NativeObservation, error) {
	i := p.operator.installer
	m, signed, actor, _, err := i.originalFirstCaptureSigning(ctx, p.enrollment, OriginalFirstCaptureDraftInputs{Request: p.input.Request, SigningMaterial: material, ControllerDeployment: deployment, ControllerPodName: pod}, p.request)
	if err != nil {
		return nil, ErrInstall
	}
	refs := []sec.BootstrapSecretRef{}
	for _, b := range m.Bindings {
		purpose := ""
		switch b.Purpose {
		case "capture_certificate":
			purpose = "capture_signing"
		case "acceptance_record":
			purpose = "acceptance_signing"
		case "catalog_record":
			purpose = "catalog_signing"
		default:
			return nil, ErrInstall
		}
		identity, e := owner.ReferenceIdentity(b)
		if b.Purpose != "capture_certificate" {
			identity, e = owner.SigningResourceReferenceIdentity(b)
		}
		if e != nil {
			return nil, ErrInstall
		}
		found := false
		for _, ref := range p.request.config.References() {
			if ref.Purpose == purpose {
				if ref.IdentityHash != identity || ref.Version != b.KeyVersion {
					return nil, ErrInstall
				}
				refs = append(refs, ref)
				found = true
			}
		}
		if !found {
			return nil, ErrInstall
		}
	}
	if len(refs) != 3 {
		return nil, ErrInstall
	}
	scopeRaw, err := canonical(struct {
		Version, Plan, Source string
		Bindings              []owner.Binding
	}{"original-c1-native-signing-probe.v1", i.planHash, material.SHA256, m.Bindings})
	if err != nil {
		return nil, ErrInstall
	}
	subject := pd.Hash(hash(c1wire(actor)))
	n := &originalC1NativeObservation{kind: "signing", parent: p, signing: m, signed: signed, actor: actor, deployment: deployment, source: material, subject: subject, identityVersion: hash(c1wire(struct {
		Actor  owner.Binding
		Source string
	}{actor, material.SHA256})), referenceHash: hash(c1wire(refs)), policy: hash([]byte("original-c1-production-signing-native-profile.v1")), started: time.Now().UTC().Truncate(time.Microsecond), until: p.until, retention: time.Now().UTC().Add(30 * 24 * time.Hour), references: refs}
	if signed.Until.Before(n.until) {
		n.until = signed.Until
	}
	n.target = pd.Target{EvaluatorOwner: "A", EvaluatorProfileHash: pd.Hash(n.policy), Role: "signing", IdentityHash: pd.Hash(hash(scopeRaw)), RefVersion: "1", ProbeScopeHash: pd.Hash(hash(scopeRaw)), ResultSlots: []pd.ID{"signing"}}
	n.host = pd.Host{Service: &pd.ServiceHost{Kind: "service", WorkloadIdentityHash: subject}}
	n.origin = n
	return n, nil
}

// Runs ONLY after the real original probe CallSnapshot has committed. Each
// actual JWT is TokenReviewed against the current Pod/SA, exchanged at native
// Vault, then signs a fresh random challenge and verifies actual Ed25519 bytes.
func (n *originalC1NativeObservation) observe(ctx context.Context, probe *pd.CallSnapshot, runID string) error {
	if n != nil && n.kind != "signing" {
		return n.observeGroup(ctx, probe, runID)
	}
	if n.local(ctx) != nil || n.observed || probe == nil || probe.Purpose() != "probe" || probe.View().Facts.Run.RunID != pd.ID(runID) || !reflect.DeepEqual(probe.View().Facts.Grant.Target, n.target) {
		return ErrInstall
	}
	i := n.parent.operator.installer
	ca, e := readBootstrapSourcePin(n.signing.CA, 65536)
	if e != nil {
		return ErrInstall
	}
	n.started = time.Now().UTC().Truncate(time.Microsecond)
	proof := []string{}
	for k, b := range n.signing.Bindings {
		jwt, e := readBootstrapSourcePin(n.signing.JWTFiles[b.Purpose], 16384)
		if e != nil {
			return ErrInstall
		}
		v, e := newOriginalPublicationVault(b.Endpoint, ca, b.CASHA256)
		if e != nil {
			clear(jwt)
			return ErrInstall
		}
		docRaw, e := readBootstrapSourcePin(n.signing.ResourceObservers[b.Purpose], 262144)
		var doc observerDocument
		if e != nil || decodeExact(docRaw, &doc) != nil {
			clear(jwt)
			v.close()
			return ErrInstall
		}
		observer, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: doc.ObserverTokenFile, SHA256: doc.ObserverTokenSHA256}, 16384)
		if e != nil || originalPublicationCheckMetadata(ctx, v, b, n.signing.Histories[k], observer) != nil {
			clear(jwt)
			clear(observer)
			v.close()
			return ErrInstall
		}
		until, e := i.originalPublicationProbe(ctx, v, b, n.signed.Keys[k].PublicKey, jwt)
		if e == nil && originalPublicationCheckMetadata(ctx, v, b, n.signing.Histories[k], observer) != nil {
			e = ErrInstall
		}
		clear(observer)
		clear(jwt)
		v.close()
		if e != nil || !time.Now().Before(until) {
			return ErrInstall
		}
		proof = append(proof, hash(c1wire(struct {
			Binding owner.Binding
			Public  []byte
		}{b, n.signed.Keys[k].PublicKey})))
	}
	if n.local(ctx) != nil {
		return ErrInstall
	}
	// Fixed original evaluator observation window, never renewed by callbacks.
	observedUntil := n.started.Add(60 * time.Second)
	if n.until.Before(observedUntil) {
		observedUntil = n.until
	}
	n.until = observedUntil
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return ErrInstall
	}
	finished := time.Now().UTC().Truncate(time.Microsecond)
	evi := sec.CapabilityEvidence{SchemaVersion: "system-backup-capability-evidence.v1", Role: "signing", IdentityHash: string(n.target.IdentityHash), RefVersion: "1", StartedAt: n.started.Format(time.RFC3339Nano), FinishedAt: finished.Format(time.RFC3339Nano), ScopeHash: string(n.target.ProbeScopeHash)}
	shape := hash(c1wire(proof))
	for _, code := range []string{"purpose_key_separation", "historic_verification", "scoped_signer", "policy_separation"} {
		evi.Capabilities = append(evi.Capabilities, sec.CapabilityObservation{Code: code, Status: "supported", Reason: "none", RequestScopeHash: string(n.target.ProbeScopeHash), ResponseShapeHash: &shape, CheckedAt: finished.Format(time.RFC3339Nano), ExpiresAt: n.until.Format(time.RFC3339Nano)})
	}
	evi.Redaction.Applied = true
	evi.Redaction.Removed = []string{"credential", "token", "private_key", "uri", "raw_response", "raw_log"}
	evi.Redaction.RawMaterial = false
	evi.Cleanup.RunID = "cap-" + hex.EncodeToString(nonce)
	evi.Cleanup.Owner = "A:original-c1-" + hex.EncodeToString(nonce)
	evi.Cleanup.Removed = true
	evi.Cleanup.VerifiedAt = finished.Format(time.RFC3339Nano)
	if sec.ValidateCapabilityEvidence(evi, sec.CapabilityPolicy{Now: time.Now().UTC(), MaxValidity: time.Minute, ValidUntil: n.until, Role: "signing", IdentityHash: string(n.target.IdentityHash), RefVersion: "1", ScopeHash: string(n.target.ProbeScopeHash)}) != nil {
		return ErrInstall
	}
	n.body, e = json.Marshal(evi)
	if e != nil {
		return ErrInstall
	}
	n.attestation = hash(c1wire(struct {
		Version     string
		Probe       pd.Hash
		Body, Proof string
	}{"original-c1-signing-native-attestation.v1", probe.BindingHash(), hash(n.body), shape}))
	version := pd.Text("1")
	sum := pd.Hash(shape)
	n.results = pd.Results{Dependency: &pd.DependencyResults{Kind: "dependency", Observations: []pd.DependencyObservation{{Slot: "signing", Status: "healthy", Reason: "none", ObservedVersion: &version, ObservedChecksum: &sum}}}}
	n.observed = true
	return nil
}
func (n *originalC1NativeObservation) identity(evidenceID string) ev.Identity {
	sum := sha256.Sum256(n.body)
	return ev.Identity{Installation: string(n.parent.domain.Scope.Installation), ID: evidenceID, OwnerType: "system", OwnerID: string(n.parent.domain.Scope.Installation), Type: "capability_snapshot", Media: "application/json", Classification: "internal", ContentHash: hex.EncodeToString(sum[:]), ContentSize: int64(len(n.body))}
}
func (n *originalC1NativeObservation) contentPolicy(identity ev.Identity) ev.CapabilityContentPolicy {
	var doc sec.CapabilityEvidence
	_ = json.Unmarshal(n.body, &doc)
	return ev.CapabilityContentPolicy{Installation: identity.Installation, EvidenceID: identity.ID, Classification: identity.Classification, Role: string(n.target.Role), ProviderIdentity: string(n.target.IdentityHash), ProviderVersion: string(n.target.RefVersion), ScopeHash: string(n.target.ProbeScopeHash), RunID: doc.Cleanup.RunID, OwnerMarker: doc.Cleanup.Owner, MaxValidity: time.Minute, ValidUntil: n.until}
}
func (n *originalC1NativeObservation) close() { clear(n.body); n.body = nil }
