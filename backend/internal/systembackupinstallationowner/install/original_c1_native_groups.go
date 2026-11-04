package install

import (
	ev "clawreef/internal/systembackupevidence"
	pd "clawreef/internal/systembackupproducer"
	probeNative "clawreef/internal/systembackupreferenceprobe"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"time"
)

// Concrete original group factories. No callback, arbitrary results, approved
// flag, or matching reference hashes can construct a native observation.
func (p *OriginalC1Production) newSixReferenceObservation(ctx context.Context, in OriginalC1SigningPipelineInputs, pin BootstrapSourceFilePin) (*originalC1NativeObservation, error) {
	n, err := p.newSigningObservation(ctx, in.SigningMaterial, in.ControllerDeployment, in.ControllerPod)
	if err != nil {
		return nil, err
	}
	raw, err := readBootstrapSourcePin(pin, 262144)
	var d SixReferenceDefinition
	if err != nil || decodeExact(raw, &d) != nil || validateSixReference(d) != nil || d.S3.Installation != string(p.domain.Scope.Installation) || d.S3.Namespace != n.actor.Namespace || d.S3.NamespaceUID != n.actor.NamespaceUID {
		return nil, ErrInstall
	}
	actual, err := sixConfigReferences(p.request.config)
	if err != nil || !sameSixReferences(actual, d.References) {
		return nil, ErrInstall
	}
	n.kind = "six-current-native-permissions"
	n.six = &d
	n.groupSource = pin
	n.references = actual
	if d.Until.Before(n.until) {
		n.until = d.Until
	}
	if time.Now().Before(d.NotBefore) {
		return nil, ErrInstall
	}
	if err = n.bindGroupTarget([]pd.ID{"artifact_credential", "evidence", "kek"}); err != nil {
		return nil, err
	}
	return n, nil
}
func (p *OriginalC1Production) newStatusRelayObservation(ctx context.Context, in OriginalC1SigningPipelineInputs, pin BootstrapSourceFilePin) (*originalC1NativeObservation, error) {
	n, err := p.newSigningObservation(ctx, in.SigningMaterial, in.ControllerDeployment, in.ControllerPod)
	if err != nil {
		return nil, err
	}
	raw, err := readBootstrapSourcePin(pin, 262144)
	var d StatusRelayReferenceDefinition
	if err != nil || decodeExact(raw, &d) != nil || validateStatusRelayReference(d) != nil || d.Controller.Pod != n.actor.PodName || d.Controller.PodUID != n.actor.PodUID || d.Controller.NamespaceUID != n.actor.NamespaceUID || d.Controller.ServiceAccountUID != n.actor.ServiceAccountUID {
		return nil, ErrInstall
	}
	ref, err := StatusRelayReferenceIdentity(raw, pin.SHA256)
	if err != nil {
		return nil, err
	}
	found := false
	for _, actual := range p.request.config.References() {
		if actual.Purpose == "status_relay" {
			if actual != ref {
				return nil, ErrInstall
			}
			found = true
		}
	}
	if !found || time.Now().Before(d.NotBefore) {
		return nil, ErrInstall
	}
	n.kind = "status-relay-actual-current-mtls"
	n.status = &d
	n.groupSource = pin
	n.references = []sec.BootstrapSecretRef{ref}
	if d.Until.Before(n.until) {
		n.until = d.Until
	}
	if err = n.bindGroupTarget([]pd.ID{"attestation"}); err != nil {
		return nil, err
	}
	return n, nil
}
func (n *originalC1NativeObservation) bindGroupTarget(slots []pd.ID) error {
	if n == nil || n.kind == "signing" || n.groupSource.File == "" || len(n.references) == 0 {
		return ErrInstall
	}
	sort.Slice(n.references, func(i, j int) bool { return n.references[i].Purpose < n.references[j].Purpose })
	scope, err := canonical(struct {
		Version, Kind, Plan, Native, Actor string
		References                         []sec.BootstrapSecretRef
	}{"original-c1-concrete-dependency-scope.v1", n.kind, n.parent.operator.installer.planHash, n.groupSource.SHA256, n.identityVersion, n.references})
	if err != nil {
		return ErrInstall
	}
	n.referenceHash = hash(c1wire(n.references))
	n.policy = hash(c1wire(struct{ Version, Kind, Scope string }{"original-c1-concrete-dependency-policy.v1", n.kind, hash(scope)}))
	n.target = pd.Target{EvaluatorOwner: "A", EvaluatorProfileHash: pd.Hash(n.policy), Role: n.target.Role, IdentityHash: pd.Hash(hash(scope)), RefVersion: "1", ProbeScopeHash: pd.Hash(hash(scope)), ResultSlots: append([]pd.ID(nil), slots...)}
	return nil
}
func (n *originalC1NativeObservation) recheckGroupFiles(ctx context.Context) error {
	if n.local(ctx) != nil || n.groupSource.File == "" {
		return ErrInstall
	}
	if _, err := readBootstrapSourcePin(n.groupSource, 262144); err != nil {
		return ErrInstall
	}
	if _, err := readBootstrapSourcePin(n.source, 262144); err != nil {
		return ErrInstall
	}
	current, err := n.parent.operator.installer.originalPublicationActor(ctx, n.deployment, n.actor.PodName)
	if err != nil || !sameC1Actor(current, n.actor) {
		return ErrInstall
	}
	switch n.kind {
	case "backup-kek-original-signed-native-permissions":
		if n.backup == nil || n.backupWire == nil {
			return ErrInstall
		}
		for _, pin := range []BootstrapSourceFilePin{n.backupWire.Observer, n.backupWire.Record, n.backupWire.Signature, n.backupWire.RuntimeIssuers} {
			raw, err := readBootstrapSourcePin(pin, 262144)
			clear(raw)
			if err != nil {
				return ErrInstall
			}
		}
	case "catalog-original-immutable-initial-checkpoint":
		if n.catalog == nil || n.five == nil || probeNative.RecheckOriginalFiveFiles(*n.five) != nil {
			return ErrInstall
		}
		for _, pin := range n.fiveFiles {
			raw, err := readBootstrapSourcePin(pin, 65536)
			clear(raw)
			if err != nil {
				return ErrInstall
			}
		}
	case "nonce-original-controlled-exact-version", "evidence-ca-actual-tls":
		if n.recheckLocalGroupInputs(ctx) != nil {
			return ErrInstall
		}
	case "minio-five-current-permissions-and-artifact-ca":
		if n.five == nil || probeNative.RecheckOriginalFiveFiles(*n.five) != nil {
			return ErrInstall
		}
		for _, pin := range n.fiveFiles {
			raw, err := readBootstrapSourcePin(pin, 65536)
			clear(raw)
			if err != nil {
				return ErrInstall
			}
		}
	case "six-current-native-permissions":
		if n.six == nil || recheckSixReferenceFiles(*n.six) != nil {
			return ErrInstall
		}
	case "status-relay-actual-current-mtls":
		if n.status == nil {
			return ErrInstall
		}
		for _, pin := range []BootstrapSourceFilePin{n.status.Deployment, n.status.CA, n.status.ClientCertificate, n.status.ClientPrivateKey} {
			raw, err := readBootstrapSourcePin(pin, 262144)
			clear(raw)
			if err != nil {
				return ErrInstall
			}
		}
	default:
		return ErrInstall
	}
	return n.parent.recheckPrepared()
}
func (n *originalC1NativeObservation) observeGroup(ctx context.Context, probe *pd.CallSnapshot, runID string) error {
	if n.recheckGroupFiles(ctx) != nil || n.observed || probe == nil || probe.Purpose() != "probe" || probe.View().Facts.Run.RunID != pd.ID(runID) || !reflect.DeepEqual(probe.View().Facts.Grant.Target, n.target) {
		return ErrInstall
	}
	i := n.parent.operator.installer
	var identity string
	var started, until time.Time
	switch n.kind {
	case "backup-kek-original-signed-native-permissions":
		actual, err := n.backup.ObserveOriginalCurrent(ctx)
		if err != nil {
			return ErrInstall
		}
		identity, started, until, err = actual.Facts(ctx)
		if err != nil {
			return ErrInstall
		}
	case "catalog-original-immutable-initial-checkpoint":
		actual, err := probeNative.ObserveOriginalCatalogCheckpoint(ctx, i.kube, *n.five, n.catalog.Bucket, n.catalog.Key, n.catalog.VersionID, n.catalogEnvelope)
		if err != nil {
			return ErrInstall
		}
		identity, started, until = actual.IdentitySHA256(), actual.StartedAt(), actual.ValidUntil()
	case "nonce-original-controlled-exact-version":
		actual, err := n.nonce.ObserveOriginalCurrent(ctx, n.parent.request.grant, n.parent.request.config)
		if err != nil {
			return ErrInstall
		}
		identity, started, until, err = actual.Facts(ctx)
		if err != nil {
			return ErrInstall
		}
	case "evidence-ca-actual-tls":
		actual, err := n.ca.ObserveOriginalCurrent(ctx, n.parent.request.grant, n.parent.request.config)
		if err != nil {
			return ErrInstall
		}
		identity, started, until, err = actual.Facts(ctx)
		if err != nil {
			return ErrInstall
		}

	case "minio-five-current-permissions-and-artifact-ca":
		actual, err := probeNative.ObserveOriginalFive(ctx, i.kube, *n.five)
		if err != nil {
			return ErrInstall
		}
		identity, started, until = actual.IdentitySHA256(), actual.StartedAt(), actual.ValidUntil()
	case "six-current-native-permissions":
		actual, err := observeSixReference(ctx, i.kube, i.plan.Target, *n.six)
		if err != nil {
			return ErrInstall
		}
		identity, started, until = actual.identity, actual.started, actual.until
	case "status-relay-actual-current-mtls":
		actual, err := observeStatusRelayReference(ctx, i.kube, i.plan.Target, *n.status)
		if err != nil {
			return ErrInstall
		}
		identity, started, until = actual.identity, actual.started, actual.until
	default:
		return ErrInstall
	}
	if !digestPattern.MatchString(identity) || started.After(time.Now()) || n.recheckGroupFiles(ctx) != nil {
		return ErrInstall
	}
	if short := started.Add(15 * time.Second); short.Before(until) {
		until = short
	}
	if n.until.Before(until) {
		until = n.until
	}
	if !time.Now().Before(until) {
		return ErrInstall
	}
	n.started, n.until, n.groupProof = started, until, identity
	// These are current resource/identity dependency checks. They do not claim
	// GenerateDataKey, PutObject, retention deletion, or all provider capabilities.
	// Six native probes independently verify BOTH original account+effective
	// native policy/versioning and Vault scope; relay verifies actual mTLS key
	// possession and unchanged actual current Pod/Service/endpoint identities.
	return n.finishGroupObservation(probe)
}
func (n *originalC1NativeObservation) finishGroupObservation(probe *pd.CallSnapshot) error {
	finished := time.Now().UTC().Truncate(time.Microsecond)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return ErrInstall
	}
	evi := sec.CapabilityEvidence{SchemaVersion: "system-backup-capability-evidence.v1", Role: string(n.target.Role), IdentityHash: string(n.target.IdentityHash), RefVersion: "1", StartedAt: n.started.Format(time.RFC3339Nano), FinishedAt: finished.Format(time.RFC3339Nano), ScopeHash: string(n.target.ProbeScopeHash)}
	codes := n.groupCodes
	if len(codes) == 0 {
		codes = []string{"exact_version_read", "resource_version_guard", "uid_guard"}
	}
	for _, code := range codes {
		shape := n.groupProof
		evi.Capabilities = append(evi.Capabilities, sec.CapabilityObservation{Code: code, Status: "supported", Reason: "none", RequestScopeHash: string(n.target.ProbeScopeHash), ResponseShapeHash: &shape, CheckedAt: finished.Format(time.RFC3339Nano), ExpiresAt: n.until.Format(time.RFC3339Nano)})
	}
	evi.Redaction.Applied = true
	evi.Redaction.Removed = []string{"credential", "secret", "token", "private_key", "uri", "raw_response", "raw_log"}
	// These concrete probes perform reads/handshakes only and create no remote
	// artifact or user. Therefore actual temporary artifact cleanup is empty.
	evi.Cleanup.RunID = "cap-" + hex.EncodeToString(nonce)
	evi.Cleanup.Owner = "A:original-c1-" + hex.EncodeToString(nonce)
	evi.Cleanup.Removed = true
	evi.Cleanup.VerifiedAt = finished.Format(time.RFC3339Nano)
	if sec.ValidateCapabilityEvidence(evi, sec.CapabilityPolicy{Now: time.Now().UTC(), MaxValidity: 15 * time.Second, ValidUntil: n.until, Role: string(n.target.Role), IdentityHash: string(n.target.IdentityHash), RefVersion: "1", ScopeHash: string(n.target.ProbeScopeHash)}) != nil {
		return ErrInstall
	}
	body, err := json.Marshal(evi)
	if err != nil {
		return ErrInstall
	}
	n.body = body
	n.attestation = hash(c1wire(struct {
		Version, Kind, Native, Body string
		Probe                       pd.Hash
	}{"original-c1-concrete-dependency-attestation.v1", n.kind, n.groupProof, hash(body), probe.BindingHash()}))
	version := pd.Text("1")
	sum := pd.Hash(n.groupProof)
	observations := []pd.DependencyObservation{}
	for _, slot := range n.target.ResultSlots {
		observations = append(observations, pd.DependencyObservation{Slot: string(slot), Status: "healthy", Reason: "none", ObservedVersion: &version, ObservedChecksum: &sum})
	}
	n.results = pd.Results{Dependency: &pd.DependencyResults{Kind: "dependency", Observations: observations}}
	n.observed = true
	return nil
}
func (p *OriginalC1Production) ProduceOriginalC1SixReferences(ctx context.Context, capacityDB *sql.DB, channel *ev.OriginalC1OwnerChannel, in OriginalC1SigningPipelineInputs, definition BootstrapSourceFilePin, password, issuerPrivate []byte) (*OriginalC1SigningProduction, error) {
	n, err := p.newSixReferenceObservation(ctx, in, definition)
	if err != nil {
		return nil, err
	}
	return p.produceOriginalC1Observed(ctx, capacityDB, channel, in, n, password, issuerPrivate)
}
func (p *OriginalC1Production) ProduceOriginalC1StatusRelay(ctx context.Context, capacityDB *sql.DB, channel *ev.OriginalC1OwnerChannel, in OriginalC1SigningPipelineInputs, definition BootstrapSourceFilePin, password, issuerPrivate []byte) (*OriginalC1SigningProduction, error) {
	n, err := p.newStatusRelayObservation(ctx, in, definition)
	if err != nil {
		return nil, err
	}
	return p.produceOriginalC1Observed(ctx, capacityDB, channel, in, n, password, issuerPrivate)
}
