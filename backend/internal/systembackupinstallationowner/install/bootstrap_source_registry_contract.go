package install

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

const BootstrapSourceRegistryVersion = "system-backup-original-bootstrap-source-registries.v1"
const BootstrapSourceRegistryDomain = BootstrapSourceRegistryVersion + "\x00"
const BootstrapSourceRegistryProfile = "original-source.functional-test.v1"

// These pins select original bytes. Neither a pin nor this distinct association
// declares a registry correct, an observation fresh, a writer stopped or a task
// authorized. A concrete B reader must still authenticate complete registries
// against its real finite source observations before providing terminal slots.
type BootstrapSourceFilePin struct{ File, SHA256 string }

// Purpose is closed. Account is the actual native identity that the reader must
// compare (SQL CURRENT_USER, Redis ACL user, object access key or API SA UID).
// Credential files contain no plaintext in this signed comparison record.
type BootstrapSourceConnection struct {
	Purpose, Endpoint, Account, ServerUUID, Database string
	CA, Credential                                  BootstrapSourceFilePin
	IdentitySHA256, ScopeSHA256                      string
}

type BootstrapSourceController struct {
	Namespace, NamespaceUID, Deployment, DeploymentUID       string
	ReplicaSet, ReplicaSetUID, Pod, PodUID                    string
	ServiceAccount, ServiceAccountUID                        string
}

// This is a separate explicit read-only agent delegation. Endpoints are NOT
// caller-selected: the real reader must derive them from complete signed-scope
// source SQL, compare the actual Pod/controller graph, and call GatewayState
// only. A missing binding is admissible solely when that census has no Lite
// agent writer; it never supplies a stopped/recovery witness.
type BootstrapSourceRuntimeAgent struct {
	Operation, ScopeSHA256 string
	CA, Credential        BootstrapSourceFilePin
}

type BootstrapSourceRegistryDefinition struct {
	SchemaVersion, Profile                            string
	MetadataGrant, MetadataIssuerPublic                BootstrapSourceFilePin
	Deployment, Materials, ExecutionProfile            BootstrapSourceFilePin
	PartsRegistry, SourceWritersRegistry               BootstrapSourceFilePin
	Controller                                         BootstrapSourceController
	Connections                                        []BootstrapSourceConnection
	RuntimeAgent                                       *BootstrapSourceRuntimeAgent
}

type BootstrapSourceRegistryRecord struct {
	SchemaVersion, Profile, PlanSHA256, CaptureRecordSHA256, DefinitionSHA256 string
	Target                                                                 owner.Target
	Actor                                                                  owner.Actor
	Enrollment                                                             EnrollmentPin
	NotBefore, Until                                                       time.Time
	Selection                                                              pd.BootstrapConsumptionRequest
	Parts, SourceWriters                                                   sec.BootstrapRegistryRef
	Source                                                                 BootstrapSourceRegistryDefinition
	Metadata                                                               ControllerSourceMetadataGrant
	MetadataRecordSHA256, MetadataIssuerSHA256                              string
}

type SignedBootstrapSourceRegistries struct{ Record, Signature []byte }

func bootstrapSourcePinValid(p BootstrapSourceFilePin) bool {
	return filepath.IsAbs(p.File) && filepath.Clean(p.File) == p.File && digestPattern.MatchString(p.SHA256)
}

func bootstrapSourceRegistryPins(config sec.BootstrapConfig) (sec.BootstrapRegistryRef, sec.BootstrapRegistryRef) {
	var parts, writers sec.BootstrapRegistryRef
	for _, pin := range config.Registries() {
		if pin.Kind == "parts" {
			parts = pin
		}
		if pin.Kind == "source_writers" {
			writers = pin
		}
	}
	return parts, writers
}

func validateBootstrapSourceDefinition(d BootstrapSourceRegistryDefinition) error {
	if d.SchemaVersion != BootstrapSourceRegistryVersion || d.Profile != BootstrapSourceRegistryProfile || len(d.Connections) != 4 {
		return ErrInstall
	}
	for _, pin := range []BootstrapSourceFilePin{d.MetadataGrant, d.MetadataIssuerPublic, d.Deployment, d.Materials, d.ExecutionProfile, d.PartsRegistry, d.SourceWritersRegistry} {
		if !bootstrapSourcePinValid(pin) {
			return ErrInstall
		}
	}
	if a := d.RuntimeAgent; a != nil && (a.Operation != "gateway_state_read" || !digestPattern.MatchString(a.ScopeSHA256) || !bootstrapSourcePinValid(a.CA) || !bootstrapSourcePinValid(a.Credential)) {
		return ErrInstall
	}
	b := d.Controller
	for _, value := range []string{b.Namespace, b.NamespaceUID, b.Deployment, b.DeploymentUID, b.ReplicaSet, b.ReplicaSetUID, b.Pod, b.PodUID, b.ServiceAccount, b.ServiceAccountUID} {
		if value == "" || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
			return ErrInstall
		}
	}
	// Native agent endpoints are derived from the actual source census under the
	// separate read-only binding above, never from a caller-selected URL.
	purposes := []string{"source_api", "source_objects", "source_redis", "source_sql"}
	for n, c := range d.Connections {
		u, err := url.Parse(c.Endpoint)
		if c.Purpose != purposes[n] || err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery || u.Path != "" || u.Scheme != "https" && u.Scheme != "rediss" && u.Scheme != "mysql+tls" || c.Account == "" || len(c.Account) > 256 || strings.ContainsAny(c.Account, "\x00\r\n") || !bootstrapSourcePinValid(c.CA) || !bootstrapSourcePinValid(c.Credential) || !digestPattern.MatchString(c.IdentitySHA256) || !digestPattern.MatchString(c.ScopeSHA256) {
			return ErrInstall
		}
		if c.Purpose == "source_sql" {
			if c.ServerUUID == "" || c.Database == "" || u.Scheme != "mysql+tls" {
				return ErrInstall
			}
		} else if c.ServerUUID != "" || c.Database != "" || c.Purpose == "source_redis" && u.Scheme != "rediss" || c.Purpose != "source_redis" && u.Scheme != "https" {
			return ErrInstall
		}
	}
	return nil
}

// Metadata uses its ORIGINAL struct-order JSON wire, not the new protocol's
// JCS wire. Keeping these separate prevents cross-domain signature confusion.
func decodeBootstrapSourceMetadata(raw, public []byte) (ControllerSourceMetadataGrant, string, error) {
	var envelope struct{ Record, Signature []byte }
	var grant ControllerSourceMetadataGrant
	if len(raw) == 0 || len(raw) > 65536 || len(public) != ed25519.PublicKeySize || json.Unmarshal(raw, &envelope) != nil || len(envelope.Record) == 0 || len(envelope.Record) > 32768 || !ed25519.Verify(public, append([]byte("system-backup-controller-source-metadata.v1\x00"), envelope.Record...), envelope.Signature) || json.Unmarshal(envelope.Record, &grant) != nil {
		return grant, "", ErrInstall
	}
	outer, e := json.Marshal(envelope)
	inner, ie := json.Marshal(grant)
	if e != nil || ie != nil || !bytes.Equal(raw, outer) || !bytes.Equal(envelope.Record, inner) || grant.Version != "system-backup-original-source-metadata-grant.v1" || grant.Revoked || grant.NotBefore.IsZero() || !grant.NotBefore.Before(grant.Until) || grant.Until.Sub(grant.NotBefore) > 24*time.Hour {
		return grant, "", ErrInstall
	}
	for _, sha := range []string{grant.DeploymentConfigSHA256, grant.CaptureGrantSHA256, grant.ConfigSHA256, grant.ScopeSHA256} {
		if !digestPattern.MatchString(sha) {
			return grant, "", ErrInstall
		}
	}
	return grant, hash(envelope.Record), nil
}

func validateBootstrapSourceRecord(r BootstrapSourceRegistryRecord) error {
	if r.SchemaVersion != BootstrapSourceRegistryVersion || r.Profile != BootstrapSourceRegistryProfile || validateBootstrapSourceDefinition(r.Source) != nil || r.NotBefore.IsZero() || !r.NotBefore.Before(r.Until) || r.Until.Sub(r.NotBefore) > 24*time.Hour || bootstrapSourceSelectionHash(r.Selection) == "" || r.Selection.Scope != (pd.Scope{Installation: pd.Installation(r.Target.InstallationID), ServerUUID: pd.ServerUUID(r.Target.ServerUUID), Database: pd.Database(r.Target.Database)}) || r.Selection.ActorID != pd.Counter(strconv.FormatInt(r.Actor.UserID, 10)) || r.Selection.Username != r.Actor.Username {
		return ErrInstall
	}
	for _, sha := range []string{r.PlanSHA256, r.CaptureRecordSHA256, r.DefinitionSHA256, r.MetadataRecordSHA256, r.MetadataIssuerSHA256} {
		if !digestPattern.MatchString(sha) {
			return ErrInstall
		}
	}
	g, b := r.Metadata, r.Source.Controller
	if r.Parts.Kind != "parts" || r.SourceWriters.Kind != "source_writers" || r.Parts.Version == "" || r.SourceWriters.Version == "" || r.Parts.SHA256 != r.Source.PartsRegistry.SHA256 || r.SourceWriters.SHA256 != r.Source.SourceWritersRegistry.SHA256 || r.MetadataIssuerSHA256 != r.Source.MetadataIssuerPublic.SHA256 || g.Version != "system-backup-original-source-metadata-grant.v1" || g.ControllerOwner == "" || g.Revoked || g.NotBefore.IsZero() || !g.NotBefore.Before(g.Until) || g.Until.Sub(g.NotBefore) > 24*time.Hour || g.InstallationID != r.Target.InstallationID || g.ConfigSHA256 != string(r.Selection.ConfigHash) || g.DeploymentConfigSHA256 != r.Source.Deployment.SHA256 || g.Namespace != b.Namespace || g.NamespaceUID != b.NamespaceUID || g.ControllerDeployment != b.Deployment || g.ControllerDeploymentUID != b.DeploymentUID || g.ControllerServiceAccount != b.ServiceAccount || g.ControllerServiceAccountUID != b.ServiceAccountUID || b.Namespace != r.Target.Namespace || b.NamespaceUID != r.Target.NamespaceUID || r.NotBefore.Before(g.NotBefore) || r.Until.After(g.Until) {
		return ErrInstall
	}
	metadata, err := json.Marshal(g)
	if err != nil || hash(metadata) != r.MetadataRecordSHA256 || !digestPattern.MatchString(g.CaptureGrantSHA256) || !digestPattern.MatchString(g.ScopeSHA256) {
		return ErrInstall
	}
	return nil
}

func bootstrapSourceSelectionHash(r pd.BootstrapConsumptionRequest) string {
	h, err := pd.BootstrapConsumptionHash(r)
	if err != nil {
		return ""
	}
	return string(h)
}

func verifyBootstrapSourceRegistries(raw, signature, public []byte) (BootstrapSourceRegistryRecord, error) {
	var r BootstrapSourceRegistryRecord
	if len(raw) == 0 || len(raw) > 262144 || len(signature) != ed25519.SignatureSize || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, append([]byte(BootstrapSourceRegistryDomain), raw...), signature) || decodeExact(raw, &r) != nil || validateBootstrapSourceRecord(r) != nil || r.MetadataIssuerSHA256 != hash(public) {
		return r, ErrInstall
	}
	return r, nil
}
