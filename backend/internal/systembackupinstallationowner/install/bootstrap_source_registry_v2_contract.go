package install

import (
	"crypto/ed25519"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// V2 is a NEW required-field protocol, not an upgrade of a v1 gateway-only
// delegation. No v1/controller-metadata signature verifies under this domain.
const BootstrapSourceRegistryV2Version = "system-backup-original-bootstrap-source-registries.v2"
const BootstrapSourceRegistryV2Domain = BootstrapSourceRegistryV2Version + "\x00"

type BootstrapSourceRuntimeAgentV2 struct {
	Operations            []string
	ScopeSHA256           string
	CA, Credential        BootstrapSourceFilePin
}

type BootstrapSourceRegistryV2Definition struct {
	SchemaVersion, Profile, ApplicationScope           string
	MetadataGrant, MetadataIssuerPublic                BootstrapSourceFilePin
	Deployment, Materials, ExecutionProfile            BootstrapSourceFilePin
	ForwardGrant                                       BootstrapSourceFilePin
	PartsRegistry, SourceWritersRegistry               BootstrapSourceFilePin
	Controller                                         BootstrapSourceController
	Connections                                        []BootstrapSourceConnection
	RuntimeAgent                                       *BootstrapSourceRuntimeAgentV2
}

type BootstrapSourceRegistryV2Record struct {
	SchemaVersion, Profile, PlanSHA256, CaptureRecordSHA256, DefinitionSHA256 string
	Target                                                                 owner.Target
	Actor                                                                  owner.Actor
	Enrollment                                                             EnrollmentPin
	NotBefore, Until                                                       time.Time
	Selection                                                              pd.BootstrapConsumptionRequest
	Parts, SourceWriters                                                   sec.BootstrapRegistryRef
	Source                                                                 BootstrapSourceRegistryV2Definition
	Metadata                                                               ControllerSourceMetadataGrant
	MetadataRecordSHA256, MetadataIssuerSHA256                              string
}

type SignedBootstrapSourceRegistriesV2 struct{ Record, Signature []byte }

func bootstrapSourceV2Files(d BootstrapSourceRegistryV2Definition) []BootstrapSourceFilePin {
	pins := []BootstrapSourceFilePin{d.MetadataGrant, d.MetadataIssuerPublic, d.Deployment, d.Materials, d.ExecutionProfile, d.ForwardGrant, d.PartsRegistry, d.SourceWritersRegistry}
	for _, c := range d.Connections {
		pins = append(pins, c.CA, c.Credential)
	}
	if d.RuntimeAgent != nil {
		pins = append(pins, d.RuntimeAgent.CA, d.RuntimeAgent.Credential)
	}
	return pins
}

func BootstrapSourceConnectionIdentitySHA256(installation string, c BootstrapSourceConnection) (string, error) {
	raw, err := canonical(struct {
		Version, Installation, Purpose, Endpoint, Account, UUID, Database, CA string
	}{"original-source-native-connection-identity.v1", installation, c.Purpose, c.Endpoint, c.Account, c.ServerUUID, c.Database, c.CA.SHA256})
	if err != nil {
		return "", ErrInstall
	}
	return hash(raw), nil
}

// The scope hash binds exact SELECT semantics, not a count or an operator's
// LeaseParticipants declaration. Actual native rows/role/TLS remain mandatory.
func BootstrapSourceControlScopeSHA256(installation, applicationScope string, c BootstrapSourceConnection) (string, error) {
	raw, err := canonical(struct {
		Version, Installation, ApplicationScope, Endpoint, UUID, Database, Account string
		Table, Query, CA, Credential, Identity                                     string
		Projection                                                                 []string
	}{"original-source-control-participant-read-scope.v1", installation, applicationScope, c.Endpoint, c.ServerUUID, c.Database, c.Account, "system_backup_participants", "SELECT participant_id FROM system_backup_participants WHERE scope=? ORDER BY participant_id", c.CA.SHA256, c.Credential.SHA256, c.IdentitySHA256, []string{"scope", "participant_id"}})
	if err != nil {
		return "", ErrInstall
	}
	return hash(raw), nil
}

func BootstrapSourceNativeRoleScopeSHA256(installation string, d BootstrapSourceRegistryV2Definition, c BootstrapSourceConnection, metadataScope string) (string, error) {
	if c.Purpose == "control_sql" {
		return BootstrapSourceControlScopeSHA256(installation, d.ApplicationScope, c)
	}
	raw, err := canonical(struct {
		Version, Installation, ApplicationScope, Purpose, Identity string
		Deployment, Materials, Profile, MetadataGrant, MetadataScope, CA, Credential string
	}{"original-source-finite-native-read-scope.v1", installation, d.ApplicationScope, c.Purpose, c.IdentitySHA256, d.Deployment.SHA256, d.Materials.SHA256, d.ExecutionProfile.SHA256, d.MetadataGrant.SHA256, metadataScope, c.CA.SHA256, c.Credential.SHA256})
	if err != nil {
		return "", ErrInstall
	}
	return hash(raw), nil
}

func BootstrapSourceAgentScopeSHA256(installation string, d BootstrapSourceRegistryV2Definition) (string, error) {
	if d.RuntimeAgent == nil {
		return "", ErrInstall
	}
	raw, err := canonical(struct {
		Version, Installation, ApplicationScope, Deployment, Materials, Profile, CA, Credential string
		Connections []BootstrapSourceConnection
		Operations  []string
	}{"original-source-two-native-agent-reads.v1", installation, d.ApplicationScope, d.Deployment.SHA256, d.Materials.SHA256, d.ExecutionProfile.SHA256, d.RuntimeAgent.CA.SHA256, d.RuntimeAgent.Credential.SHA256, d.Connections, d.RuntimeAgent.Operations})
	if err != nil {
		return "", ErrInstall
	}
	return hash(raw), nil
}

func validateBootstrapSourceV2(r BootstrapSourceRegistryV2Record) error {
	d := r.Source
	if r.SchemaVersion != BootstrapSourceRegistryV2Version || d.SchemaVersion != BootstrapSourceRegistryV2Version || r.Profile != BootstrapSourceRegistryProfile || d.Profile != r.Profile || d.ApplicationScope == "" || len(d.ApplicationScope) > 256 || strings.ContainsAny(d.ApplicationScope, "\x00\r\n") || len(d.Connections) != 5 {
		return ErrInstall
	}
	if !bootstrapSourcePinValid(d.ForwardGrant) || d.ForwardGrant.SHA256 != r.Metadata.CaptureGrantSHA256 {
		return ErrInstall
	}
	// The existing v1 DATA validator validates only the common original anchor
	// and four source roles. It supplies no signature/authority/extra operation.
	base := bootstrapSourceV2IdentityProjection(r)
	if validateBootstrapSourceRecord(base) != nil {
		return ErrInstall
	}
	for n, purpose := range []string{"control_sql", "source_api", "source_objects", "source_redis", "source_sql"} {
		c := d.Connections[n]
		if c.Purpose != purpose || !bootstrapSourcePinValid(c.CA) || !bootstrapSourcePinValid(c.Credential) {
			return ErrInstall
		}
		identity, err := BootstrapSourceConnectionIdentitySHA256(r.Target.InstallationID, c)
		scope, se := BootstrapSourceNativeRoleScopeSHA256(r.Target.InstallationID, d, c, r.Metadata.ScopeSHA256)
		if err != nil || se != nil || c.IdentitySHA256 != identity || c.ScopeSHA256 != scope {
			return ErrInstall
		}
	}
	control, source := d.Connections[0], d.Connections[4]
	u, err := url.Parse(control.Endpoint)
	if err != nil || u.Scheme != "mysql+tls" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery || control.Account == "" || len(control.Account) > 256 || strings.ContainsAny(control.Account, "\x00\r\n") || control.Account == source.Account || control.Credential.File == source.Credential.File || control.ServerUUID != r.Target.ServerUUID || control.Database != r.Target.Database {
		return ErrInstall
	}
	if a := d.RuntimeAgent; a != nil {
		if !reflect.DeepEqual(a.Operations, []string{"backup_capabilities_read", "gateway_state_read"}) || !bootstrapSourcePinValid(a.CA) || !bootstrapSourcePinValid(a.Credential) {
			return ErrInstall
		}
		scope, err := BootstrapSourceAgentScopeSHA256(r.Target.InstallationID, d)
		if err != nil || a.ScopeSHA256 != scope {
			return ErrInstall
		}
	}
	return nil
}

// This projection is PRIVATE original identity data, never a v1 signed grant
// or a returned caller capability. Only a fully VERIFIED V2 signature may use
// the shared capture-identity implementation; it cannot acquire V2 authority
// by presenting a v1 record. Control/agent permissions remain in V2 only.
func bootstrapSourceV2IdentityProjection(r BootstrapSourceRegistryV2Record) BootstrapSourceRegistryRecord {
	d := r.Source
	connections := []BootstrapSourceConnection{}
	for _, c := range d.Connections {
		if c.Purpose != "control_sql" {
			connections = append(connections, c)
		}
	}
	base := BootstrapSourceRegistryDefinition{SchemaVersion: BootstrapSourceRegistryVersion, Profile: d.Profile, MetadataGrant: d.MetadataGrant, MetadataIssuerPublic: d.MetadataIssuerPublic, Deployment: d.Deployment, Materials: d.Materials, ExecutionProfile: d.ExecutionProfile, PartsRegistry: d.PartsRegistry, SourceWritersRegistry: d.SourceWritersRegistry, Controller: d.Controller, Connections: connections}
	return BootstrapSourceRegistryRecord{SchemaVersion: BootstrapSourceRegistryVersion, Profile: r.Profile, PlanSHA256: r.PlanSHA256, CaptureRecordSHA256: r.CaptureRecordSHA256, DefinitionSHA256: r.DefinitionSHA256, Target: r.Target, Actor: r.Actor, Enrollment: r.Enrollment, NotBefore: r.NotBefore, Until: r.Until, Selection: r.Selection, Parts: r.Parts, SourceWriters: r.SourceWriters, Source: base, Metadata: r.Metadata, MetadataRecordSHA256: r.MetadataRecordSHA256, MetadataIssuerSHA256: r.MetadataIssuerSHA256}
}

func verifyBootstrapSourceV2(raw, signature, public []byte) (BootstrapSourceRegistryV2Record, error) {
	var r BootstrapSourceRegistryV2Record
	if len(raw) == 0 || len(raw) > 262144 || len(public) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(public, append([]byte(BootstrapSourceRegistryV2Domain), raw...), signature) || decodeExact(raw, &r) != nil || validateBootstrapSourceV2(r) != nil || r.MetadataIssuerSHA256 != hash(public) {
		return r, ErrInstall
	}
	return r, nil
}

func cloneBootstrapSourceV2(r BootstrapSourceRegistryV2Record) (BootstrapSourceRegistryV2Record, error) {
	var owned BootstrapSourceRegistryV2Record
	raw, err := json.Marshal(r)
	if err != nil || json.Unmarshal(raw, &owned) != nil {
		return owned, ErrInstall
	}
	return owned, nil
}

