package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	api "clawreef/internal/systembackupdeployment"
	pd "clawreef/internal/systembackupproducer"
)

// The source declaration/core/profile/Forward metadata are controlled signed
// DATA. The V2 association itself is issued ONLY by the real authenticated
// Installer action, then consumed through the actual original capture loader,
// TLS/enrollment transport and selected files. No Prepared object is fabricated.
// This is not a native source census or thirty-owner/terminal admission proof.
func newActualBootstrapSourceV2MaterialConsumer(t *testing.T, ctx context.Context, padding int) (*captureConsumerFixture, *PreparedBootstrapSourceRegistriesV2, BootstrapSourceRegistryV2Definition, []byte) {
	t.Helper()
	c, selection, pack := newBootstrapSourceAuthenticatedConsumer(t, ctx, time.Minute)
	f := c.f
	legacy, _ := bootstrapSourceProtocolDefinition(t, ctx, f)
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private V2 materials fixture")
	}
	write := func(name string, raw []byte) BootstrapSourceFilePin {
		t.Helper()
		file := filepath.Join(directory, name)
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return BootstrapSourceFilePin{File: file, SHA256: hash(raw)}
	}
	marshal := func(value any) []byte {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	d := BootstrapSourceRegistryV2Definition{SchemaVersion: BootstrapSourceRegistryV2Version, Profile: BootstrapSourceRegistryProfile, ApplicationScope: "original_application", MetadataIssuerPublic: legacy.MetadataIssuerPublic, Controller: legacy.Controller, PartsRegistry: legacy.PartsRegistry, SourceWritersRegistry: legacy.SourceWritersRegistry}
	profile := api.ExecutionProfile{InstallationID: f.record.Target.InstallationID, Revision: "source-fixture-v1", Orchestrator: "kubernetes", Profile: "cluster", TargetClass: "same-cluster-copy", TargetRisks: []string{"same_failure_domain"}, FailureDomain: "controlled-source-domain", RestoreTargetRef: "source-fixture-no-restore-delegation", RestoreTargetHash: hash([]byte("no-restore-authority"))}
	profileRaw, profileSHA, err := profile.CanonicalIdentity()
	if err != nil {
		t.Fatal(err)
	}
	d.ExecutionProfile = write("profile.json", profileRaw)
	connections := append([]BootstrapSourceConnection(nil), legacy.Connections...)
	sqlSource := &connections[3]
	sqlSource.Account = "source_reader@localhost"
	sqlSource.Credential = write("source.dsn", []byte("source_reader:source-secret@tcp(source.example:3306)/original_source?parseTime=true&tls=true"))
	control := BootstrapSourceConnection{Purpose: "control_sql", Endpoint: "mysql+tls://control.example:3306", Account: "control_reader@localhost", ServerUUID: f.record.Target.ServerUUID, Database: f.record.Target.Database, CA: write("control.ca", []byte("controlled source CA")), Credential: write("control.dsn", []byte("control_reader:control-secret@tcp(control.example:3306)/"+f.record.Target.Database+"?parseTime=true&tls=true"))}
	d.Connections = append([]BootstrapSourceConnection{control}, connections...)
	core := bootstrapSourceCoreWire{Version: "system-backup-public-deployment.v1", CaptureScope: "six-part", InstallationID: f.record.Target.InstallationID, ControllerOwner: "original-controller-owner", ApplicationScope: d.ApplicationScope, Namespace: f.record.Target.Namespace, NamespaceUID: f.record.Target.NamespaceUID, SourceDSNFile: sqlSource.Credential.File, SourceUser: "source_reader", SourceDatabase: sqlSource.Database, SourceServerUUID: sqlSource.ServerUUID, ProfileFile: d.ExecutionProfile.File}
	core.CaptureModules.Protocol, core.CaptureModules.Path = "original-six-part-capture-materials.v1", filepath.Join(directory, "materials.json")
	core.ForwardGrant.Path, core.ForwardGrant.PublicKey = filepath.Join(directory, "forward.json"), base64.StdEncoding.EncodeToString(f.i.public)
	d.Deployment = write("core.json", marshal(core))
	// This is the original independently signed execution envelope as DATA;
	// no enabled Forward object or future task is constructed by this fixture.
	forward := marshal(struct {
		Version      string    `json:"schema_version"`
		Installation string    `json:"installation_id"`
		Controller   string    `json:"controller_owner"`
		Config       string    `json:"config_sha256"`
		Profile      string    `json:"profile_sha256"`
		Deployment   string    `json:"deployment_config_sha256"`
		NotBefore    time.Time `json:"not_before"`
		Until        time.Time `json:"expires_at"`
	}{"system-backup-execution-grant.v1", core.InstallationID, core.ControllerOwner, string(selection.ConfigHash), profileSHA, d.Deployment.SHA256, f.record.NotBefore, f.record.Until})
	d.ForwardGrant = write("forward.json", marshal(struct {
		Payload   string `json:"payload_base64"`
		Signature string `json:"signature_base64"`
	}{base64.StdEncoding.EncodeToString(forward), base64.StdEncoding.EncodeToString(ed25519.Sign(f.key, forward))}))
	m := bootstrapSourceMaterialsWire{Version: "original-six-part-capture-materials.v1", Revision: "source-fixture-v1", InstallationID: core.InstallationID, ControllerOwner: core.ControllerOwner, DeploymentConfigSHA256: d.Deployment.SHA256, CaptureGrantSHA256: d.ForwardGrant.SHA256, Operations: map[string]json.RawMessage{"controlled-declaration": marshal(strings.Repeat("m", padding))}, Discovery: &bootstrapSourceDiscoveryWire{Issuer: f.i.public, ControllerDeployment: d.Controller.Deployment, ControllerDeploymentUID: d.Controller.DeploymentUID, ControllerServiceAccount: d.Controller.ServiceAccount, ControllerServiceAccountUID: d.Controller.ServiceAccountUID, SourceAPI: worker.ResourceSourceMount{Server: connections[0].Endpoint, CAFile: connections[0].CA.File, CASHA256: connections[0].CA.SHA256, TokenFile: connections[0].Credential.File}, SourceAPITokenSHA256: connections[0].Credential.SHA256, SourceAPIServiceAccount: "source-api", SourceAPIServiceAccountUID: connections[0].Account}}
	m.Redis = worker.FormalSourceMount{CredentialFile: connections[2].Credential.File, CredentialSHA256: connections[2].Credential.SHA256, Redis: &worker.SourceTLSMapping{Address: "source.example:6379", CAFile: connections[2].CA.File, CASHA256: connections[2].CA.SHA256}}
	m.Objects = worker.FormalSourceMount{CredentialFile: connections[1].Credential.File, CredentialSHA256: connections[1].Credential.SHA256, Objects: &worker.SourceTLSMapping{Address: "source.example:443", CAFile: connections[1].CA.File, CASHA256: connections[1].CA.SHA256}}
	scope, err := BootstrapSourceMetadataScopeFromMaterials(marshal(m))
	if err != nil {
		t.Fatal("actual original materials scope wire", err)
	}
	metadata := ControllerSourceMetadataGrant{Version: "system-backup-original-source-metadata-grant.v1", InstallationID: core.InstallationID, ControllerOwner: core.ControllerOwner, DeploymentConfigSHA256: d.Deployment.SHA256, CaptureGrantSHA256: d.ForwardGrant.SHA256, ConfigSHA256: f.config.SHA256(), ScopeSHA256: scope, Namespace: d.Controller.Namespace, NamespaceUID: d.Controller.NamespaceUID, ControllerDeployment: d.Controller.Deployment, ControllerDeploymentUID: d.Controller.DeploymentUID, ControllerServiceAccount: d.Controller.ServiceAccount, ControllerServiceAccountUID: d.Controller.ServiceAccountUID, NotBefore: f.record.NotBefore, Until: f.record.Until}
	metadataRaw := marshal(metadata)
	d.MetadataGrant = write("metadata.json", marshal(struct{ Record, Signature []byte }{metadataRaw, ed25519.Sign(f.key, append([]byte("system-backup-controller-source-metadata.v1\x00"), metadataRaw...))}))
	m.Discovery.GrantFile, m.Discovery.GrantSHA256 = d.MetadataGrant.File, d.MetadataGrant.SHA256
	materialsRaw := marshal(m)
	d.Materials = write("materials.json", materialsRaw)
	for n := range d.Connections {
		connection := &d.Connections[n]
		connection.IdentitySHA256, err = BootstrapSourceConnectionIdentitySHA256(core.InstallationID, *connection)
		if err != nil {
			t.Fatal(err)
		}
		connection.ScopeSHA256, err = BootstrapSourceNativeRoleScopeSHA256(core.InstallationID, d, *connection, scope)
		if err != nil {
			t.Fatal(err)
		}
	}
	definitionRaw, err := canonical(d)
	if err != nil {
		t.Fatal(err)
	}
	definition := write("definition.json", definitionRaw)
	signed, err := f.i.IssueBootstrapSourceRegistriesV2(ctx, f.password, f.enrollment, pack, hash(pack), definition.File, definition.SHA256, selection, f.files, f.key)
	if err != nil {
		t.Fatal("actual authenticated V2 issuer with selected materials", err)
	}
	if f.s.openTx.Load() != 0 || bytes.Contains(signed.Record, []byte("source-secret")) || bytes.Contains(signed.Record, []byte("control-secret")) {
		t.Fatal("actual issuer retained SQL locks or exported source credentials")
	}
	if err := SaveFrozenBootstrapSourceRegistriesV2(directory, signed); err != nil {
		t.Fatal(err)
	}
	files := BootstrapSourceRegistryFiles{RecordFile: filepath.Join(directory, "bootstrap-source-registries-v2.record.json"), RecordSHA256: hash(signed.Record), SignatureFile: filepath.Join(directory, "bootstrap-source-registries-v2.signature")}
	prepared, err := c.source.PrepareBootstrapSourceRegistriesV2(ctx, f.grant, f.config, selection, files)
	if err != nil || prepared == nil {
		t.Fatal("actual V2 consumer through original capture/files", err)
	}
	return c, prepared, d, materialsRaw
}

func TestBootstrapSourceRegistryV2ActualIssuerConsumerMaterialBounds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		padding int
	}{{"small_original_material", 0}, {"above_private_file_cap", 300000}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			c, prepared, d, want := newActualBootstrapSourceV2MaterialConsumer(t, ctx, tc.padding)
			if tc.padding > 262144 && len(want) <= 262144 {
				t.Fatal("fixture did not cross the unchanged private-file cap")
			}
			raw, err := prepared.ReadSelectedFile(ctx, d.Materials)
			if err != nil || !bytes.Equal(raw, want) {
				t.Fatal("actual selected material read", err)
			}
			clear(raw)
			if raw, err := ReadPrivateFile(d.Materials.File, 8<<20); err == nil || raw != nil {
				clear(raw)
				t.Fatal("private plan/key/DSN reader was widened")
			}
			if raw, err := readBootstrapSourcePin(d.Materials, (8<<20)+1); err == nil || raw != nil {
				clear(raw)
				t.Fatal("arbitrary larger bounds acquired the material-only selector")
			}
			apiReads := c.apiCalls.Load()
			if err := runBootstrapSourceIdentityGuard(t, ctx, c, func(q *pd.Transaction, _ *bootstrapSourceIdentityClock) error {
				if _, err := prepared.AuthorizeIdentity(ctx, q); err != nil {
					return err
				}
				return prepared.RecheckIdentity(ctx, q)
			}); err != nil {
				t.Fatal("actual original SQL identity and materials tail", err)
			}
			if c.apiCalls.Load() != apiReads {
				t.Fatal("SQL identity material tail reopened native API")
			}
		})
	}
}

func TestBootstrapSourceRegistryV2ActualLockedMaterialTailFailureLatches(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	c, prepared, d, original := newActualBootstrapSourceV2MaterialConsumer(t, ctx, 300000)
	apiReads := c.apiCalls.Load()
	tailReached := false
	err := runBootstrapSourceIdentityGuard(t, ctx, c, func(q *pd.Transaction, _ *bootstrapSourceIdentityClock) error {
		if _, err := prepared.AuthorizeIdentity(ctx, q); err != nil {
			t.Fatal("positive actual V2 source identity under original SQL guard", err)
		}
		if err := prepared.RecheckIdentity(ctx, q); err != nil {
			t.Fatal("positive actual large-material identity tail before fault", err)
		}
		if err := os.WriteFile(d.Materials.File, append(bytes.Clone(original), '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		tailReached = true
		failure := prepared.RecheckIdentity(ctx, q)
		if failure == nil || !prepared.base.failed.Load() {
			t.Fatal("changed final material escaped actual locked identity tail")
		}
		if err := os.WriteFile(d.Materials.File, original, 0600); err != nil {
			t.Fatal(err)
		}
		if prepared.RecheckIdentity(ctx, q) == nil {
			t.Fatal("restoring source bytes revived the same failed locked attempt")
		}
		return failure
	})
	if err == nil || !tailReached || c.apiCalls.Load() != apiReads {
		t.Fatal("fault did not reach the actual local material tail or reopened provider IO", err)
	}
}

func TestBootstrapSourceRegistryV2ActualMaterialDeliveryTailFailureLatches(t *testing.T) {
	for _, scenario := range []string{"material_replaced", "cancel_after_read"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			_, prepared, d, original := newActualBootstrapSourceV2MaterialConsumer(t, ctx, 300000)
			positive, err := prepared.ReadSelectedFile(ctx, d.Materials)
			if err != nil || !bytes.Equal(positive, original) {
				t.Fatal("positive actual V2 selected read before fault", err)
			}
			clear(positive)
			// The actual public method uses this SAME completion function after
			// its selected read. Fault only after real bytes were acquired.
			raw, err := readBootstrapSourcePin(d.Materials, 8<<20)
			if err != nil || !bytes.Equal(raw, original) {
				t.Fatal("actual pinned bytes before delivery tail", err)
			}
			until := prepared.base.record.Until
			if scenario == "material_replaced" {
				if err := os.WriteFile(d.Materials.File, append(bytes.Clone(original), '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			returned, err := prepared.base.finishSelectedRead(ctx, raw, nil)
			if err == nil || returned != nil || !prepared.base.failed.Load() || !bytes.Equal(raw, make([]byte, len(raw))) {
				clear(raw)
				t.Fatal("late material/context failure returned bytes or missed original failure latch")
			}
			if err := os.WriteFile(d.Materials.File, original, 0600); err != nil {
				t.Fatal(err)
			}
			if raw, err := prepared.ReadSelectedFile(ctx, d.Materials); err == nil || raw != nil || !prepared.base.record.Until.Equal(until) {
				clear(raw)
				t.Fatal("restoring original material revived the failed attempt/window")
			}
			if _, err := prepared.Association(); err == nil {
				t.Fatal("failed original material identity became available again")
			}
		})
	}
}
