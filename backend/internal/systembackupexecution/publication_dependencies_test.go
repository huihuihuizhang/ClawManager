package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

func TestPublicationDependencyOriginalWindowsNeverExtend(t *testing.T) {
	now := time.Now().UTC()
	w := publicationDependencyWindow{}
	if w.include(now, now.Add(-time.Minute), now.Add(time.Hour)) != nil || w.include(now, now.Add(-time.Second), now.Add(time.Minute)) != nil || w.notBefore != now.Add(-time.Second) || w.until != now.Add(time.Minute) {
		t.Fatal("lost original intersection")
	}
	if w.include(now, now.Add(-time.Hour), now.Add(2*time.Hour)) != nil || w.until != now.Add(time.Minute) {
		t.Fatal("later source extended original permission")
	}
	for _, span := range [][2]time.Time{{{}, now.Add(time.Hour)}, {now.Add(time.Second), now.Add(time.Hour)}, {now.Add(-time.Minute), now}, {now, now}} {
		if (&publicationDependencyWindow{}).include(now, span[0], span[1]) == nil {
			t.Fatal("missing, future or expired authority admitted")
		}
	}
}

func TestPublicationDependenciesCannotUseAbsentComposition(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []struct {
		service *DeploymentService
		ctx     context.Context
	}{
		{nil, context.Background()}, {&DeploymentService{}, nil}, {&DeploymentService{}, ctx}, {&DeploymentService{}, context.Background()},
	} {
		observed, err := input.service.CheckPublicationDependencies(input.ctx)
		var dependency *PublicationDependencyError
		if err == nil || !errors.As(err, &dependency) || dependency.Dependency == "" || !observed.CheckedAt().IsZero() || !observed.ValidUntil().IsZero() {
			t.Fatal("absent concrete source became an observation")
		}
	}
}

// This tests only the exact signed-file inspector, not full deployment SQL,
// workload identity, provider permission, task signing or D capability.
func TestPublicationDependencyOriginalSigningSources(t *testing.T) {
	for _, mode := range []string{"current", "expired-record", "future-record", "revoked-key", "expired-key", "future-key", "wrong-issuer", "bad-signature", "changed-bytes", "wrong-owner-account", "wrong-config", "duplicate-purpose", "missing-jwt", "replaced-ca", "key-shorter-than-record"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			grant := c.ExecutionGrant{InstallationID: "installation_original_dependencies", ServerUUID: "owned-server", Database: "owned_database", DatabaseAccount: "publisher@localhost", ConfigVersion: 3, ConfigSHA256: strings.Repeat("a", 64)}
			runtime := PublicationSignerRuntime{InstallationID: grant.InstallationID, ServerUUID: grant.ServerUUID, Database: grant.Database, PublisherOwner: "public:original-pod", Namespace: "original-namespace", NamespaceUID: "original-ns-uid", PodName: "original-controller", PodUID: "original-pod", ServiceAccountName: "original-controller-sa", ServiceAccountUID: "original-sa-uid"}
			dir := t.TempDir()
			write := func(name string, raw []byte) string {
				t.Helper()
				file := filepath.Join(dir, name)
				if err := os.WriteFile(file, raw, 0600); err != nil {
					t.Fatal(err)
				}
				return file
			}
			issuer, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(private)
			record := security.InstallationSigningRecord{InstallationID: grant.InstallationID, Revision: 9, NotBefore: now.Add(-time.Minute), Until: now.Add(time.Hour)}
			materials := PublicationSignerMaterials{Version: PublicationSignerMaterialsVersion}
			for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
				public, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				clear(key)
				ca := []byte("explicit pinned file fixture CA " + purpose)
				mount := PublicationSigningMount{Binding: security.TransitSigningBinding{InstallationID: grant.InstallationID, Purpose: purpose, KeyID: "original-" + purpose, KeyVersion: "opaque-r7", ProviderVersion: "7", Endpoint: "https://original-provider.invalid", KeyName: purpose}, AuthMount: "original-auth", Role: purpose + "-role", Policy: purpose + "-policy", JWTFile: write(purpose+".jwt", []byte("explicit-original-projected-jwt-fixture")), CAFile: write(purpose+".pem", ca), CASHA256: hash(ca)}
				materials.Mounts = append(materials.Mounts, mount)
				record.Keys = append(record.Keys, security.ArtifactSigningPublicKey{InstallationID: grant.InstallationID, Purpose: purpose, KeyID: mount.Binding.KeyID, KeyVersion: mount.Binding.KeyVersion, PublicKey: public, NotBefore: now.Add(-time.Minute), NotAfter: record.Until})
				record.Permissions = append(record.Permissions, security.InstallationSigningPermission{Binding: mount.Binding, AuthMount: mount.AuthMount, Role: mount.Role, Policy: mount.Policy, CASHA256: mount.CASHA256, SQLOwner: &security.SQLSigningOwnerGrant{ServerUUID: grant.ServerUUID, Database: grant.Database, DatabaseAccount: grant.DatabaseAccount, ControllerOwner: runtime.PublisherOwner, ConfigVersion: grant.ConfigVersion, ConfigSHA256: grant.ConfigSHA256, Workload: security.SigningWorkloadIdentity{Namespace: runtime.Namespace, PodUID: runtime.PodUID, ServiceAccountUID: runtime.ServiceAccountUID}}})
			}
			switch mode {
			case "expired-record":
				record.Until = now
			case "future-record":
				record.NotBefore = now.Add(time.Second)
			case "revoked-key":
				record.Keys[1].Revoked = true
			case "expired-key":
				record.Keys[1].NotAfter = now
			case "future-key":
				record.Keys[1].NotBefore = now.Add(time.Second)
			case "wrong-owner-account":
				record.Permissions[1].SQLOwner.DatabaseAccount = "other@localhost"
			case "wrong-config":
				record.Permissions[1].SQLOwner.ConfigVersion++
			case "duplicate-purpose":
				record.Permissions[1] = record.Permissions[0]
			case "key-shorter-than-record":
				record.Keys[1].NotAfter = now.Add(time.Minute)
			}
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			sig := ed25519.Sign(private, append([]byte(security.InstallationSigningDomain), raw...))
			if mode == "bad-signature" {
				sig[0] ^= 1
			}
			materials.Record = security.FileSigningRecordReader{RecordFile: write("owner.json", raw), SignatureFile: write("owner.sig", sig)}
			materials.Pin = security.InstallationSigningPin{InstallationID: grant.InstallationID, Revision: record.Revision, RecordSHA256: hash(raw), Issuer: issuer}
			switch mode {
			case "wrong-issuer":
				materials.Pin.Issuer, _, err = ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
			case "changed-bytes":
				write("owner.json", append(raw, ' '))
			case "missing-jwt":
				if err = os.Remove(materials.Mounts[1].JWTFile); err != nil {
					t.Fatal(err)
				}
			case "replaced-ca":
				write("acceptance_record.pem", []byte("different CA"))
			}
			observed, err := publicationDependencySigningFacts(context.Background(), materials, runtime, grant, now)
			if mode != "current" && mode != "key-shorter-than-record" {
				if err == nil || !observed.until.IsZero() {
					t.Fatal("invalid original signing source admitted", mode)
				}
				return
			}
			until := record.Until
			if mode == "key-shorter-than-record" {
				until = now.Add(time.Minute)
			}
			if err != nil || observed.until != until || observed.recordSHA != materials.Pin.RecordSHA256 {
				t.Fatal("original signed permission/key expiry lost", err)
			}
		})
	}
}
