package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Separate local TLS endpoints and actual distinct read/append credentials.
// Purpose/config SQL authority and record signatures are separate native tests.
func newPublicationCatalogTransportFixture(t *testing.T) (PublicationTargetMaterials, PublicationCatalogMaterials, *aNativePublicationServer, *aNativePublicationServer) {
	t.Helper()
	artifact, artifactState := newANativePublicationStore(t, time.Minute)
	catalog, catalogState := newANativePublicationStore(t, time.Minute)
	catalog.config.Root += "catalog/"
	catalog.config.ReadIdentityHash = hash([]byte("catalog read identity DATA"))
	catalog.config.WriteIdentityHash = hash([]byte("catalog append identity DATA"))
	catalog.config.ReadRefVersion = "catalog-read-v1"
	catalog.config.WriteRefVersion = "catalog-append-v1"
	catalogState.read.AccessKey = "catalog-read-local"
	catalogState.read.SecretKey = strings.Repeat("c", 32)
	catalogState.write.AccessKey = "catalog-append-local"
	catalogState.write.SecretKey = strings.Repeat("a", 32)
	read, _ := json.Marshal(catalogState.read)
	appendCredential, _ := json.Marshal(catalogState.write)
	if os.WriteFile(catalog.config.ReadCredentialFile, read, 0600) != nil || os.WriteFile(catalog.config.WriteCredentialFile, appendCredential, 0600) != nil {
		t.Fatal("catalog credential setup")
	}
	catalog.config.ReadCredentialSHA256 = hash(read)
	catalog.config.WriteCredentialSHA256 = hash(appendCredential)
	m := PublicationCatalogMaterials{Version: publicationCatalogMaterialsVersion, InstallationID: catalog.config.InstallationID, Endpoint: catalog.config.Endpoint, Region: catalog.config.Region, Bucket: catalog.config.Bucket, Root: catalog.config.Root, ReadIdentityHash: catalog.config.ReadIdentityHash, ReadRefVersion: catalog.config.ReadRefVersion, AppendIdentityHash: catalog.config.WriteIdentityHash, AppendRefVersion: catalog.config.WriteRefVersion, CAIdentityHash: catalog.config.CAIdentityHash, CARefVersion: catalog.config.CARefVersion, CAFile: catalog.config.CAFile, CASHA256: catalog.config.CASHA256, ReadCredentialFile: catalog.config.ReadCredentialFile, ReadCredentialSHA256: catalog.config.ReadCredentialSHA256, AppendCredentialFile: catalog.config.WriteCredentialFile, AppendCredentialSHA256: catalog.config.WriteCredentialSHA256}
	parent := artifact.config
	parent.CatalogMaterialsFile = filepath.Join(filepath.Dir(parent.CAFile), "catalog-materials.json")
	raw, _ := json.Marshal(m)
	parent.CatalogMaterialsSHA256 = hash(raw)
	if err := os.WriteFile(parent.CatalogMaterialsFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return parent, m, artifactState, catalogState
}

func TestCatalogMappingUsesDistinctNativeReadAppendTransport(t *testing.T) {
	parent, expected, artifactState, catalogState := newPublicationCatalogTransportFixture(t)
	m, err := loadPinnedPublicationCatalog(parent)
	if err != nil || m != expected {
		t.Fatal("independently pinned catalog mapping", err)
	}
	store, err := newNativePublicationS3(m.transport())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	body := []byte(`{"local":"catalog transport protocol DATA"}`)
	key := m.Root + "registration/original.json"
	until := time.Now().Add(10 * time.Second)
	object, err := store.createJSON(context.Background(), key, bytes.NewReader(body), int64(len(body)), hash(body), until)
	if err != nil {
		t.Fatal(err)
	}
	action := publicationJournalAction{Kind: "catalog_registration_append", Key: key, Payload: body, PayloadSHA: hash(body), Size: int64(len(body)), ObjectVersion: sql.NullString{String: object.Version, Valid: true}}
	observed, raw, err := readPublicationJSON(context.Background(), store, action, until)
	if err != nil || !bytes.Equal(raw, body) || observed.Version != object.Version || catalogState.puts != 1 || catalogState.gets != 1 || artifactState.puts != 0 || artifactState.gets != 0 {
		t.Fatal("catalog reused artifact transport or skipped readback", err, catalogState.puts, catalogState.gets, artifactState.puts)
	}
}

func TestCatalogMappingRejectsArtifactAliasesAndPinChanges(t *testing.T) {
	for _, mode := range []string{"wrong-protocol", "foreign-installation", "artifact-root", "artifact-read-identity", "artifact-append-identity", "cross-read-identity", "cross-append-identity", "artifact-read-file", "artifact-append-file", "cross-read-file", "cross-append-file", "shared-read-append", "changed-ca-ref", "missing-parent-pin", "changed-file"} {
		t.Run(mode, func(t *testing.T) {
			parent, m, _, _ := newPublicationCatalogTransportFixture(t)
			switch mode {
			case "wrong-protocol":
				m.Version = publicationTargetVersion
			case "foreign-installation":
				m.InstallationID = "installation_other"
			case "artifact-root":
				m.Root = parent.Root
			case "artifact-read-identity":
				m.ReadIdentityHash = parent.ReadIdentityHash
			case "artifact-append-identity":
				m.AppendIdentityHash = parent.WriteIdentityHash
			case "cross-read-identity":
				m.ReadIdentityHash = parent.WriteIdentityHash
			case "cross-append-identity":
				m.AppendIdentityHash = parent.ReadIdentityHash
			case "artifact-read-file":
				m.ReadCredentialFile = parent.ReadCredentialFile
			case "artifact-append-file":
				m.AppendCredentialFile = parent.WriteCredentialFile
			case "cross-read-file":
				m.ReadCredentialFile = parent.WriteCredentialFile
			case "cross-append-file":
				m.AppendCredentialFile = parent.ReadCredentialFile
			case "shared-read-append":
				m.AppendIdentityHash = m.ReadIdentityHash
			case "changed-ca-ref":
				m.CARefVersion = "foreign-ca-v1"
			case "missing-parent-pin":
				parent.CatalogMaterialsSHA256 = ""
			case "changed-file":
				m.Root += "substitute/"
			}
			raw, _ := json.Marshal(m)
			if err := os.WriteFile(parent.CatalogMaterialsFile, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if mode != "missing-parent-pin" && mode != "changed-file" {
				parent.CatalogMaterialsSHA256 = hash(raw)
			}
			if _, err := loadPinnedPublicationCatalog(parent); !errors.Is(err, ErrPublicationCatalogUnavailable) {
				t.Fatal("invalid catalog mapping accepted", mode, err)
			}
		})
	}
}
