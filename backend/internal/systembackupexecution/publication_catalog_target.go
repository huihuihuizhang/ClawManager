package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"

	security "clawreef/internal/systembackupsecurity"
)

const publicationCatalogMaterialsVersion = "system-backup-native-catalog-s3.v1"

var ErrPublicationCatalogUnavailable = errors.New("independent original catalog read/append mapping unavailable")

// Separate, independently pinned purpose mapping. It is not an artifact write
// credential alias, task authority, signing key, or independent acceptance.
// The admitted artifact-target file pins this file BEFORE any task capture.
type PublicationCatalogMaterials struct {
	Version                string `json:"schema_version"`
	InstallationID         string `json:"installation_id"`
	Endpoint               string `json:"endpoint"`
	Region                 string `json:"region"`
	Bucket                 string `json:"bucket"`
	Root                   string `json:"root"`
	ReadIdentityHash       string `json:"catalog_read_identity_hash"`
	ReadRefVersion         string `json:"catalog_read_ref_version"`
	AppendIdentityHash     string `json:"catalog_append_identity_hash"`
	AppendRefVersion       string `json:"catalog_append_ref_version"`
	CAIdentityHash         string `json:"ca_identity_hash"`
	CARefVersion           string `json:"ca_ref_version"`
	CAFile                 string `json:"ca_file"`
	CASHA256               string `json:"ca_sha256"`
	ReadCredentialFile     string `json:"read_credential_file"`
	ReadCredentialSHA256   string `json:"read_credential_sha256"`
	AppendCredentialFile   string `json:"append_credential_file"`
	AppendCredentialSHA256 string `json:"append_credential_sha256"`
}

func (m PublicationCatalogMaterials) transport() PublicationTargetMaterials {
	return PublicationTargetMaterials{Version: publicationTargetVersion, InstallationID: m.InstallationID, Endpoint: m.Endpoint, Region: m.Region, Bucket: m.Bucket, Root: m.Root, ReadIdentityHash: m.ReadIdentityHash, ReadRefVersion: m.ReadRefVersion, WriteIdentityHash: m.AppendIdentityHash, WriteRefVersion: m.AppendRefVersion, CAIdentityHash: m.CAIdentityHash, CARefVersion: m.CARefVersion, CAFile: m.CAFile, CASHA256: m.CASHA256, ReadCredentialFile: m.ReadCredentialFile, ReadCredentialSHA256: m.ReadCredentialSHA256, WriteCredentialFile: m.AppendCredentialFile, WriteCredentialSHA256: m.AppendCredentialSHA256}
}

func (m PublicationCatalogMaterials) validate(parent PublicationTargetMaterials) error {
	if m.Version != publicationCatalogMaterialsVersion || m.InstallationID != parent.InstallationID || m.transport().validate() != nil || !strings.HasPrefix(m.Root, m.InstallationID+"/") || m.Root == parent.Root || m.CAIdentityHash != parent.CAIdentityHash || m.CARefVersion != parent.CARefVersion {
		return ErrPublicationCatalogUnavailable
	}
	for _, identity := range []string{m.ReadIdentityHash, m.AppendIdentityHash} {
		if identity == parent.ReadIdentityHash || identity == parent.WriteIdentityHash {
			return ErrPublicationCatalogUnavailable
		}
	}
	for _, path := range []string{m.ReadCredentialFile, m.AppendCredentialFile} {
		if path == parent.ReadCredentialFile || path == parent.WriteCredentialFile {
			return ErrPublicationCatalogUnavailable
		}
	}
	return nil
}

func loadPinnedPublicationCatalog(parent PublicationTargetMaterials) (PublicationCatalogMaterials, error) {
	var m PublicationCatalogMaterials
	if parent.validate() != nil || parent.CatalogMaterialsFile == "" {
		return m, ErrPublicationCatalogUnavailable
	}
	raw, err := pinnedDeploymentFile(parent.CatalogMaterialsFile, parent.CatalogMaterialsSHA256, 65536)
	if err != nil || decodeProviderDeploymentJSON(raw, &m) != nil || m.validate(parent) != nil {
		return PublicationCatalogMaterials{}, ErrPublicationCatalogUnavailable
	}
	return m, nil
}

// This constructor performs bounded local file/TLS checks only. There is no
// provider/Kube request or nested SQL, including when called by a receipt tail.
func (s *DeploymentService) currentPublicationCatalog(ctx context.Context) (PublicationCatalogMaterials, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.publicationTargetInput == nil || s.publicationTarget == nil || s.publicationBinding() != nil {
		return PublicationCatalogMaterials{}, ErrPublicationCatalogUnavailable
	}
	parent, err := loadPublicationTarget(s.Config, []PublicationTargetInput{*s.publicationTargetInput})
	if err != nil || !reflect.DeepEqual(parent, s.publicationTarget) {
		return PublicationCatalogMaterials{}, ErrPublicationCatalogUnavailable
	}
	return loadPinnedPublicationCatalog(*parent)
}

func (s *DeploymentService) catalogStore(ctx context.Context) (*nativePublicationS3, error) {
	m, err := s.currentPublicationCatalog(ctx)
	if err != nil {
		return nil, err
	}
	store, err := newNativePublicationS3(m.transport())
	if err != nil {
		return nil, err
	}
	store.catalog = &m
	return store, nil
}

func (s *DeploymentService) publicationStoreForAction(ctx context.Context, kind string) (*nativePublicationS3, error) {
	if kind == "catalog_registration_append" {
		return s.catalogStore(ctx)
	}
	return s.publicationStore(ctx)
}

func (s *DeploymentService) checkPublicationActionTargetTx(ctx context.Context, tx *sql.Tx, facts security.PublisherCaptureFacts, target PublicationTargetMaterials, kind string) error {
	if kind != "catalog_registration_append" {
		return s.checkPublicationTargetTx(ctx, tx, facts, target)
	}
	m, err := s.currentPublicationCatalog(ctx)
	if err != nil || m.InstallationID != facts.InstallationID || m.transport() != target {
		return ErrPublicationCatalogUnavailable
	}
	return checkOriginalPublicationReferencesTx(ctx, tx, facts, publicationConfigReference{"catalog_read", m.ReadIdentityHash, m.ReadRefVersion}, publicationConfigReference{"catalog_append", m.AppendIdentityHash, m.AppendRefVersion}, publicationConfigReference{"artifact_ca", m.CAIdentityHash, m.CARefVersion})
}
