package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	security "clawreef/internal/systembackupsecurity"
)

type artifactCatalogManifestLocator struct {
	Provider string `json:"provider"`
	Identity string `json:"identity_hash"`
	Key      string `json:"key"`
	Version  string `json:"version"`
}
type artifactRegistrationPayload struct {
	Version          string                         `json:"schema_version"`
	Installation     string                         `json:"origin_installation_id"`
	Backup           string                         `json:"backup_public_id"`
	Attempt          uint64                         `json:"attempt_no"`
	ID               string                         `json:"record_id"`
	At               string                         `json:"recorded_at"`
	Key              security.PublicationSigningKey `json:"signing_key"`
	Event            string                         `json:"event_type"`
	Manifest         artifactCatalogManifestLocator `json:"manifest"`
	ManifestSHA256   string                         `json:"manifest_checksum"`
	MarkerSHA256     string                         `json:"marker_checksum"`
	AcceptanceSHA256 string                         `json:"acceptance_checksum"`
	CaptureSHA256    string                         `json:"capture_certificate_hash"`
	IndexSHA256      string                         `json:"artifact_index_checksum"`
}

// Authenticated catalog->manifest->index CONTENT only. This is deliberately
// not a complete business/cleanup/acceptance proof. The final reader still
// validates all manifest semantics, three records and every full C payload.
// Original SQL/controller/capture keys are not constructor dependencies.
type ArtifactCatalogContent struct {
	installation, backup, base  string
	attempt                     uint64
	material                    ArtifactReadMaterials
	manifest, index             []byte
	entries                     map[string]publicationArtifactEntry
	manifestObject, indexObject ArtifactReadObject
}

func (c *ArtifactCatalogContent) ManifestBytes() []byte {
	if c == nil {
		return nil
	}
	return bytes.Clone(c.manifest)
}
func (c *ArtifactCatalogContent) IndexBytes() []byte {
	if c == nil {
		return nil
	}
	return bytes.Clone(c.index)
}

func (r *ArtifactReadOnlyS3) readVersionedBytes(ctx context.Context, key, version, sha string, maxBytes int64, until time.Time) ([]byte, ArtifactReadObject, error) {
	var zero ArtifactReadObject
	if r == nil || r.store == nil || version == "" || version == "null" || version == "latest" || maxBytes < 1 || maxBytes > 8<<30 || !formalCandidateDigest(sha) {
		return nil, zero, errPublicationUnavailable
	}
	object, err := r.store.stat(ctx, key, version, until)
	if err != nil || object.Size > maxBytes {
		return nil, zero, errPublicationUnavailable
	}
	var body bytes.Buffer
	intent := publicationPayloadIntent{Key: key, Size: object.Size, SHA256: sha}
	object, err = readPublicationPayloadTo(ctx, r.store, intent, version, until, &body)
	if err != nil {
		return nil, zero, err
	}
	if _, err = r.store.credential(false); err != nil {
		return nil, zero, err
	}
	return body.Bytes(), ArtifactReadObject{Key: object.Key, Version: object.Version, SHA256: object.SHA256, Size: object.Size}, nil
}

func (r *ArtifactReadOnlyS3) ReadCatalogIndex(ctx context.Context, catalog []byte, history *security.ArtifactSigningKeyHistory, maxIndexBytes int64, maxEntries int, budget ArtifactVersionSearchBudget, until time.Time) (*ArtifactCatalogContent, error) {
	if r == nil || r.store == nil || history == nil || maxIndexBytes < 1 || maxIndexBytes > 8<<30 || maxEntries < 1 || maxEntries > 1000000 {
		return nil, errPublicationUnavailable
	}
	var envelope struct {
		Payload   json.RawMessage `json:"payload"`
		Signature json.RawMessage `json:"signature"`
	}
	var registration artifactRegistrationPayload
	if len(catalog) > 16384 || decodeProviderDeploymentJSON(catalog, &envelope) != nil || decodeProviderDeploymentJSON(envelope.Payload, &registration) != nil || registration.Version != "system-backup-catalog-record.v1" || registration.Event != "artifact_registered" || registration.Installation != r.store.config.InstallationID || registration.Attempt < 1 || registration.Attempt > 9007199254740991 || registration.Manifest.Provider != "s3" || registration.Manifest.Identity != r.store.config.ReadIdentityHash || registration.ID == "" || len(registration.ID) > 256 || !strings.HasSuffix(registration.Manifest.Key, "/manifest.json") {
		return nil, errPublicationUnavailable
	}
	for _, digest := range []string{registration.ManifestSHA256, registration.MarkerSHA256, registration.AcceptanceSHA256, registration.CaptureSHA256, registration.IndexSHA256} {
		if !formalCandidateDigest(digest) {
			return nil, errPublicationUnavailable
		}
	}
	if _, err := history.VerifyPublicationRecord(catalog, security.ArtifactSigningTask{BackupPublicID: registration.Backup, AttemptNo: int64(registration.Attempt)}, "catalog_record"); err != nil {
		return nil, err
	}
	manifest, manifestObject, err := r.readVersionedBytes(ctx, registration.Manifest.Key, registration.Manifest.Version, registration.ManifestSHA256, 262144, until)
	if err != nil {
		return nil, err
	}
	canonical, err := ce.Canonical(json.RawMessage(manifest))
	if err != nil || !bytes.Equal(canonical, manifest) {
		return nil, errPublicationUnavailable
	}
	// These fields locate authenticated content; this partial view does not
	// claim validation of the remaining public manifest/business semantics.
	var binding struct {
		Version      string `json:"schema_version"`
		Installation string `json:"origin_installation_id"`
		Backup       string `json:"backup_public_id"`
		Attempt      uint64 `json:"attempt_no"`
		Context      string `json:"capture_context_hash"`
		Capture      string `json:"capture_certificate_hash"`
		Index        struct {
			Path     string `json:"path"`
			Checksum string `json:"checksum"`
		} `json:"artifact_index"`
	}
	if json.Unmarshal(manifest, &binding) != nil || binding.Version != "system-backup.v1" || binding.Installation != registration.Installation || binding.Backup != registration.Backup || binding.Attempt != registration.Attempt || !formalCandidateDigest(binding.Context) || binding.Capture != registration.CaptureSHA256 || binding.Index.Path != "artifact-index.json" || binding.Index.Checksum != registration.IndexSHA256 {
		return nil, errPublicationUnavailable
	}
	base := strings.TrimSuffix(registration.Manifest.Key, "manifest.json")
	indexObject, err := r.ResolveHashedObject(ctx, base+binding.Index.Path, binding.Index.Checksum, maxIndexBytes, budget, until)
	if err != nil {
		return nil, err
	}
	index, indexObject, err := r.readVersionedBytes(ctx, indexObject.Key, indexObject.Version, indexObject.SHA256, maxIndexBytes, until)
	if err != nil {
		return nil, err
	}
	var parsed publicationArtifactIndex
	canonical, err = ce.Canonical(json.RawMessage(index))
	if err != nil || !bytes.Equal(canonical, index) || decodeProviderDeploymentJSON(index, &parsed) != nil || parsed.Version != "system-backup-artifact-index.v1" || parsed.Backup != registration.Backup || parsed.Attempt != registration.Attempt || parsed.CaptureContext != binding.Context || len(parsed.Entries) < 1 || len(parsed.Entries) > maxEntries {
		return nil, errPublicationUnavailable
	}
	entries := map[string]publicationArtifactEntry{}
	last := ""
	for _, entry := range parsed.Entries {
		if !safePublicationKey(entry.Path) || entry.Path <= last || entry.Path == "artifact-index.json" || entry.Path == "manifest.json" || entry.Path == "_COMMITTED" || entry.Path == "_ACCEPTANCE" || entry.Size < 1 || entry.Size > 8<<30 || !formalCandidateDigest(entry.SHA256) || len(entry.Framing) < 1 || len(entry.Framing) > 64 || entry.Role != "encrypted_payload" && entry.Role != "envelope" && entry.Role != "control_evidence" {
			return nil, errPublicationUnavailable
		}
		entries[entry.Path] = entry
		last = entry.Path
	}
	return &ArtifactCatalogContent{installation: registration.Installation, backup: registration.Backup, attempt: registration.Attempt, base: base, material: artifactReadMaterials(r.store.config), manifest: manifest, index: index, entries: entries, manifestObject: manifestObject, indexObject: indexObject}, nil
}

func (c *ArtifactCatalogContent) ResolveEntry(ctx context.Context, reader *ArtifactReadOnlyS3, path string, budget ArtifactVersionSearchBudget, until time.Time) (ArtifactReadObject, error) {
	if c == nil || reader == nil || reader.store == nil || artifactReadMaterials(reader.store.config) != c.material {
		return ArtifactReadObject{}, errPublicationUnavailable
	}
	entry, ok := c.entries[path]
	if !ok {
		return ArtifactReadObject{}, errPublicationUnavailable
	}
	return reader.ResolveIndexedObject(ctx, c.base+entry.Path, entry.SHA256, entry.Size, budget, until)
}
