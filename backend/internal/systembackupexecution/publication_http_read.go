package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	contract "clawreef/internal/systembackupcontract"
	read "clawreef/internal/systembackupread"
	security "clawreef/internal/systembackupsecurity"
)

const PublicationHTTPReadVersion = "system-backup-publication-http-read.v1"

// Independently installed READ-only inputs. There is no source/capture grant,
// private signing key, provider callback, JWT, append/delete credential or DB.
type PublicationHTTPReadInput struct{ File, SHA256 string }
type PublicationHTTPReadMaterials struct {
	Version        string                           `json:"schema_version"`
	Artifacts      ArtifactReadMaterials            `json:"artifacts"`
	Catalog        ArtifactReadMaterials            `json:"catalog"`
	History        security.FileSigningRecordReader `json:"signing_history_files"`
	HistoryPin     security.InstallationSigningPin  `json:"signing_history_pin"`
	Limits         ArtifactReadLimits               `json:"limits"`
	MaxReadSeconds int64                            `json:"max_read_seconds"`
}

type PublicationHTTPReader struct {
	input     PublicationHTTPReadInput
	materials PublicationHTTPReadMaterials
}

func loadPublicationHTTPRead(input PublicationHTTPReadInput) (PublicationHTTPReadMaterials, error) {
	var p PublicationHTTPReadMaterials
	raw, e := pinnedDeploymentFile(input.File, input.SHA256, 262144)
	if e != nil || decodeProviderDeploymentJSON(raw, &p) != nil || p.Version != PublicationHTTPReadVersion || p.MaxReadSeconds < 1 || p.MaxReadSeconds > 30 || p.Artifacts.validate() != nil || p.Catalog.validate() != nil || p.Limits.validate() != nil || p.Limits.MaxIndexBytes > 16<<20 || p.Artifacts.InstallationID != p.Catalog.InstallationID || p.HistoryPin.InstallationID != p.Artifacts.InstallationID || p.Artifacts.ReadIdentityHash == p.Catalog.ReadIdentityHash || p.Artifacts.ReadCredentialFile == p.Catalog.ReadCredentialFile || p.Artifacts.Root == p.Catalog.Root {
		return PublicationHTTPReadMaterials{}, read.ErrUnavailable
	}
	return p, nil
}

func NewPublicationHTTPReader(ctx context.Context, input PublicationHTTPReadInput) (*PublicationHTTPReader, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, read.ErrUnavailable
	}
	p, e := loadPublicationHTTPRead(input)
	if e != nil {
		return nil, e
	}
	if _, e = security.LoadInstallationSigningHistory(ctx, p.History, p.HistoryPin); e != nil {
		return nil, read.ErrUnavailable
	}
	for _, material := range []ArtifactReadMaterials{p.Artifacts, p.Catalog} {
		r, e := NewArtifactReadOnlyS3(material, p.Limits)
		if e != nil {
			return nil, read.ErrUnavailable
		}
		r.Close()
	}
	return &PublicationHTTPReader{input: input, materials: p}, nil
}

type publicationHTTPPlan struct {
	ConfigSHA256                                          string
	Manifest, Index, Marker, Acceptance, Catalog          ArtifactReadObject
	RegistrationID, RegistrationSHA256, CertificateSHA256 string
	CatalogBytes                                          []byte
	Attempt                                               uint64
}

func publicationHTTPObject(material ArtifactReadMaterials, uri, version, sha string) (ArtifactReadObject, error) {
	u, e := url.Parse(uri)
	base, be := url.Parse(material.Endpoint)
	if e != nil || be != nil || u.Scheme != base.Scheme || u.Host != base.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery || !fixedPublicationReadVersion(version) || !formalCandidateDigest(sha) {
		return ArtifactReadObject{}, read.ErrUnavailable
	}
	prefix := "/" + material.Bucket + "/"
	if !strings.HasPrefix(u.Path, prefix) {
		return ArtifactReadObject{}, read.ErrUnavailable
	}
	key := strings.TrimPrefix(u.Path, prefix)
	base.Path = prefix + key
	if !safePublicationKey(key) || !strings.HasPrefix(key, material.Root) || base.String() != uri {
		return ArtifactReadObject{}, read.ErrUnavailable
	}
	return ArtifactReadObject{Key: key, Version: version, SHA256: sha}, nil
}

// All SQL uses the request-bound callback capability. It cannot re-open a
// privileged connection or adopt the old publisher's cleared task permission.
func (r *PublicationHTTPReader) plan(ctx context.Context, q read.CurrentFactsSQL, h read.TaskHeader) (publicationHTTPPlan, error) {
	var p publicationHTTPPlan
	if r == nil || ctx == nil || ctx.Err() != nil || q == nil || h.InstallationID != r.materials.Artifacts.InstallationID || h.Kind != read.BackupTask || h.Status != "succeeded" {
		return p, read.ErrUnavailable
	}
	var config, readID, readRef, caID, caRef string
	var configRaw []byte
	var manifestURI, manifestVersion, manifestSHA, indexURI, indexVersion, indexSHA, markerURI, markerVersion, markerSHA, acceptanceURI, acceptanceVersion, acceptanceSHA string
	var actionSHA, actionKey string
	e := q.QueryRow(`SELECT b.config_snapshot_json,b.config_snapshot_sha256,b.artifact_read_identity_hash,b.artifact_read_ref_version,b.artifact_ca_identity_hash,b.artifact_ca_ref_version,
b.manifest_uri,b.manifest_immutable_version,b.manifest_checksum,b.index_uri,b.index_immutable_version,b.index_checksum,
b.marker_uri,b.marker_immutable_version,b.marker_checksum,b.acceptance_uri,b.acceptance_immutable_version,b.acceptance_checksum,
b.artifact_registration_id,b.artifact_registration_hash,b.capture_certificate_sha256,
x.final_key,x.observed_version,x.observed_checksum,x.content_length,x.canonical_payload_bytes,x.payload_sha256,x.action_key,
(SELECT MAX(a.attempt_no) FROM system_backup_v2_attempts a WHERE a.target_type='backup' AND a.target_public_id=b.public_id AND a.phase='capture' AND a.status='sealed')
FROM system_backup_v2_backups b JOIN system_backup_v2_external_actions x ON x.origin_installation_id=b.origin_installation_id AND x.target_type='backup' AND x.target_public_id=b.public_id AND x.action_type='catalog_registration_append'
WHERE b.origin_installation_id=? AND b.public_id=? AND b.row_version=? AND b.config_version=? AND b.status='succeeded' AND b.artifact_state='committed' AND b.artifact_committed_at IS NOT NULL
AND x.state='confirmed_present' AND x.observed_version IS NOT NULL AND x.observed_checksum=x.payload_sha256 AND x.payload_sha256=b.artifact_registration_hash
AND OCTET_LENGTH(b.config_snapshot_json) BETWEEN 2 AND 262144 AND x.content_length BETWEEN 1 AND 16384 AND OCTET_LENGTH(x.canonical_payload_bytes)=x.content_length
AND (SELECT COUNT(*) FROM system_backup_v2_external_actions y WHERE y.origin_installation_id=b.origin_installation_id AND y.target_type='backup' AND y.target_public_id=b.public_id AND y.action_type='catalog_registration_append')=1 FOR SHARE`, h.InstallationID, h.PublicID, h.RowVersion, h.ConfigVersion).Scan(
		&configRaw, &config, &readID, &readRef, &caID, &caRef, &manifestURI, &manifestVersion, &manifestSHA, &indexURI, &indexVersion, &indexSHA, &markerURI, &markerVersion, &markerSHA, &acceptanceURI, &acceptanceVersion, &acceptanceSHA,
		&p.RegistrationID, &p.RegistrationSHA256, &p.CertificateSHA256, &p.Catalog.Key, &p.Catalog.Version, &p.Catalog.SHA256, &p.Catalog.Size, &p.CatalogBytes, &actionSHA, &actionKey, &p.Attempt)
	if e != nil || len(configRaw) < 2 || len(configRaw) > 262144 || hash(configRaw) != config || readID != r.materials.Artifacts.ReadIdentityHash || readRef != r.materials.Artifacts.ReadRefVersion || caID != r.materials.Artifacts.CAIdentityHash || caRef != r.materials.Artifacts.CARefVersion || p.Attempt == 0 || p.RegistrationID != publicationCatalogRecordID(h.InstallationID, h.PublicID, p.Attempt) || p.Catalog.Key != r.materials.Catalog.Root+"registrations/"+p.RegistrationID+".json" || p.Catalog.Size < 1 || p.Catalog.Size > 16384 || int64(len(p.CatalogBytes)) != p.Catalog.Size || hash(p.CatalogBytes) != p.RegistrationSHA256 || actionSHA != p.RegistrationSHA256 || p.Catalog.SHA256 != p.RegistrationSHA256 || actionKey != publicationActionKey(h.PublicID, p.Attempt, "catalog_registration_append") || !fixedPublicationReadVersion(p.Catalog.Version) || !formalCandidateDigest(p.CertificateSHA256) {
		return publicationHTTPPlan{}, read.ErrUnavailable
	}
	refs, e := publicationSnapshotReferences(configRaw, config)
	if e != nil {
		return publicationHTTPPlan{}, read.ErrUnavailable
	}
	p.ConfigSHA256 = config
	for _, wanted := range []publicationConfigReference{{"artifact_read", r.materials.Artifacts.ReadIdentityHash, r.materials.Artifacts.ReadRefVersion}, {"artifact_ca", r.materials.Artifacts.CAIdentityHash, r.materials.Artifacts.CARefVersion}, {"catalog_read", r.materials.Catalog.ReadIdentityHash, r.materials.Catalog.ReadRefVersion}} {
		if refs[wanted.Purpose] != wanted {
			return publicationHTTPPlan{}, read.ErrUnavailable
		}
	}
	objects := []*ArtifactReadObject{&p.Manifest, &p.Index, &p.Marker, &p.Acceptance}
	for i, item := range []struct{ uri, version, sha string }{{manifestURI, manifestVersion, manifestSHA}, {indexURI, indexVersion, indexSHA}, {markerURI, markerVersion, markerSHA}, {acceptanceURI, acceptanceVersion, acceptanceSHA}} {
		*objects[i], e = publicationHTTPObject(r.materials.Artifacts, item.uri, item.version, item.sha)
		if e != nil {
			return publicationHTTPPlan{}, e
		}
	}
	base := r.materials.Artifacts.Root + h.PublicID + "/" + strconv.FormatUint(p.Attempt, 10) + "/"
	if p.Manifest.Key != base+"manifest.json" || p.Index.Key != base+"artifact-index.json" || p.Marker.Key != base+"_COMMITTED" || p.Acceptance.Key != base+"_ACCEPTANCE" {
		return publicationHTTPPlan{}, read.ErrUnavailable
	}
	return p, nil
}

type publicationHTTPBundle struct {
	Catalog  contract.CatalogRecordResource
	Manifest []byte
	Until    time.Time
}

func (r *PublicationHTTPReader) bundle(ctx context.Context, q read.CurrentFactsSQL, h read.TaskHeader) (publicationHTTPBundle, error) {
	var zero publicationHTTPBundle
	current, e := loadPublicationHTTPRead(r.input)
	if e != nil {
		return zero, e
	}
	want, _ := json.Marshal(r.materials)
	got, _ := json.Marshal(current)
	if !bytes.Equal(want, got) {
		return zero, read.ErrUnavailable
	}
	p, e := r.plan(ctx, q, h)
	if e != nil {
		return zero, e
	}
	var now time.Time
	if q.QueryRow(`SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil || now.IsZero() {
		return zero, read.ErrUnavailable
	}
	until := now.Add(time.Duration(r.materials.MaxReadSeconds) * time.Second)
	if bound, ok := ctx.Deadline(); ok && bound.Before(until) {
		until = bound
	}
	artifact, e := NewArtifactReadOnlyS3(r.materials.Artifacts, r.materials.Limits)
	if e != nil {
		return zero, read.ErrUnavailable
	}
	defer artifact.Close()
	catalog, e := NewArtifactReadOnlyS3(r.materials.Catalog, r.materials.Limits)
	if e != nil {
		return zero, read.ErrUnavailable
	}
	defer catalog.Close()
	for _, reader := range []*ArtifactReadOnlyS3{artifact, catalog} {
		credential, e := reader.store.credential(false)
		if e != nil {
			return zero, read.ErrUnavailable
		}
		if credential.Until.Before(until) {
			until = credential.Until
		}
	}
	if !now.Before(until) {
		return zero, read.ErrUnavailable
	}
	bounded, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	history, e := security.LoadInstallationSigningHistory(bounded, r.materials.History, r.materials.HistoryPin)
	if e != nil {
		return zero, read.ErrUnavailable
	}
	raw, observed, e := catalog.readVersionedBytes(bounded, p.Catalog.Key, p.Catalog.Version, p.Catalog.SHA256, p.Catalog.Size, until)
	if e != nil || observed != p.Catalog || !bytes.Equal(raw, p.CatalogBytes) {
		return zero, read.ErrUnavailable
	}
	task := security.ArtifactSigningTask{BackupPublicID: h.PublicID, AttemptNo: int64(p.Attempt)}
	if _, e = history.VerifyPublicationRecord(raw, task, "catalog_record"); e != nil {
		return zero, read.ErrUnavailable
	}
	var envelope struct {
		Payload   json.RawMessage `json:"payload"`
		Signature json.RawMessage `json:"signature"`
	}
	if decodePublicationCanonical(raw, &envelope) != nil {
		return zero, read.ErrUnavailable
	}
	payload, e := decodePublicationCatalogPayload(envelope.Payload)
	if e != nil || payload.ID != p.RegistrationID || payload.Installation != h.InstallationID || payload.Backup != h.PublicID || payload.Attempt != p.Attempt || payload.Manifest.Provider != "s3" || payload.Manifest.Identity != r.materials.Artifacts.ReadIdentityHash || payload.Manifest.Key != p.Manifest.Key || payload.Manifest.Version != p.Manifest.Version || payload.ManifestSHA256 != p.Manifest.SHA256 || payload.IndexSHA256 != p.Index.SHA256 || payload.MarkerSHA256 != p.Marker.SHA256 || payload.AcceptanceSHA256 != p.Acceptance.SHA256 || payload.CaptureSHA256 != p.CertificateSHA256 {
		return zero, read.ErrUnavailable
	}
	readObject := func(object ArtifactReadObject, max int64) ([]byte, ArtifactReadObject, error) {
		if max > r.materials.Limits.MaxIndexBytes {
			max = r.materials.Limits.MaxIndexBytes
		}
		return artifact.readVersionedBytes(bounded, object.Key, object.Version, object.SHA256, max, until)
	}
	manifest, manifestObject, e := readObject(p.Manifest, 262144)
	if e != nil {
		return zero, read.ErrUnavailable
	}
	m, e := decodePublicationManifestV12(manifest)
	if e != nil || m.Installation != h.InstallationID || m.Backup != h.PublicID || m.Attempt != p.Attempt || m.Config.Version != h.ConfigVersion || m.Config.SHA256 != p.ConfigSHA256 || m.Index.Checksum != p.Index.SHA256 || m.CaptureCertificate != p.CertificateSHA256 {
		return zero, read.ErrUnavailable
	}
	index, _, e := readObject(p.Index, r.materials.Limits.MaxIndexBytes)
	if e != nil {
		return zero, read.ErrUnavailable
	}
	var parsed publicationArtifactIndex
	if decodePublicationCanonical(index, &parsed) != nil || parsed.Version != "system-backup-artifact-index.v1" || parsed.Backup != h.PublicID || parsed.Attempt != p.Attempt || parsed.CaptureContext != m.CaptureContext || len(parsed.Entries) < 1 || len(parsed.Entries) > 1000000 {
		return zero, read.ErrUnavailable
	}
	last := ""
	remaining := r.materials.Limits.MaxArtifactBytes - int64(len(index))
	for _, entry := range parsed.Entries {
		if !safePublicationKey(entry.Path) || entry.Path <= last || entry.Path == "artifact-index.json" || entry.Path == "manifest.json" || entry.Path == "_COMMITTED" || entry.Path == "_ACCEPTANCE" || entry.Size < 1 || entry.Size > remaining || !formalCandidateDigest(entry.SHA256) || !manifestBound(entry.Framing, 64) || !manifestOneOf(entry.Role, "encrypted_payload", "envelope", "control_evidence") {
			return zero, read.ErrUnavailable
		}
		last = entry.Path
		remaining -= entry.Size
	}
	marker, _, e := readObject(p.Marker, 8192)
	if e != nil {
		return zero, read.ErrUnavailable
	}
	expected, e := originalCommittedMarkerData(manifest, manifestObject, h.InstallationID, h.PublicID, p.Attempt, r.materials.Artifacts.Root)
	if e != nil || !bytes.Equal(marker, expected) {
		return zero, read.ErrUnavailable
	}
	acceptance, _, e := readObject(p.Acceptance, 16384)
	if e != nil {
		return zero, read.ErrUnavailable
	}
	if _, e = history.VerifyPublicationRecord(acceptance, task, "acceptance_record"); e != nil {
		return zero, read.ErrUnavailable
	}
	var accepted struct {
		Payload   json.RawMessage `json:"payload"`
		Signature json.RawMessage `json:"signature"`
	}
	if decodePublicationCanonical(acceptance, &accepted) != nil {
		return zero, read.ErrUnavailable
	}
	a, e := decodePublicationAcceptancePayload(accepted.Payload)
	if e != nil || a.Backup != h.PublicID || a.Attempt != p.Attempt || a.ConfigVersion != h.ConfigVersion || a.ManifestSHA256 != p.Manifest.SHA256 || a.MarkerSHA256 != p.Marker.SHA256 {
		return zero, read.ErrUnavailable
	}
	// Re-read owner history and local READ pins after the last HTTP I/O. This
	// grants no provider operation and never consults the old publishing claim.
	history, e = security.LoadInstallationSigningHistory(bounded, r.materials.History, r.materials.HistoryPin)
	if e != nil {
		return zero, read.ErrUnavailable
	}
	if _, e = history.VerifyPublicationRecord(raw, task, "catalog_record"); e != nil {
		return zero, read.ErrUnavailable
	}
	if _, e = history.VerifyPublicationRecord(acceptance, task, "acceptance_record"); e != nil {
		return zero, read.ErrUnavailable
	}
	for _, reader := range []*ArtifactReadOnlyS3{artifact, catalog} {
		if _, e = reader.store.credential(false); e != nil {
			return zero, read.ErrUnavailable
		}
	}
	current, e = loadPublicationHTTPRead(r.input)
	got, marshalErr := json.Marshal(current)
	if e != nil || marshalErr != nil || !bytes.Equal(want, got) || bounded.Err() != nil {
		return zero, read.ErrUnavailable
	}
	return publicationHTTPBundle{Catalog: contract.CatalogRecordResource{ID: p.RegistrationID, RecordSHA256: p.RegistrationSHA256, Record: append(json.RawMessage(nil), raw...)}, Manifest: bytes.Clone(manifest), Until: until}, nil
}

func (r *PublicationHTTPReader) Catalog(ctx context.Context, q read.CurrentFactsSQL, candidate read.CatalogRecordControl) (contract.CatalogRecordResource, time.Time, error) {
	if r == nil {
		return contract.CatalogRecordResource{}, time.Time{}, read.ErrUnavailable
	}
	b, e := r.bundle(ctx, q, candidate.Task)
	if e != nil || b.Catalog.ID != candidate.RegistrationID || b.Catalog.RecordSHA256 != candidate.RegistrationSHA256 {
		return contract.CatalogRecordResource{}, time.Time{}, read.ErrUnavailable
	}
	return b.Catalog, b.Until, nil
}

func (r *PublicationHTTPReader) Backup(ctx context.Context, q read.CurrentFactsSQL, s read.TaskCheckEvidenceControlSnapshot) (read.BackupCurrentFacts, error) {
	var zero read.BackupCurrentFacts
	if r == nil || ctx == nil || ctx.Err() != nil || q == nil {
		return zero, read.ErrUnavailable
	}
	detail := s.Checks().Detail()
	h := detail.Execution().Task()
	b, ok := detail.Backup()
	if !ok || h.InstallationID != r.materials.Artifacts.InstallationID {
		return zero, read.ErrUnavailable
	}
	var observed time.Time
	if q.QueryRow(`SELECT UTC_TIMESTAMP(6)`).Scan(&observed) != nil || observed.IsZero() {
		return zero, read.ErrUnavailable
	}
	f := read.BackupCurrentFacts{CurrentFactsIdentity: read.CurrentFactsIdentity{SchemaVersion: read.CurrentFactsVersion, InstallationID: h.InstallationID, TaskPublicID: h.PublicID, RowVersion: h.RowVersion, ObservedAt: observed, ValidUntil: observed.Add(time.Duration(r.materials.MaxReadSeconds) * time.Second)}, Checksums: b.Checksums, RegistrationID: b.RegistrationID.String, RegistrationSHA: b.RegistrationSHA.String, UnusableReason: b.UnusableReason}
	if b.ArtifactState != "committed" {
		return f, nil
	}
	bundle, e := r.bundle(ctx, q, h)
	if e != nil {
		return zero, read.ErrUnavailable
	}
	f.ValidUntil = bundle.Until
	// A fixed signed metadata read is not a fresh KEK recovery proof. Current
	// KEK/owner/attestation adapters are not yet mounted in this READ-only input;
	// do not copy SQL artifact_usable or acceptance_eligible into fresh approval.
	f.ArtifactUsable, f.AcceptanceReady, f.UnusableReason = false, false, "verification_inconclusive"
	return f, nil
}

func (*PublicationHTTPReader) Preflight(context.Context, read.CurrentFactsSQL, read.TaskCheckEvidenceControlSnapshot) (read.PreflightCurrentFacts, error) {
	return read.PreflightCurrentFacts{}, read.ErrUnavailable
}

func (r *PublicationHTTPReader) Read(ctx context.Context, q read.CurrentFactsSQL, s read.TaskCheckEvidenceControlSnapshot) ([]byte, error) {
	if r == nil {
		return nil, read.ErrUnavailable
	}
	b, e := r.bundle(ctx, q, s.Checks().Detail().Execution().Task())
	if e != nil {
		return nil, e
	}
	return b.Manifest, nil
}

var _ read.CatalogRecordReader = (*PublicationHTTPReader)(nil)
var _ read.CurrentTaskFacts = (*PublicationHTTPReader)(nil)
var _ read.ManifestReader = (*PublicationHTTPReader)(nil)
