package systembackupexecution

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"

	contract "clawreef/internal/systembackupcontract"
	ce "clawreef/internal/systembackupcontrolevidence"
	pc "clawreef/internal/systembackuppartcontainer"
	security "clawreef/internal/systembackupsecurity"
)

type PublicationReadbackInputs struct {
	Version   string                   `json:"schema_version"`
	Materials PublicationHTTPReadInput `json:"read_materials"`
	Catalog   PublicationHTTPReadInput `json:"catalog_record"`
	Report    PublicationHTTPReadInput `json:"private_content_report"`
}

type PublicationReadbackResult struct {
	Installation string `json:"origin_installation_id"`
	Backup       string `json:"backup_public_id"`
	Attempt      uint64 `json:"attempt_no"`
	CatalogSHA   string `json:"catalog_record_sha256"`
	ManifestSHA  string `json:"manifest_sha256"`
	Parts        int    `json:"fixed_version_parts_verified"`
	Bytes        int64  `json:"ciphertext_container_bytes_verified"`
}

type publicationReadbackPart struct {
	object  ArtifactReadObject
	members map[string]pc.MemberLocation
}

func publicationReadbackParts(report publicationContentSampleReport, manifest publicationManifestV12) (map[string]publicationReadbackPart, error) {
	parts := make(map[string]publicationReadbackPart, len(publicationRequestedParts))
	seen := make(map[string]bool, len(report.Members))
	for _, member := range report.Members {
		summary, ok := manifest.Parts[member.RequestedPart]
		location := member.Member
		object := member.Container
		if !ok || !manifestOneOf(member.RequestedPart, publicationRequestedParts...) || member.Part == "" || seen[member.Part] ||
			location.Part != member.Part || location.ObjectVersion != object.Version || !formalCandidateDigest(location.CheckpointSHA256) ||
			!fixedPublicationReadVersion(object.Version) || object.Size < 1 || object.SHA256 != summary.CipherSHA256 {
			return nil, errPublicationUnavailable
		}
		seen[member.Part] = true
		part := parts[member.RequestedPart]
		if part.members == nil {
			part = publicationReadbackPart{object: object, members: map[string]pc.MemberLocation{}}
		} else if part.object != object {
			return nil, errPublicationUnavailable
		}
		part.members[member.Part] = location
		parts[member.RequestedPart] = part
	}
	for _, name := range publicationRequestedParts {
		part := parts[name]
		if len(part.members) == 0 {
			return nil, errPublicationUnavailable
		}
		set := make([]struct{ Part, SHA256 string }, 0, len(part.members))
		for memberName, location := range part.members {
			set = append(set, struct{ Part, SHA256 string }{memberName, location.CheckpointSHA256})
		}
		sort.Slice(set, func(i, j int) bool { return set[i].Part < set[j].Part })
		raw, err := ce.Canonical(set)
		if err != nil || hash(raw) != manifest.Parts[name].CheckpointSHA256 {
			return nil, errPublicationUnavailable
		}
	}
	return parts, nil
}

// VerifyPublicationReadback is an independent ciphertext read. The signed
// catalog anchors the manifest, which in turn anchors all six container hashes
// and checkpoint sets. The private report supplies the original fixed versions.
// This does not unwrap, restore, or confer any recovery/acceptance authority.
func VerifyPublicationReadback(ctx context.Context, in PublicationReadbackInputs, origin, backup string, maxBytes int64) (PublicationReadbackResult, error) {
	var zero PublicationReadbackResult
	if ctx == nil || ctx.Err() != nil || in.Version != "system-backup-publication-readback-inputs.v1" || maxBytes <= 0 {
		return zero, errPublicationUnavailable
	}
	until, ok := ctx.Deadline()
	if !ok {
		return zero, errPublicationUnavailable
	}
	materials, err := loadPublicationHTTPRead(in.Materials)
	if err != nil || origin != materials.Artifacts.InstallationID {
		return zero, errPublicationUnavailable
	}
	raw, err := pinnedDeploymentFile(in.Report.File, in.Report.SHA256, 16<<20)
	var report BusinessContentReport
	if err != nil || decodeProviderDeploymentJSON(raw, &report) != nil ||
		report.Version != "system-backup-business-content-report.v1" || report.Scope != "private_same_ready_not_acceptance_or_restore" {
		return zero, errPublicationUnavailable
	}
	sample := report.AuthenticatedRead
	if sample.Version != "system-backup-final-content-observations.v1" || sample.Installation != origin || sample.Backup != backup ||
		sample.Attempt == 0 || sample.Attempt > 9007199254740991 || sample.ArtifactReadIdentitySHA256 != materials.Artifacts.ReadIdentityHash {
		return zero, errPublicationUnavailable
	}
	raw, err = pinnedDeploymentFile(in.Catalog.File, in.Catalog.SHA256, 32768)
	var resource contract.CatalogRecordResource
	if err != nil || decodeProviderDeploymentJSON(raw, &resource) != nil || resource.RecordSHA256 != hash(resource.Record) {
		return zero, errPublicationUnavailable
	}
	var envelope struct {
		Payload   json.RawMessage `json:"payload"`
		Signature json.RawMessage `json:"signature"`
	}
	if decodePublicationCanonical(resource.Record, &envelope) != nil {
		return zero, errPublicationUnavailable
	}
	catalog, err := decodePublicationCatalogPayload(envelope.Payload)
	base := materials.Artifacts.Root + backup + "/" + strconv.FormatUint(sample.Attempt, 10) + "/"
	m := sample.Manifest
	if err != nil || catalog.Installation != origin || catalog.Backup != backup || catalog.Attempt != sample.Attempt ||
		catalog.ID != resource.ID || resource.ID != publicationCatalogRecordID(origin, backup, sample.Attempt) ||
		catalog.Manifest.Identity != materials.Artifacts.ReadIdentityHash || catalog.Manifest.Key != m.Key ||
		catalog.Manifest.Version != m.Version || catalog.ManifestSHA256 != m.SHA256 || m.Key != base+"manifest.json" || m.Size < 1 || m.Size > 262144 {
		return zero, errPublicationUnavailable
	}
	task := security.ArtifactSigningTask{BackupPublicID: backup, AttemptNo: int64(sample.Attempt)}
	history, err := security.LoadInstallationSigningHistory(ctx, materials.History, materials.HistoryPin)
	if err != nil {
		return zero, errPublicationUnavailable
	}
	if _, err = verifyPublicationCatalogRecord(resource.Record, envelope.Payload, history, task); err != nil {
		return zero, errPublicationUnavailable
	}
	reader, err := NewArtifactReadOnlyS3(materials.Artifacts, materials.Limits)
	if err != nil {
		return zero, err
	}
	defer reader.Close()
	credential, err := reader.store.credential(false)
	if err != nil {
		return zero, errPublicationUnavailable
	}
	if credential.Until.Before(until) {
		until = credential.Until
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	manifestBytes, observed, err := reader.readVersionedBytes(ctx, m.Key, m.Version, m.SHA256, m.Size, until)
	if err != nil || observed != m {
		return zero, errPublicationUnavailable
	}
	manifest, err := decodePublicationManifestV12(manifestBytes)
	if err != nil || manifest.Installation != origin || manifest.Backup != backup || manifest.Attempt != sample.Attempt ||
		manifest.CaptureCertificate != catalog.CaptureSHA256 || manifest.Index.Checksum != catalog.IndexSHA256 {
		return zero, errPublicationUnavailable
	}
	parts, err := publicationReadbackParts(sample, manifest)
	if err != nil {
		return zero, err
	}
	if materials.Limits.MaxArtifactBytes < maxBytes {
		maxBytes = materials.Limits.MaxArtifactBytes
	}
	var total int64
	for _, name := range publicationRequestedParts {
		part := parts[name]
		if part.object.Size > maxBytes-total || part.object.Key != base+"parts/"+name+"/container.enc" {
			return zero, errPublicationUnavailable
		}
		total += part.object.Size
	}
	for _, name := range publicationRequestedParts {
		part := parts[name]
		checkpoints := make(map[string]string, len(part.members))
		for name, loc := range part.members {
			checkpoints[name] = loc.CheckpointSHA256
		}
		scope := pc.Scope{Installation: origin, Backup: backup, Attempt: sample.Attempt, ConfigVersion: manifest.Config.Version,
			ConfigSHA256: manifest.Config.SHA256, CaptureContextSHA256: manifest.CaptureContext, Part: name}
		facts, err := reader.InspectPartContainer(ctx, part.object, scope, checkpoints, until)
		if err != nil || len(facts.Locations) != len(part.members) {
			return zero, errPublicationUnavailable
		}
		for _, location := range facts.Locations {
			if location != part.members[location.Part] {
				return zero, errPublicationUnavailable
			}
		}
	}
	if _, err = loadPublicationHTTPRead(in.Materials); err != nil || ctx.Err() != nil {
		return zero, errPublicationUnavailable
	}
	history, err = security.LoadInstallationSigningHistory(ctx, materials.History, materials.HistoryPin)
	if err != nil {
		return zero, errPublicationUnavailable
	}
	if _, err = verifyPublicationCatalogRecord(resource.Record, envelope.Payload, history, task); err != nil {
		return zero, errPublicationUnavailable
	}
	return PublicationReadbackResult{Installation: origin, Backup: backup, Attempt: sample.Attempt,
		CatalogSHA: resource.RecordSHA256, ManifestSHA: m.SHA256, Parts: len(parts), Bytes: total}, nil
}
