package systembackupexecution

import (
	"bytes"
	"encoding/json"

	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
	pc "clawreef/internal/systembackuppartcontainer"
	w "clawreef/internal/systembackupwire"
)

const publicationCaptureCertificatePath = "control/capture-certificate.json"

// Upload-only transport validation. The original producer must independently
// verify the signature/current history and complete C before constructing this
// request; the final independent consumer repeats verification after upload.
func validatePublicationContainerManifestInput(request PublicationUploadRequest, manifest []byte) error {
	containers := false
	objects := map[string]PublicationUploadInput{}
	for _, object := range request.Objects {
		objects[object.Path] = object
		if isPublicationContainerObject(object.Path) {
			containers = true
		}
	}
	if !containers {
		if len(request.CaptureCertificate) > 0 || len(request.CaptureBootstrap) > 0 {
			return errPublicationConflict
		}
		return nil
	}
	if request.Version != publicationPresignedUploadVersion || len(request.IndexBytes) == 0 || len(request.CaptureCertificate) == 0 || len(request.CaptureBootstrap) == 0 || !bytes.Equal(request.ManifestInput, manifest) {
		return errPublicationConflict
	}
	m, err := decodePublicationManifestV12(manifest)
	if err != nil || m.Installation != request.Installation || m.Backup != request.Backup || m.Attempt != request.Attempt || m.CaptureCertificate != hash(request.CaptureCertificate) || m.Index.Checksum != hash(request.IndexBytes) || len(m.Parts) != 6 {
		return errPublicationConflict
	}
	for _, part := range publicationRequestedParts {
		summary, ok := m.Parts[part]
		object, exists := objects["parts/"+part+"/container.enc"]
		if !ok || !exists || summary.CipherSHA256 != object.SHA256 {
			return errPublicationConflict
		}
	}
	if len(objects) != 15 || validatePublicationContainerIndexInput(request, m, objects) != nil {
		return errPublicationConflict
	}
	control, ok := objects[ce.CipherPath]
	if !ok || control.SHA256 != m.Control.Checksum {
		return errPublicationConflict
	}
	certificate, ok := objects[publicationCaptureCertificatePath]
	if !ok || certificate.SHA256 != m.CaptureCertificate || certificate.Bytes != int64(len(request.CaptureCertificate)) {
		return errPublicationConflict
	}
	envelope, closed := decodeOriginalCaptureCertificateEnvelope(request.CaptureCertificate)
	var payload publicationCaptureCertificatePayload
	if !closed || decodeProviderDeploymentJSON(envelope.Payload, &payload) != nil || payload.Version != "system-backup-capture-certificate.v1" || payload.Installation != m.Installation || payload.Backup != m.Backup || payload.Attempt != m.Attempt || payload.Context != m.CaptureContext {
		return errPublicationConflict
	}
	canonical, err := ce.Canonical(payload)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		return errPublicationConflict
	}
	pins := map[string]string{}
	for _, cp := range payload.Checkpoints {
		if _, exists := pins[cp.Part]; exists {
			return errPublicationConflict
		}
		pins[cp.Part] = cp.SHA256
	}
	var untrusted cd.Bootstrap
	if json.Unmarshal(request.CaptureBootstrap, &untrusted) != nil {
		return errPublicationConflict
	}
	bootstrap, err := cd.DecodeBootstrap(request.CaptureBootstrap, cd.Scope{InstallationID: m.Installation, TaskPublicID: m.Backup, ConfigVersion: m.Config.Version, ConfigSHA256: m.Config.SHA256, AttemptNo: m.Attempt, CaptureContextSHA256: m.CaptureContext}, untrusted.SourceInventorySHA256, pins)
	if err != nil {
		return errPublicationConflict
	}
	for _, member := range bootstrap.Members {
		key := member.Stream.Request.Key
		cipher, cipherOK := objects[member.CipherPath]
		env, envOK := objects[member.EnvelopePath]
		if key.Provider != m.KEK.Provider || key.ProviderKeyID != m.KEK.KeyID || key.ProviderVersion != m.KEK.KeyVersion || !cipherOK || !envOK || cipher.SHA256 != member.CipherSHA256 || cipher.Bytes != member.CipherBytes || env.SHA256 != member.EnvelopeSHA256 || env.Bytes != member.EnvelopeBytes {
			return errPublicationConflict
		}
	}
	return nil
}

func validatePublicationContainerIndexInput(request PublicationUploadRequest, m publicationManifestV12, objects map[string]PublicationUploadInput) error {
	var index publicationArtifactIndex
	if decodeProviderDeploymentJSON(request.IndexBytes, &index) != nil {
		return errPublicationConflict
	}
	canonical, err := ce.Canonical(index)
	if err != nil || !bytes.Equal(canonical, request.IndexBytes) || index.Version != "system-backup-artifact-index.v1" || index.Backup != m.Backup || index.Attempt != m.Attempt || index.CaptureContext != m.CaptureContext || len(index.Entries) != 13 {
		return errPublicationConflict
	}
	last := ""
	for _, entry := range index.Entries {
		object, ok := objects[entry.Path]
		if !ok || entry.Path <= last || entry.SHA256 != object.SHA256 || entry.Size != object.Bytes {
			return errPublicationConflict
		}
		last = entry.Path
		if isPublicationContainerObject(entry.Path) {
			if entry.Role != "encrypted_payload" || entry.Framing != pc.Version {
				return errPublicationConflict
			}
			continue
		}
		switch entry.Path {
		case ce.CipherPath, ce.ProofCipherPath, cd.CipherPath:
			if entry.Role != "control_evidence" || entry.Framing != w.FramingVersion {
				return errPublicationConflict
			}
		case ce.EnvelopePath, "control/evidence-proofs.envelope.json", cd.EnvelopePath:
			if entry.Role != "envelope" || entry.Framing != w.EnvelopeVersion {
				return errPublicationConflict
			}
		case cd.BootstrapPath:
			if entry.Role != "control_evidence" || entry.Framing != cd.BootstrapVersion || entry.SHA256 != hash(request.CaptureBootstrap) || entry.Size != int64(len(request.CaptureBootstrap)) {
				return errPublicationConflict
			}
		default:
			return errPublicationConflict
		}
	}
	return nil
}
