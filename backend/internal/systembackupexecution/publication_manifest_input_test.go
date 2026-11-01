package systembackupexecution

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
	pc "clawreef/internal/systembackuppartcontainer"
	w "clawreef/internal/systembackupwire"
)

// Public transport DATA. Signature text below is a placeholder, deliberately
// NOT a verifier/acceptance proof or an authenticated production certificate.
func publicationContainerRequestData(t *testing.T) (PublicationUploadRequest, publicationManifestV12, publicationArtifactIndex) {
	t.Helper()
	m := publicationManifestDataV12(t)
	m.Backup = "sbk_11111111-1111-4111-8111-111111111111"
	sum := strings.Repeat("a", 64)
	payload := publicationCaptureCertificatePayload{Version: "system-backup-capture-certificate.v1", Installation: m.Installation, Backup: m.Backup, Attempt: m.Attempt, Context: m.CaptureContext, Jobs: []publicationCertificateJob{}, Checkpoints: []publicationCertificateCheckpoint{}, Stages: []publicationCertificateStage{}, IssuedAt: m.Generated, CompletedAt: m.Generated, ExpiresAt: m.Generated}
	bootstrap := publicationBootstrapManifestData(t, m, &payload)
	var envelope originalCaptureCertificateEnvelope
	envelope.Payload, _ = ce.Canonical(payload)
	envelope.Signature.Algorithm = "EdDSA"
	envelope.Signature.Purpose = "capture_certificate"
	envelope.Signature.KeyID = "named-DATA"
	envelope.Signature.KeyVersion = "1"
	envelope.Signature.Domain = "named-DATA"
	envelope.Signature.Header = "named-DATA"
	envelope.Signature.Value = "placeholder-public-signature-DATA"
	certificate, err := ce.Canonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	p := PublicationUploadRequest{Version: publicationPresignedUploadVersion, Installation: m.Installation, Backup: m.Backup, Attempt: m.Attempt, Endpoint: "https://localhost:443", Region: "local-1", Bucket: "named-data", ArtifactRoot: "installation_DATA/artifacts/", RemoteStagingRoot: "installation_DATA/staging/", CAHash: sum, Deadline: m.Generated.AddDate(1, 0, 0), CaptureCertificate: certificate, CaptureBootstrap: bootstrap}
	index := publicationArtifactIndex{Version: "system-backup-artifact-index.v1", Backup: m.Backup, Attempt: m.Attempt, CaptureContext: m.CaptureContext, Entries: []publicationArtifactEntry{}}
	for _, part := range publicationRequestedParts {
		path := "parts/" + part + "/container.enc"
		p.Objects = append(p.Objects, PublicationUploadInput{Path: path, SHA256: sum, Bytes: 100})
		index.Entries = append(index.Entries, publicationArtifactEntry{Path: path, Role: "encrypted_payload", SHA256: sum, Size: 100, Framing: pc.Version})
	}
	for _, path := range []string{ce.CipherPath, ce.ProofCipherPath, ce.EnvelopePath, "control/evidence-proofs.envelope.json", cd.CipherPath, cd.EnvelopePath} {
		role, framing := "control_evidence", w.FramingVersion
		if strings.HasSuffix(path, ".envelope.json") {
			role, framing = "envelope", w.EnvelopeVersion
		}
		p.Objects = append(p.Objects, PublicationUploadInput{Path: path, SHA256: sum, Bytes: 100})
		index.Entries = append(index.Entries, publicationArtifactEntry{Path: path, Role: role, SHA256: sum, Size: 100, Framing: framing})
	}
	p.Objects = append(p.Objects, PublicationUploadInput{Path: cd.BootstrapPath, SHA256: hash(bootstrap), Bytes: int64(len(bootstrap))})
	index.Entries = append(index.Entries, publicationArtifactEntry{Path: cd.BootstrapPath, Role: "control_evidence", SHA256: hash(bootstrap), Size: int64(len(bootstrap)), Framing: cd.BootstrapVersion})
	p.Objects = append(p.Objects, PublicationUploadInput{Path: "artifact-index.json"}, PublicationUploadInput{Path: publicationCaptureCertificatePath})
	finishPublicationRequestData(t, &p, &m, &index)
	return p, m, index
}

func publicationBootstrapManifestData(t *testing.T, m publicationManifestV12, payload *publicationCaptureCertificatePayload) []byte {
	t.Helper()
	sum := strings.Repeat("a", 64)
	for _, part := range publicationRequestedParts {
		payload.Checkpoints = append(payload.Checkpoints, publicationCertificateCheckpoint{Part: part, SHA256: sum})
	}
	bootstrap := cd.Bootstrap{Version: cd.BootstrapVersion, Scope: cd.Scope{InstallationID: m.Installation, TaskPublicID: m.Backup, ConfigVersion: m.Config.Version, ConfigSHA256: m.Config.SHA256, AttemptNo: m.Attempt, CaptureContextSHA256: m.CaptureContext}, SourceInventorySHA256: sum, Members: []cd.AdministrativeMember{}}
	descriptionLimit, _ := cd.Budget(6)
	names := []struct {
		part, op, cipher, envelope, path string
		limit                            int64
	}{{cd.Part, cd.Operation, cd.CipherPath, cd.EnvelopePath, cd.LogicalCipherName, descriptionLimit}, {ce.Part, ce.Operation, ce.CipherPath, ce.EnvelopePath, ce.LogicalCipherName, ce.MaxBytes}, {ce.ProofPart, ce.Operation, ce.ProofCipherPath, "control/evidence-proofs.envelope.json", ce.LogicalProofCipherName, ce.MaxProofBytes}}
	for i, item := range names {
		index := uint32(i + 6)
		cp := b.Checkpoint{SchemaVersion: "system-backup-b-checkpoint.v1", InstallationID: m.Installation, ConfigVersion: m.Config.Version, TaskPublicID: m.Backup, AttemptNo: m.Attempt, Phase: "capture", ConfigSHA256: m.Config.SHA256, InventorySHA256: sum, Part: item.part, JobUID: "DATA-" + item.part, JobGeneration: 1, InvocationSHA256: sum, SealedRef: "DATA-original-seal", ContentSHA256: sum}
		raw, _ := json.Marshal(cp)
		canonical, _ := ce.Canonical(cp)
		payload.Checkpoints = append(payload.Checkpoints, publicationCertificateCheckpoint{Part: item.part, SHA256: hash(canonical)})
		bootstrap.Members = append(bootstrap.Members, cd.AdministrativeMember{Selection: cd.Selection{Part: item.part, Operation: item.op, PartIndex: index}, CipherPath: item.cipher, EnvelopePath: item.envelope, CipherBytes: 100, CipherSHA256: sum, EnvelopeBytes: 100, EnvelopeSHA256: sum, CheckpointJSON: raw, Stream: w.StreamSpec{Path: item.path, MaxPlaintextBytes: item.limit, MaxFrames: 128, Request: w.KeyRequest{Key: w.KeyBinding{Provider: m.KEK.Provider, IdentityHash: sum, RegistryVersion: "r1", ProviderKeyID: m.KEK.KeyID, ProviderVersion: m.KEK.KeyVersion}, Context: w.KeyContext{InstallationID: m.Installation, BackupPublicID: m.Backup, AttemptNo: strconv.FormatUint(m.Attempt, 10), Phase: "capture", Part: item.part, PartIndex: strconv.FormatUint(uint64(index), 10), EnvelopeID: "DATA-" + item.part, CaptureContextHash: m.CaptureContext}}}})
	}
	pins := map[string]string{}
	for _, cp := range payload.Checkpoints {
		pins[cp.Part] = cp.SHA256
	}
	raw, err := cd.EncodeBootstrap(bootstrap, pins)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func finishPublicationRequestData(t *testing.T, p *PublicationUploadRequest, m *publicationManifestV12, index *publicationArtifactIndex) {
	t.Helper()
	sort.Slice(index.Entries, func(i, j int) bool { return index.Entries[i].Path < index.Entries[j].Path })
	var err error
	p.IndexBytes, err = ce.Canonical(index)
	if err != nil {
		t.Fatal(err)
	}
	m.Index.Checksum, m.CaptureCertificate = hash(p.IndexBytes), hash(p.CaptureCertificate)
	for i := range p.Objects {
		switch p.Objects[i].Path {
		case "artifact-index.json":
			p.Objects[i].SHA256, p.Objects[i].Bytes = hash(p.IndexBytes), int64(len(p.IndexBytes))
		case publicationCaptureCertificatePath:
			p.Objects[i].SHA256, p.Objects[i].Bytes = hash(p.CaptureCertificate), int64(len(p.CaptureCertificate))
		}
	}
	p.ManifestInput, err = ce.Canonical(*m)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPublicationContainerTransportBindsCompleteManifestIndexAndPublicCertificateData(t *testing.T) {
	for _, mode := range []string{"current", "part-physical-hash", "certificate-context", "certificate-hidden-field", "certificate-alias", "index-role", "index-certificate-entry", "index-physical-size", "extra-object", "missing-certificate", "minimal-mf"} {
		t.Run(mode, func(t *testing.T) {
			p, m, index := publicationContainerRequestData(t)
			switch mode {
			case "part-physical-hash":
				part := m.Parts["workspace"]
				part.CipherSHA256 = strings.Repeat("b", 64)
				m.Parts["workspace"] = part
			case "certificate-context", "certificate-hidden-field", "certificate-alias":
				var envelope map[string]json.RawMessage
				json.Unmarshal(p.CaptureCertificate, &envelope)
				if mode == "certificate-alias" {
					envelope["Signature"] = envelope["signature"]
					delete(envelope, "signature")
				} else {
					var payload map[string]any
					json.Unmarshal(envelope["payload"], &payload)
					if mode == "certificate-context" {
						payload["capture_context_hash"] = strings.Repeat("b", 64)
					} else {
						payload["unapproved"] = true
					}
					envelope["payload"], _ = ce.Canonical(payload)
				}
				p.CaptureCertificate, _ = ce.Canonical(envelope)
			case "index-role":
				index.Entries[0].Role = "encrypted_payload"
			case "index-certificate-entry":
				index.Entries = append(index.Entries, publicationArtifactEntry{Path: publicationCaptureCertificatePath, Role: "control_evidence", SHA256: hash(p.CaptureCertificate), Size: int64(len(p.CaptureCertificate)), Framing: "public-json"})
			case "index-physical-size":
				index.Entries[0].Size++
			case "extra-object":
				p.Objects = append(p.Objects, PublicationUploadInput{Path: "parts/extra.enc", SHA256: strings.Repeat("b", 64), Bytes: 100})
			case "missing-certificate":
				p.CaptureCertificate = nil
			}
			finishPublicationRequestData(t, &p, &m, &index)
			if mode == "minimal-mf" {
				p.ManifestInput, _ = ce.Canonical(map[string]any{"schema_version": "system-backup.v1", "origin_installation_id": p.Installation, "backup_public_id": p.Backup, "attempt_no": p.Attempt, "artifact_index": m.Index})
			}
			_, _, err := p.validate()
			if (err == nil) != (mode == "current") {
				t.Fatal("wrong exact public content binding", mode, err)
			}
		})
	}
}
