package systembackupexecution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	pc "clawreef/internal/systembackuppartcontainer"
	w "clawreef/internal/systembackupwire"
)

type publicationManifestAssembly struct {
	Manifest, Index []byte
	Objects         []PublicationUploadInput
}

// Assemble only from the private complete-current-C receipt, known original
// signed certificate, actual six durable files, current original recovery
// facts and original bootstrap. No caller-supplied passed/eligibility flag is
// accepted, and this function cannot issue a grant, sign or upload anything.
func assembleOriginalPublicationManifest(capture publicationVerifiedCapture, certificate originalPublicationCaptureCertificate, files publicationContainerFileSet, bootstrap []byte, recovery publicationRecoveryFacts, target PublicationTargetMaterials, limits ArtifactReadLimits, now time.Time) (_ publicationManifestAssembly, resultErr error) {
	stage := "private input receipts"
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("original manifest %s: %w", stage, resultErr)
		}
	}()
	var zero publicationManifestAssembly
	if !capture.checked() || !certificate.checked(capture, now) || capture.DescriptionSHA256 == "" || capture.SourceFacts.PublicationPolicy == nil || recovery.captureSHA256 != capture.receipt.sha256 || recovery.targetSHA256 != publicationRecoveryTargetSHA(target) || !formalCandidateDigest(recovery.evidenceSHA256) || !now.Before(recovery.until) || files.Version != "system-backup-original-publication-container-files.v1" || !formalCandidateDigest(files.PlanSHA256) || len(files.Files) != 6 || len(bootstrap) < 2 || len(bootstrap) > cd.MaxBootstrapBytes || limits.validate() != nil {
		return zero, c.ErrExecutionRecord
	}
	envelope, closed := decodeOriginalCaptureCertificateEnvelope(certificate.bytes)
	stage = "known certificate payload"
	var cert publicationCaptureCertificatePayload
	if !closed || decodePublicationCanonical(envelope.Payload, &cert) != nil || cert.CompletedAt.IsZero() || cert.CompletedAt.After(now) {
		return zero, c.ErrExecutionRecord
	}
	checkpointPins := map[string]string{}
	for _, pin := range cert.Checkpoints {
		if checkpointPins[pin.Part] != "" {
			return zero, c.ErrExecutionRecord
		}
		checkpointPins[pin.Part] = pin.SHA256
	}
	if len(checkpointPins) != len(capture.Parts) {
		return zero, c.ErrExecutionRecord
	}
	if _, err := cd.DecodeBootstrap(bootstrap, cd.Scope{InstallationID: capture.Input.InstallationID, TaskPublicID: capture.Input.TaskPublicID, ConfigVersion: capture.Input.ConfigVersion, ConfigSHA256: capture.Input.ConfigSHA256, AttemptNo: capture.Input.CaptureAttemptNo, CaptureContextSHA256: capture.CaptureContextSHA256}, capture.Input.SourceSHA256, checkpointPins); err != nil {
		return zero, err
	}
	source := capture.SourceFacts
	stage = "original Secret policy"
	secret, err := publicationSecretPolicyFacts(capture)
	if err != nil {
		return zero, err
	}
	stage = "original SQL domain counts"
	sqlCounts, err := publicationSQLBusinessCounts(capture)
	if err != nil {
		return zero, err
	}
	m := publicationManifestV12{Version: "system-backup.v1", AppVersion: source.AppVersion, GitCommit: source.GitCommit, Generated: certificate.issued, Installation: capture.Input.InstallationID, Backup: capture.Input.TaskPublicID, Attempt: capture.Input.CaptureAttemptNo, Orchestrator: capture.Input.Backup.SourceOrchestrator, Profile: capture.Input.Backup.SourceProfile, Runner: "kubernetes", Purpose: capture.Input.Backup.TaskPurpose, MigrationCatalog: source.MigrationCatalogSHA256, Schema: source.SchemaSHA256, CaptureContext: capture.CaptureContextSHA256, CaptureCertificate: certificate.sha256, Target: recovery.Target, KEK: recovery.KEK, Consistency: "strong", Eligibility: publicationManifestEligibility{PartsComplete: true, VerifiersComplete: true, Disqualifiers: []string{}}, Parts: map[string]publicationManifestPart{}, Index: publicationManifestIndex{Path: "artifact-index.json"}, Marker: publicationManifestMarker{Path: "_COMMITTED", Version: "system-backup-committed.v1"}, Control: publicationManifestControl{Path: ce.CipherPath, Version: ce.Version}, SecretPolicy: secret, SchemaCoverage: publicationManifestCoverage{RegistryVersion: source.SchemaRegistry.Version, RegistrySHA256: source.SchemaRegistry.SHA256, Covered: int64(source.CoveredObjects), Excluded: int64(source.ExcludedObjects)}, Config: publicationManifestConfig{Version: capture.Input.ConfigVersion, SHA256: capture.Input.ConfigSHA256, Parameters: map[string]json.RawMessage{}}, Business: map[string]publicationManifestBusiness{}, Warnings: []publicationManifestWarning{}}
	stage = "original task projection"
	if d.ValidateBackupSpec(&capture.Input.Backup) != nil || len(capture.Input.Backup.RequestedParts) != 6 {
		return zero, c.ErrExecutionRecord
	}
	// Redacted recovery parameters contain only this fixed public allowlist.
	// The exact full configuration stays encrypted and its original hash remains
	// above. No material path, credentials or source inventory is copied here.
	for key, value := range map[string]string{"source_orchestrator": m.Orchestrator, "source_profile": m.Profile, "runner": capture.Input.Backup.Runner} {
		b, _ := json.Marshal(value)
		m.Config.Parameters[key] = b
	}
	index := publicationArtifactIndex{Version: "system-backup-artifact-index.v1", Backup: m.Backup, Attempt: m.Attempt, CaptureContext: m.CaptureContext, Entries: []publicationArtifactEntry{}}
	byFile := map[string]publicationContainerFile{}
	stage = "six physical files"
	for _, file := range files.Files {
		if !manifestOneOf(file.Part, publicationRequestedParts...) || byFile[file.Part].Part != "" || file.Path != "parts/"+file.Part+"/container.enc" || file.Receipt.Size < 1 || !formalCandidateDigest(file.Receipt.SHA256) {
			return zero, c.ErrExecutionRecord
		}
		byFile[file.Part] = file
		index.Entries = append(index.Entries, publicationArtifactEntry{Path: file.Path, Role: "encrypted_payload", Size: file.Receipt.Size, SHA256: file.Receipt.SHA256, Framing: pc.Version})
	}
	type checkpointMember struct{ Part, SHA256 string }
	checkpointSets := map[string][]checkpointMember{}
	evidenceSets := map[string]map[string]bool{}
	summaryInputs := map[string][]any{}
	for category, counts := range sqlCounts {
		m.Business[category] = publicationManifestBusiness{Objects: counts.Tables, Rows: counts.Rows, Bytes: counts.RawCellBytes}
		summaryInputs[category] = []any{source.SchemaRegistry, counts}
	}
	warnings := map[string]publicationManifestWarning{}
	stage = "original member results"
	for _, part := range capture.Parts {
		if len(part.ResultJSON) < 2 || hash(part.ResultJSON) != part.ResultSHA256 {
			return zero, c.ErrExecutionRecord
		}
		var result d.ModuleResult
		if decodeMetadataCanonical(part.ResultJSON, &result) != nil || result.Part != part.Part || result.Status != "completed" || result.FailureCategory != "none" || !bytes.Equal(result.Checkpoint, part.Checkpoint) || result.Warnings == nil {
			return zero, c.ErrExecutionRecord
		}
		for _, warning := range result.Warnings {
			raw, err := ce.Canonical(warning)
			if err != nil {
				return zero, err
			}
			sum := hash(raw)
			details, _ := json.Marshal(sum)
			key := warning.Code + "/" + sum
			warnings[key] = publicationManifestWarning{Code: warning.Code, Category: warning.Category, Disqualifying: warning.Disqualifying, Details: details}
		}
		if part.RequestedPart == "" {
			if part.Part != cd.Part && part.Part != ce.Part && part.Part != ce.ProofPart {
				return zero, c.ErrExecutionRecord
			}
			index.Entries = append(index.Entries, publicationArtifactEntry{Path: part.CipherPath, Role: "control_evidence", Size: part.CipherBytes, SHA256: part.CipherSHA256, Framing: w.FramingVersion}, publicationArtifactEntry{Path: part.EnvelopePath, Role: "envelope", Size: part.EnvelopeBytes, SHA256: part.EnvelopeSHA256, Framing: w.EnvelopeVersion})
			if part.Part == ce.Part {
				m.Control.Checksum = part.CipherSHA256
			}
			continue
		}
		name := part.RequestedPart
		if byFile[name].Part == "" || !part.Counts.Complete {
			return zero, c.ErrExecutionRecord
		}
		cp, err := ce.Canonical(json.RawMessage(part.Checkpoint))
		if err != nil {
			return zero, err
		}
		checkpointSets[name] = append(checkpointSets[name], checkpointMember{Part: part.Part, SHA256: hash(cp)})
		if evidenceSets[name] == nil {
			evidenceSets[name] = map[string]bool{}
		}
		evidenceSets[name][part.ResultEvidenceRef] = true
		for _, ref := range part.ResultEvidenceIDs {
			evidenceSets[name][ref] = true
		}
		summary := m.Parts[name]
		summary.Required, summary.Status, summary.Consistency, summary.CheckpointType = true, "completed", "strong", "gate_staging"
		summary.Captured, summary.CipherSHA256 = cert.CompletedAt, byFile[name].Receipt.SHA256
		objects := part.Counts.Items
		if part.Operation == "capture-workspace" {
			objects = part.Counts.ArchiveEntries
		}
		if !addPublicationManifestCounts(&summary.Objects, objects) || !addPublicationManifestCounts(&summary.Bytes, part.Counts.ContentBytes) {
			return zero, c.ErrExecutionRecord
		}
		m.Parts[name] = summary
		binding := publicationBusinessMemberBinding(part, hash(cp))
		if part.Operation == "capture-database" {
			// Every SQL category is a projection of this independently read
			// original full SQL C stream. Bind its actual content/result/CP,
			// not only equal table/row/byte statistics. This hash is comparison
			// DATA and never a replacement for the complete C verification.
			for category := range sqlCounts {
				summaryInputs[category] = append(summaryInputs[category], binding)
			}
		} else {
			category := publicationOperationBusinessCategory(part.Operation, part.Category)
			business, ok := m.Business[category]
			if !ok {
				return zero, c.ErrExecutionRecord
			}
			if !addPublicationManifestCounts(&business.Objects, objects) || !addPublicationManifestCounts(&business.Bytes, part.Counts.ContentBytes) {
				return zero, c.ErrExecutionRecord
			}
			m.Business[category] = business
			summaryInputs[category] = append(summaryInputs[category], binding)
		}
	}
	stage = "six requested-part aggregates"
	for _, name := range publicationRequestedParts {
		set := checkpointSets[name]
		if len(set) == 0 {
			return zero, c.ErrExecutionRecord
		}
		sort.Slice(set, func(i, j int) bool { return set[i].Part < set[j].Part })
		raw, err := ce.Canonical(set)
		if err != nil {
			return zero, err
		}
		summary := m.Parts[name]
		summary.CheckpointSHA256 = hash(raw)
		summary.Evidence = []string{}
		for ref := range evidenceSets[name] {
			summary.Evidence = append(summary.Evidence, ref)
		}
		sort.Strings(summary.Evidence)
		m.Parts[name] = summary
	}
	for category, inputs := range summaryInputs {
		raw, err := ce.Canonical(struct {
			Version, Category string
			Inputs            []any
		}{"system-backup-original-business-summary-inputs.v1", category, inputs})
		if err != nil {
			return zero, err
		}
		b := m.Business[category]
		b.VerifierSHA256 = hash(raw)
		m.Business[category] = b
	}
	for _, warning := range warnings {
		m.Warnings = append(m.Warnings, warning)
	}
	sort.Slice(m.Warnings, func(i, j int) bool {
		if m.Warnings[i].Code != m.Warnings[j].Code {
			return m.Warnings[i].Code < m.Warnings[j].Code
		}
		return string(m.Warnings[i].Details) < string(m.Warnings[j].Details)
	})
	index.Entries = append(index.Entries, publicationArtifactEntry{Path: cd.BootstrapPath, Role: "control_evidence", Size: int64(len(bootstrap)), SHA256: hash(bootstrap), Framing: cd.BootstrapVersion})
	sort.Slice(index.Entries, func(i, j int) bool { return index.Entries[i].Path < index.Entries[j].Path })
	if len(index.Entries) != 13 {
		return zero, c.ErrExecutionRecord
	}
	rawIndex, err := ce.Canonical(index)
	if err != nil || int64(len(rawIndex)) > limits.MaxIndexBytes {
		return zero, c.ErrExecutionRecord
	}
	m.Index.Checksum = hash(rawIndex)
	if m.Purpose == "functional_test" {
		m.Eligibility.Disqualifiers = append(m.Eligibility.Disqualifiers, "functional_test")
	}
	for _, warning := range m.Warnings {
		if warning.Disqualifying {
			m.Eligibility.Disqualifiers = append(m.Eligibility.Disqualifiers, "disqualifying_warning")
			break
		}
	}
	if m.Target.Class != "dr-ready-external" {
		m.Eligibility.Disqualifiers = append(m.Eligibility.Disqualifiers, "target_not_external")
	}
	if len(m.Target.Risks) != 0 {
		m.Eligibility.Disqualifiers = append(m.Eligibility.Disqualifiers, "target_risk")
	}
	if m.Target.AttestationID == nil {
		m.Eligibility.Disqualifiers = append(m.Eligibility.Disqualifiers, "attestation_invalid")
	}
	if !m.KEK.SourceIndependent || m.KEK.RecoveryProof == nil {
		m.Eligibility.Disqualifiers = append(m.Eligibility.Disqualifiers, "kek_not_recoverable")
	}
	// Hash the independently authenticated original inputs, never the manifest
	// containing this hash. Reconciliation regenerates the same exact bytes.
	rawInputs, err := ce.Canonical(struct{ Capture, Certificate, Files, Index, Bootstrap, Recovery string }{capture.receipt.sha256, certificate.sha256, files.PlanSHA256, m.Index.Checksum, hash(bootstrap), recovery.evidenceSHA256})
	if err != nil {
		return zero, err
	}
	m.Eligibility.InputsSHA256 = hash(rawInputs)
	stage = "complete manifest contract"
	manifest, err := ce.Canonical(m)
	if err != nil || m.validate() != nil {
		return zero, c.ErrExecutionRecord
	}
	out := publicationManifestAssembly{Manifest: manifest, Index: rawIndex, Objects: []PublicationUploadInput{}}
	for _, entry := range index.Entries {
		out.Objects = append(out.Objects, PublicationUploadInput{Path: entry.Path, SHA256: entry.SHA256, Bytes: entry.Size})
	}
	out.Objects = append(out.Objects, PublicationUploadInput{Path: "artifact-index.json", SHA256: hash(rawIndex), Bytes: int64(len(rawIndex))}, PublicationUploadInput{Path: publicationCaptureCertificatePath, SHA256: certificate.sha256, Bytes: int64(len(certificate.bytes))})
	sort.Slice(out.Objects, func(i, j int) bool { return out.Objects[i].Path < out.Objects[j].Path })
	req := PublicationUploadRequest{Version: publicationPresignedUploadVersion, Installation: m.Installation, Backup: m.Backup, Attempt: m.Attempt, Objects: out.Objects, ManifestInput: manifest, IndexBytes: rawIndex, CaptureCertificate: certificate.bytes, CaptureBootstrap: bootstrap}
	stage = "complete upload transport and original capacity"
	if validatePublicationContainerManifestInput(req, manifest) != nil || publicationUploadBytesWithinLimits(req, int64(len(manifest)), limits) != nil {
		return zero, c.ErrExecutionRecord
	}
	return out, nil
}

func addPublicationManifestCounts(dst *int64, value int64) bool {
	if !manifestCount(*dst) || !manifestCount(value) || value > 9007199254740991-*dst {
		return false
	}
	*dst += value
	return true
}

func publicationBusinessMemberBinding(part publicationVerifiedPart, checkpoint string) any {
	return struct {
		Part, Operation, InvocationSHA256, CandidateSHA256, ResultSHA256  string
		CheckpointSHA256, CipherSHA256, EnvelopeSHA256, ResultEvidenceRef string
		Counts                                                            ownedPayloadCounts
	}{part.Part, part.Operation, part.InvocationSHA256, part.CandidateSHA256, part.ResultSHA256, checkpoint, part.CipherSHA256, part.EnvelopeSHA256, part.ResultEvidenceRef, part.Counts}
}

// SQL ownership is defined by the original schema registry. Non-SQL units are
// counted in their original owning domain: team state, skill content, or the
// application's shared Redis/Kubernetes resource inventory. Counts are actual
// reader units; ciphertext sizes remain separate in the physical object index.
func publicationOperationBusinessCategory(op, category string) string {
	switch op {
	case "capture-team-redis", "capture-team-objects":
		return "teams"
	case "capture-skill-objects":
		return "skill_hub"
	case "capture-workspace":
		if manifestOneOf(category, "instances", "teams") {
			return category
		}
		return ""
	case "capture-source-redis", "capture-deployment-resources", "capture-secret-bundle":
		return "resources"
	}
	return ""
}
