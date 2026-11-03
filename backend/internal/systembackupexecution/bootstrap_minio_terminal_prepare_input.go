package systembackupexecution

import (
	"bytes"
	"context"
	"path/filepath"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	ma "clawreef/internal/systembackupminioauthority"
	sec "clawreef/internal/systembackupsecurity"
	"k8s.io/client-go/kubernetes"
)

// Original locators only. The pin comes from the independently retained
// ORIGINAL install intent and must match its existing enrolled issuer/bundle,
// never a future task, newly generated key or the observed provider response.
type MinIOBootstrapTerminalMaterials struct {
	Version                                      string
	GrantFile, GrantSHA256                       string
	DefinitionFile, DefinitionSHA256             string
	PermissionSource                             MinIOPublicationPermissionInput
	CapabilityIntentFile, CapabilityIntentSHA256 string
	ReferenceFiles                               []MinIOBootstrapReferenceFile
	ProvenanceFile                               string
}

type MinIOBootstrapTerminalCandidate struct {
	Version, File, SHA256, BindingSHA256 string
	ProbeInventory                       []MinIOBootstrapProbeObject
}

// PrepareOriginalMinIOTerminalInput creates the taskless input instead of
// requiring an already constructed input to export itself. Actual original
// operator/enrollment authorization precedes native probes; exact ORIGINAL
// grant and five payloads must match the frozen issued bundle. No SQL rows are
// inserted here. Runtime L2 refuses this candidate until its exact seven-row
// authority is installed, and every candidate use prepares its own observation.
func PrepareOriginalMinIOTerminalInput(ctx context.Context, owner *install.Installer, kube kubernetes.Interface, password []byte, enrollment install.EnrollmentPin, intentFile, intentSHA, bundleFile, bundleSHA, materialsFile, materialsSHA, directory string) (MinIOBootstrapTerminalCandidate, error) {
	zero := MinIOBootstrapTerminalCandidate{}
	if owner == nil || ctx == nil || ctx.Err() != nil || minioTerminalOutputDirectory(directory) != nil {
		return zero, sec.ErrRegistrationUnavailable
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, sec.ErrRegistrationUnavailable
	}
	read := func(file, sha string, out any) error {
		raw, e := install.ReadPrivateFile(file, 262144)
		if e != nil || !formalCandidateDigest(sha) || hash(raw) != sha || decodePublicationCanonical(raw, out) != nil {
			return sec.ErrRegistrationUnavailable
		}
		return nil
	}
	var intent install.MinIOSQLInstallIntent
	var materials MinIOBootstrapTerminalMaterials
	if read(intentFile, intentSHA, &intent) != nil || read(materialsFile, materialsSHA, &materials) != nil || intent.Version != install.MinIOSQLInstallIntentVersion || len(intent.References) != 5 || materials.Version != "original-minio-bootstrap-terminal-materials.v1" {
		return zero, sec.ErrRegistrationUnavailable
	}
	bundleRaw, e := pinnedDeploymentFile(bundleFile, bundleSHA, 1<<20)
	if e != nil {
		return zero, e
	}
	bundle, e := ma.DecodeSQLBundle(bundleRaw, ma.Digest(bundleSHA))
	if e != nil || bundle.Action != ma.SQLActionInstall {
		return zero, sec.ErrRegistrationUnavailable
	}
	grantRaw, e := ma.EncodeSQLGrant(intent.Grant)
	if e != nil || !bytes.Equal(grantRaw, bundle.Grant) {
		return zero, sec.ErrRegistrationUnavailable
	}
	for i, record := range intent.References {
		raw, e := ma.EncodeSQLReference(record)
		if e != nil || record.Reference.Purpose != bundle.References[i].Purpose || !bytes.Equal(raw, bundle.References[i].Record) {
			return zero, sec.ErrRegistrationUnavailable
		}
	}
	input := MinIOBootstrapTerminalInput{Pin: intent.Pin, BundleFile: bundleFile, BundleSHA256: bundleSHA, GrantFile: materials.GrantFile, GrantSHA256: materials.GrantSHA256, DefinitionFile: materials.DefinitionFile, DefinitionSHA256: materials.DefinitionSHA256, PermissionSource: materials.PermissionSource, CapabilityIntentFile: materials.CapabilityIntentFile, CapabilityIntentSHA256: materials.CapabilityIntentSHA256, ReferenceFiles: materials.ReferenceFiles, ProvenanceFile: materials.ProvenanceFile}
	resource, e := NewMinIOBootstrapTerminalResource(kube, input)
	if e != nil {
		return zero, e
	}
	if e = owner.AuthorizeMinIOSQLInstallation(ctx, password, enrollment, resource.input.Pin, bundleRaw, bundleSHA); e != nil {
		return zero, e
	}
	grant, _, _, e := sec.ReadBootstrapGrantFile(input.GrantFile, input.GrantSHA256)
	if e != nil {
		return zero, e
	}
	definitionRaw, e := pinnedDeploymentFile(input.DefinitionFile, input.DefinitionSHA256, 262144)
	if e != nil {
		return zero, e
	}
	definition, e := install.DecodeMinIOPermissionDefinition(definitionRaw, input.DefinitionSHA256)
	if e != nil {
		return zero, e
	}
	configRaw, e := pinnedDeploymentFile(definition.ConfigFile, definition.ConfigSHA256, 262144)
	if e != nil {
		return zero, e
	}
	config, e := sec.DecodeBootstrapConfig(configRaw)
	if e != nil {
		return zero, e
	}
	check, until, e := resource.qualifyInstallation(ctx, grant, config)
	if e != nil {
		return zero, e
	}
	active, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if e = owner.AuthorizeMinIOSQLInstallation(active, password, enrollment, resource.input.Pin, bundleRaw, bundleSHA); e != nil {
		return zero, e
	}
	// Reopen both independent original inputs after physical qualification.
	var intentTail install.MinIOSQLInstallIntent
	var materialsTail MinIOBootstrapTerminalMaterials
	if read(intentFile, intentSHA, &intentTail) != nil || read(materialsFile, materialsSHA, &materialsTail) != nil || active.Err() != nil || !time.Now().Before(until) {
		return zero, sec.ErrRegistrationUnavailable
	}
	raw, e := ce.Canonical(resource.input)
	if e != nil {
		return zero, sec.ErrRegistrationUnavailable
	}
	if e = writeMinioTerminalInput(directory, raw); e != nil {
		return zero, e
	}
	if e = owner.AuthorizeMinIOSQLInstallation(active, password, enrollment, resource.input.Pin, bundleRaw, bundleSHA); e != nil || active.Err() != nil || !time.Now().Before(until) {
		return zero, install.ErrCommitUnknown
	}
	path := filepath.Join(directory, minioTerminalInputFileName)
	exported, e := ReadMinIOBootstrapTerminalInput(path, hash(raw))
	if e != nil {
		return zero, install.ErrCommitUnknown
	}
	binding, e := resource.BindingSHA256()
	if e != nil || active.Err() != nil || !time.Now().Before(until) {
		return zero, install.ErrCommitUnknown
	}
	loaded, e := NewMinIOBootstrapTerminalResource(kube, exported)
	if e != nil {
		return zero, install.ErrCommitUnknown
	}
	loadedBinding, e := loaded.BindingSHA256()
	if e != nil || loadedBinding != binding || active.Err() != nil || !time.Now().Before(until) {
		return zero, install.ErrCommitUnknown
	}
	return MinIOBootstrapTerminalCandidate{Version: "original-minio-terminal-input-candidate.v1", File: path, SHA256: hash(raw), BindingSHA256: binding, ProbeInventory: check.ProbeInventory()}, nil
}
