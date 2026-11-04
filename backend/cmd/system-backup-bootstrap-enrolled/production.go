package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"path/filepath"
	"time"

	materials "clawreef/internal/systembackupbootstrapmaterials"
	ca "clawreef/internal/systembackupcatrust"
	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
	nonce "clawreef/internal/systembackupnoncebootstrap"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

const enrolledCompositionVersion = "enrolled-bootstrap-production-composition.v10"
const enrolledCaptureSource = "/run/system-backup/installation-owner/capture-consumer.json"
const enrolledCapturePin = enrolledCaptureSource + ".sha256"

// Private independently pinned composition DATA, not authority. A's actual
// terminal authenticates the original signed owner-binding/host/evidence
// selection and current SQL source. No implementer or Passed value is decoded.
// Wire aliases avoid invoking the capability types' forbidden MarshalJSON.
type nonceKeyWire nonce.Key
type caBindingWire ca.Binding
type nonceBindingWire struct {
	InstallationID, ServerUUID, Database, ConfigSHA256 string
	NotBefore, ExpiresAt                               time.Time
	Keys                                               []nonceKeyWire
}
type enrolledComposition struct {
	Version                                                            string
	Terminal                                                           install.BootstrapTerminalFiles
	NativeHost                                                         install.BootstrapNativeHostFiles
	Classification                                                     install.FunctionalClassificationFiles
	SourceRegistries                                                   install.BootstrapSourceRegistryFiles
	SourceNativeRegistries                                             execution.BootstrapSourceNativeRegistryFiles
	MinIO                                                              execution.MinIOBootstrapTerminalInput
	SigningConsumerFile, SigningConsumerPinFile, SigningConsumerSHA256 string
	KEKFile, KEKSHA256                                                 string
	KEKWindow                                                          install.BootstrapKEKWindowFiles
	StatusRelay                                                        install.StatusRelayReferenceFiles
	SixReferences                                                      install.SixReferenceFiles
	CatalogLocation                                                    install.BootstrapSourceFilePin
	Nonce                                                              nonceBindingWire
	ArtifactCA, EvidenceCA                                             caBindingWire
	Selections                                                         []pd.BootstrapCandidateSelection
}

func (d enrolledComposition) bindings() (nonce.Binding, ca.Binding, ca.Binding) {
	n := nonce.Binding{InstallationID: d.Nonce.InstallationID, ServerUUID: d.Nonce.ServerUUID, Database: d.Nonce.Database, ConfigSHA256: d.Nonce.ConfigSHA256, NotBefore: d.Nonce.NotBefore, ExpiresAt: d.Nonce.ExpiresAt}
	for _, key := range d.Nonce.Keys {
		n.Keys = append(n.Keys, nonce.Key(key))
	}
	return n, ca.Binding(d.ArtifactCA), ca.Binding(d.EvidenceCA)
}

func loadEnrolledComposition(file, expectedSHA string) (enrolledComposition, error) {
	var d enrolledComposition
	raw, err := install.ReadPrivateFile(file, 262144)
	if err != nil {
		return d, sec.ErrRegistrationUnavailable
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != expectedSHA {
		return d, sec.ErrRegistrationUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || decoder.Decode(new(any)) != io.EOF || d.Version != enrolledCompositionVersion {
		return enrolledComposition{}, sec.ErrRegistrationUnavailable
	}
	canonical, err := json.Marshal(d)
	if err != nil || !bytes.Equal(raw, canonical) {
		return enrolledComposition{}, sec.ErrRegistrationUnavailable
	}
	nativeSHA, err := hex.DecodeString(d.NativeHost.RecordSHA256)
	if err != nil || len(nativeSHA) != 32 || hex.EncodeToString(nativeSHA) != d.NativeHost.RecordSHA256 || !filepath.IsAbs(d.NativeHost.RecordFile) || filepath.Clean(d.NativeHost.RecordFile) != d.NativeHost.RecordFile || !filepath.IsAbs(d.NativeHost.SignatureFile) || filepath.Clean(d.NativeHost.SignatureFile) != d.NativeHost.SignatureFile {
		return enrolledComposition{}, sec.ErrRegistrationUnavailable
	}
	for _, pin := range []install.BootstrapSourceFilePin{d.SourceNativeRegistries.RedisSources, d.SourceNativeRegistries.SecretAllowlist} {
		sha, e := hex.DecodeString(pin.SHA256)
		if e != nil || len(sha) != 32 || hex.EncodeToString(sha) != pin.SHA256 || !filepath.IsAbs(pin.File) || filepath.Clean(pin.File) != pin.File {
			return enrolledComposition{}, sec.ErrRegistrationUnavailable
		}
	}
	if d.SourceNativeRegistries.RedisSources.File == d.SourceNativeRegistries.SecretAllowlist.File {
		return enrolledComposition{}, sec.ErrRegistrationUnavailable
	}
	for _, pin := range [][2]string{{d.SixReferences.RecordFile, d.SixReferences.RecordSHA256}, {d.CatalogLocation.File, d.CatalogLocation.SHA256}, {d.StatusRelay.RecordFile, d.StatusRelay.RecordSHA256}, {d.KEKWindow.RecordFile, d.KEKWindow.RecordSHA256}, {d.SourceRegistries.RecordFile, d.SourceRegistries.RecordSHA256}, {d.SigningConsumerFile, d.SigningConsumerSHA256}, {d.Classification.RecordFile, d.Classification.RecordSHA256}, {d.KEKFile, d.KEKSHA256}, {d.MinIO.BundleFile, d.MinIO.BundleSHA256}, {d.MinIO.GrantFile, d.MinIO.GrantSHA256}, {d.MinIO.DefinitionFile, d.MinIO.DefinitionSHA256}, {d.MinIO.PermissionSource.File, d.MinIO.PermissionSource.SHA256}, {d.MinIO.CapabilityIntentFile, d.MinIO.CapabilityIntentSHA256}} {
		digest, err := hex.DecodeString(pin[1])
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != pin[1] || !filepath.IsAbs(pin[0]) || filepath.Clean(pin[0]) != pin[0] {
			return enrolledComposition{}, sec.ErrRegistrationUnavailable
		}
	}
	paths := []string{d.SixReferences.SignatureFile, d.StatusRelay.SignatureFile, d.KEKWindow.SignatureFile, d.SourceRegistries.SignatureFile, d.SigningConsumerPinFile, d.Classification.SignatureFile, d.Classification.RegistryDirectory, d.MinIO.ProvenanceFile}
	if len(d.MinIO.ReferenceFiles) != 5 {
		return enrolledComposition{}, sec.ErrRegistrationUnavailable
	}
	for _, ref := range d.MinIO.ReferenceFiles {
		paths = append(paths, ref.File)
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return enrolledComposition{}, sec.ErrRegistrationUnavailable
		}
	}
	return d, nil
}

func runEnrolled(ctx context.Context, args []string, out io.Writer) int {
	if len(args) > 0 && args[0] == "query-original" {
		return runOriginalBootstrapQuery(ctx, args[1:], out)
	}
	if ctx == nil || out == nil {
		return 1
	}
	if len(args) > 0 && (args[0] == "catalog-owner-bindings" || args[0] == "issue-original-mapping") {
		return runOriginalMappingAction(ctx, args, out)
	}
	flags := flag.NewFlagSet("system-backup-bootstrap-enrolled", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requirements := flags.Bool("requirements", false, "report concrete linked owners without reading inputs")
	crossBinding := flags.Bool("cross-resource-binding", false, "emit this compiled original cross-resource constructor binding only")
	check := flags.Bool("check", false, "check deployment and pinned composition integrity")
	apply := flags.Bool("apply", false, "consume actual original authority and initialize disabled config")
	deploymentFile := flags.String("deployment-file", "", "private pinned original deployment")
	deploymentSHA := flags.String("deployment-sha256", "", "original deployment SHA256")
	compositionFile := flags.String("composition-file", "", "private independently pinned original composition")
	compositionSHA := flags.String("composition-sha256", "", "original composition SHA256")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 1
	}
	modes := 0
	for _, enabled := range []bool{*requirements, *check, *apply, *crossBinding} {
		if enabled {
			modes++
		}
	}
	if modes != 1 {
		return 1
	}
	base := linkedOwnerAdapters()
	capture := install.NewCaptureSigningConsumer(enrolledCaptureSource, enrolledCapturePin)
	if base.CrossResources != nil {
		return 1
	}
	cross, err := install.NewOriginalCrossResourceRelations(capture)
	if err != nil {
		return 1
	}
	base.CrossResources = cross
	if *crossBinding {
		if *compositionFile != "" || *compositionSHA != "" || *deploymentFile != "" || *deploymentSHA != "" {
			return 1
		}
		binding, e := cross.BindingSHA256()
		if e != nil || json.NewEncoder(out).Encode(install.BootstrapOriginalOwnerBinding{Key: "cross_resources", SHA256: binding}) != nil {
			return 1
		}
		return 0
	}
	if *requirements {
		if *compositionFile != "" || *compositionSHA != "" || *deploymentFile != "" || *deploymentSHA != "" {
			return 1
		}
		owners, err := capture.Owners(base)
		if err != nil {
			return 1
		}
		// Constructors only: five linked owners, still missing concrete nonce/CA
		// binding instances and all other owners. No input file is opened here.
		return run(ctx, []string{"--requirements"}, out, owners)
	}
	if *deploymentFile == "" || *deploymentSHA == "" || *compositionFile == "" || *compositionSHA == "" {
		return 1
	}
	d, err := loadEnrolledComposition(*compositionFile, *compositionSHA)
	if err != nil {
		return 1
	}
	n, artifact, evidence := d.bindings()
	base, _, err = install.LinkFunctionalClassificationOwners(base, capture, d.Classification)
	if err != nil {
		return 1
	}
	base, sourceRegistries, err := addOriginalSourceRegistryTerminal(base, capture, d.SourceRegistries, d.SourceNativeRegistries)
	if err != nil {
		return 1
	}
	base, statusRelay, err := install.LinkOriginalStatusRelayOwners(base, capture, d.StatusRelay)
	if err != nil {
		return 1
	}
	base, sixReferences, err := install.LinkOriginalSixReferenceOwners(base, capture, d.SixReferences)
	if err != nil {
		return 1
	}
	owners, original, err := materials.NewEnrolledTerminalInstallationOwners(base, capture, d.Terminal, n, artifact, evidence)
	if err != nil || owners.CrossResources != cross || owners.References["status_relay"] != statusRelay || !originalSourceRegistryAliases(owners, sourceRegistries) || !originalSixReferenceAliases(owners, sixReferences) {
		return 1
	}
	owners, original, err = materials.LinkOriginalWindowSQLBootstrapKEK(original, d.KEKFile, d.KEKSHA256, d.KEKWindow)
	if err != nil || owners.CrossResources != cross || owners.References["status_relay"] != statusRelay || !originalSourceRegistryAliases(owners, sourceRegistries) || !originalSixReferenceAliases(owners, sixReferences) {
		return 1
	}
	originalKEK, ok := owners.KEK.(*install.OriginalWindowKEK)
	if !ok || originalKEK == nil || owners.References["kek"] != originalKEK {
		return 1
	}
	// Do not open C's client credentials until every OTHER owner is concrete.
	// The six pending C slots are still missing, never counted as installed.
	missing := sec.MissingBootstrapOwnerAdapters(owners)
	terminalMissing := original.MissingTerminalResources()
	remaining := missingBeforeOriginalCatalog(owners)
	remaining = missingBeforeOriginalSigningResources(remaining)
	if len(remaining) != 0 {
		if json.NewEncoder(out).Encode(map[string]any{"status": "blocked", "missing_adapters": missing, "missing_terminal_resources": terminalMissing, "missing_before_minio_construction": remaining, "minio_constructed": false, "kek_preparation_linked": false, "provider_admission": "not_run", "database_opened": false, "configuration_mutated": false}) != nil {
			return 1
		}
		return 2
	}
	// All OTHER owners are concrete before either signer consumer or C
	// credentials are opened. Pending aliases were never marked installed.
	ctx, finish := context.WithTimeout(ctx, 2*time.Minute)
	defer finish()
	var signingConsumer *install.SigningResourceConsumer
	owners, original, signingConsumer, err = install.LinkSigningResourceConsumerOwners(ctx, owners, original, d.SigningConsumerFile, d.SigningConsumerPinFile, d.SigningConsumerSHA256)
	if err != nil {
		return 1
	}
	defer signingConsumer.Close()
	if owners.CrossResources != cross || owners.References["status_relay"] != statusRelay || owners.KEK != originalKEK || owners.References["kek"] != originalKEK || !originalSourceRegistryAliases(owners, sourceRegistries) || !originalSixReferenceAliases(owners, sixReferences) || len(missingBeforeOriginalCatalog(owners)) != 0 {
		return 1
	}
	client, err := capture.OpenTerminalKubernetes(ctx)
	if err != nil {
		return 1
	}
	catalog, err := execution.NewOriginalCatalogInitialInventory(client, execution.CatalogInitialInventoryTerminalInput{MinIO: d.MinIO, LocationFile: d.CatalogLocation.File, LocationSHA256: d.CatalogLocation.SHA256})
	if err != nil {
		return 1
	}
	owners, original, err = addOriginalCatalogTerminal(owners, capture, d.Terminal, catalog)
	if err != nil || owners.CrossResources != cross || owners.References["status_relay"] != statusRelay || owners.KEK != originalKEK || owners.References["kek"] != originalKEK || !originalSourceRegistryAliases(owners, sourceRegistries) || !originalSixReferenceAliases(owners, sixReferences) || len(sec.MissingBootstrapOwnerAdapters(owners)) != 0 || len(original.MissingTerminalResources()) != 0 {
		return 1
	}
	candidates, _, err := original.NativeHostDeploymentCandidates(d.Selections, d.NativeHost)
	if err != nil {
		return 1
	}
	owners.Candidates = candidates
	mode := "--check"
	if *apply {
		mode = "--apply"
	}
	return run(ctx, []string{mode, "--deployment-file", *deploymentFile, "--deployment-sha256", *deploymentSHA}, out, owners)
}
