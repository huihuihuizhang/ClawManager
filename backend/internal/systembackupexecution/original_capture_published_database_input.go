package systembackupexecution

import (
	"encoding/json"
	"path/filepath"
	"reflect"

	"clawreef/internal/systembackupinstallationowner/install"
)

type OriginalPublishedCaptureDatabaseInputs struct {
	Version                                                                            string
	OriginalDefinition, PublishedDefinition, OriginalDatabaseIssue, PublicationReceipt install.BootstrapSourceFilePin
}

// The publication owner only appends one actual verifier pin to the unsigned
// source definition. Rebind this DATA hash before DB native issuance; preserve
// every original scope/file/window, and never change an already signed grant.
func BindOriginalPublishedCaptureDatabaseInputs(in OriginalPublishedCaptureDatabaseInputs) (install.BootstrapSourceFilePin, error) {
	var zero install.BootstrapSourceFilePin
	if in.Version != "original-published-capture-database-inputs.v1" {
		return zero, install.ErrInstall
	}
	read := func(pin install.BootstrapSourceFilePin) ([]byte, error) {
		return pinnedDeploymentFile(pin.File, pin.SHA256, 8<<20)
	}
	raw, e := read(in.OriginalDefinition)
	var original ProductionMaterialDefinition
	if e != nil || decodeMetadataCanonical(raw, &original) != nil || len(original.PublisherVerifier) != 0 {
		return zero, install.ErrInstall
	}
	raw, e = read(in.PublishedDefinition)
	var published ProductionMaterialDefinition
	if e != nil || decodeMetadataCanonical(raw, &published) != nil || len(published.PublisherVerifier) != 1 {
		return zero, install.ErrInstall
	}
	copy := published
	copy.PublisherVerifier = original.PublisherVerifier
	if !reflect.DeepEqual(copy, original) {
		return zero, install.ErrInstall
	}
	raw, e = read(in.PublicationReceipt)
	var receipt PublicationRuntimeMaterialReceipt
	if e != nil || json.Unmarshal(raw, &receipt) != nil || receipt.Version != "original-publication-runtime-materials-result.v1" || receipt.State != "original_owner_materials_generated_installed_binding_check_pending" || receipt.SourceDefinition != in.PublishedDefinition || published.PublisherVerifier[0] != receipt.Verifier {
		return zero, install.ErrInstall
	}
	raw, e = read(in.OriginalDatabaseIssue)
	var database install.DatabaseSourceIssueDefinition
	if e != nil || decodeMetadataCanonical(raw, &database) != nil || database.Version != install.DatabaseSourceIssueVersion || database.OriginalDefinitionSHA256 != in.OriginalDefinition.SHA256 || database.Source.GrantSHA256 != "" {
		return zero, install.ErrInstall
	}
	database.OriginalDefinitionSHA256 = in.PublishedDefinition.SHA256
	body, e := json.Marshal(database)
	if e != nil {
		return zero, e
	}
	file := filepath.Join(filepath.Dir(in.OriginalDatabaseIssue.File), "database-source-published-inputs.json")
	if e = writeOriginalMaterialFile(file, body); e != nil {
		return zero, e
	}
	return install.BootstrapSourceFilePin{File: file, SHA256: hash(body)}, nil
}
