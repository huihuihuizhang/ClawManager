package systembackupexecution

import (
	"clawreef/internal/systembackupinstallationowner/install"
	"encoding/json"
	"errors"
	"time"
)

// Private comparison/diagnostic data only. No receipt grants deletion or
// proves that a namespace/name/label belongs to this invocation.
type OriginalMaterializationAsset struct {
	Kind, Namespace, Name, UID, ContentSHA256 string
	Disposition, CreateResponseUID            string
	Observed, Accepted                        bool
}
type originalMaterializationDiagnostic struct {
	Version, OriginalDefinitionSHA256, Phase, Status string
	NotBefore, Until                                 time.Time
	Assets                                           []OriginalMaterializationAsset
}
type OriginalMaterializationDiagnosticReference struct {
	Version, Status, Phase, File, SHA256 string
}
type originalMaterializationFailure struct {
	cause      error
	diagnostic OriginalMaterializationDiagnosticReference
}

func (*originalMaterializationFailure) Error() string {
	return "original materialization rejected; resources may remain"
}
func (e *originalMaterializationFailure) Unwrap() error { return e.cause }

// MaterializationDiagnosticForError returns only the independent private
// diagnostic locator; never an authorization, absence proof or cleanup list.
func MaterializationDiagnosticForError(err error) (OriginalMaterializationDiagnosticReference, bool) {
	var failed *originalMaterializationFailure
	if !errors.As(err, &failed) {
		return OriginalMaterializationDiagnosticReference{}, false
	}
	return failed.diagnostic, true
}
func (d *originalMaterializationDiagnostic) record(asset OriginalMaterializationAsset) {
	if d != nil {
		d.Assets = append(d.Assets, asset)
	}
}
func (d *originalMaterializationDiagnostic) persist(outputFile string) OriginalMaterializationDiagnosticReference {
	ref := OriginalMaterializationDiagnosticReference{Version: "original-materialization-diagnostic-reference.v1", Status: "diagnostic_unavailable_possible_residuals", Phase: d.Phase}
	raw, err := json.Marshal(d)
	if err != nil {
		return ref
	}
	digest := hash(raw)
	// Different attempt outcomes get different create-only files. Exact prior
	// diagnostics are reusable; none is overwritten, including failed outcomes.
	file := outputFile + ".diagnostic." + digest + ".json"
	if writeOriginalMaterialFile(file, raw) != nil {
		return ref
	}
	actual, err := install.ReadSourceMaterialFile(file)
	if err != nil || hash(actual) != digest {
		return ref
	}
	ref.Status, ref.File, ref.SHA256 = d.Status, file, digest
	return ref
}
