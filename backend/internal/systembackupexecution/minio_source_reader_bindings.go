package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"time"

	sb "clawreef/internal/systembackup"
	"clawreef/internal/systembackupinstallationowner/install"
)

// DATA pins, not source delegation, original hold, coverage or native outcome.
// CaptureCredential is the existing []byte/base64 worker+metadata format;
// HistoryCredential is the DISTINCT string format required by S3CoverageCensus.
type OriginalMinIOSourceReaderBindings struct {
	Version, MaterialsSHA256, Account, CredentialVersion string
	CaptureCredential, HistoryCredential                 install.BootstrapSourceFilePin
	Until                                                time.Time
}

// Call BEFORE replacing original authoring source connection/material pins and
// BEFORE Acquire disables the old root. Both original genuine capabilities are
// rechecked; this creates no account/policy and sends no native operation.
// D's actual source builder/issuer must then bind these fixed files into its
// new real source selection/grants, preserving endpoint/CA and finite scopes.
func PrepareOriginalMinIOSourceReaderBindings(ctx context.Context, write *install.OriginalWriterMaintenance, source *install.BootstrapSourceRegistryAuthoring, materialsFile, materialsSHA, privateEmptyDirectory string) (OriginalMinIOSourceReaderBindings, error) {
	zero := OriginalMinIOSourceReaderBindings{}
	if write == nil || source == nil || write.CheckOriginalMinIOSourceSetup(ctx, source) != nil || nativeInstallEmptyDirectory(privateEmptyDirectory) != nil {
		return zero, install.ErrInstall
	}
	raw, e := pinnedDeploymentFile(materialsFile, materialsSHA, 262144)
	var mat OriginalMinIOSourceReadMaterials
	if e != nil || strictBootstrapSourceJSON(raw, &mat) != nil || mat.Version != "original-minio-source-read-materials.v1" || filepath.Join(mat.Native.CustodyDirectory, "source-read.materials.json") != materialsFile {
		return zero, install.ErrInstall
	}
	selection, target, e := source.Selection(ctx)
	if e != nil {
		return zero, e
	}
	selected, _ := json.Marshal(selection)
	if hash(selected) != mat.SourceSelectionSHA256 || target.Namespace != mat.Native.Namespace || target.NamespaceUID != mat.Native.NamespaceUID {
		return zero, install.ErrInstall
	}
	bound := false
	for _, connection := range selection.Connections {
		if connection.Purpose == "source_objects" {
			bound = connection.Endpoint == mat.Native.Endpoint && connection.CA.File == mat.Native.CAFile && connection.CA.SHA256 == mat.Native.CASHA256
		}
	}
	if !bound {
		return zero, install.ErrInstall
	}
	raw, e = pinnedDeploymentFile(mat.ReaderCredential.File, mat.ReaderCredential.SHA256, 16384)
	var credential sb.MinIOGateCredential
	if e != nil || strictBootstrapSourceJSON(raw, &credential) != nil {
		clear(raw)
		return zero, install.ErrInstall
	}
	clear(raw)
	defer clear(credential.SecretKey)
	raw, e = pinnedDeploymentFile(mat.CaptureReaderCredential.File, mat.CaptureReaderCredential.SHA256, 16384)
	var capture metadataSourceCredential
	if e != nil || strictBootstrapSourceJSON(raw, &capture) != nil {
		clear(raw)
		return zero, install.ErrInstall
	}
	clear(raw)
	defer clear(capture.SecretKey)
	if capture.AccessKey != credential.AccessKey || !bytes.Equal(capture.SecretKey, credential.SecretKey) || len(capture.SessionToken) != 0 || capture.Username != "" || len(capture.Password) != 0 || credential.Version == "" || credential.Version == "latest" || credential.Version == "current" || len(credential.SecretKey) < 8 {
		return zero, install.ErrInstall
	}
	until := mat.Until
	_, writerUntil, e := write.Identity(ctx)
	if e != nil {
		return zero, e
	}
	for _, cap := range []time.Time{selection.Until, credential.Until, writerUntil} {
		if cap.Before(until) {
			until = cap
		}
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return zero, install.ErrInstall
	}
	if deadline.Before(until) {
		until = deadline
	}
	if time.Now().Before(credential.NotBefore) || !time.Now().Before(until) {
		return zero, install.ErrInstall
	}
	// Exact legacy census credential shape; no byte-array/Base64 conversion
	// is delegated to the caller, and the fixed native secret is unchanged.
	history := struct {
		AccessKey    string `json:"access_key"`
		SecretKey    string `json:"secret_key"`
		SessionToken string `json:"session_token"`
	}{credential.AccessKey, string(credential.SecretKey), ""}
	file, sha, e := nativeInstallSave(privateEmptyDirectory, "history-reader.json", history)
	if e != nil {
		return zero, e
	}
	if sourceGateSyncDirectory(privateEmptyDirectory) != nil || write.CheckOriginalMinIOSourceSetup(ctx, source) != nil {
		return zero, install.ErrInstall
	}
	stored, e := pinnedDeploymentFile(file, sha, 16384)
	var actual struct {
		AccessKey    string `json:"access_key"`
		SecretKey    string `json:"secret_key"`
		SessionToken string `json:"session_token"`
	}
	if e != nil || strictBootstrapSourceJSON(stored, &actual) != nil || actual != history {
		clear(stored)
		return zero, install.ErrInstall
	}
	clear(stored)
	return OriginalMinIOSourceReaderBindings{Version: "original-minio-source-reader-bindings.v1", MaterialsSHA256: materialsSHA, Account: credential.AccessKey, CredentialVersion: credential.Version, CaptureCredential: mat.CaptureReaderCredential, HistoryCredential: install.BootstrapSourceFilePin{File: file, SHA256: sha}, Until: until}, nil
}
