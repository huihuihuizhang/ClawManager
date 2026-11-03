package systembackupexecution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	adapter "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	"k8s.io/client-go/kubernetes"
)

type OriginalCoverageSourceOutput struct{ File, SHA256 string }
type OriginalMinIOCoverageSource struct {
	Purpose string
	Census  adapter.S3CoverageCensusFacts
}
type OriginalMinIOCoverageCollection struct {
	Version, DefinitionSHA256, State string
	Scopes                           []OriginalMinIOCoverageSource
}

func CollectOriginalSQLCoverageSource(ctx context.Context, owner *install.Installer, password []byte, enrollment install.EnrollmentPin, definitionFile, definitionSHA, directory string) (OriginalCoverageSourceOutput, error) {
	zero := OriginalCoverageSourceOutput{}
	if ctx == nil || ctx.Err() != nil || owner == nil || nativeInstallEmptyDirectory(directory) != nil {
		return zero, install.ErrInstall
	}
	// Preserve actual original table names first. Unknown schemas remain a
	// strict census refusal; this file is DATA for source-owner review only.
	names, e := owner.InspectOriginalSQLCoverageTables(ctx, password, enrollment, definitionFile, definitionSHA)
	if e != nil {
		return zero, e
	}
	if _, _, e = nativeInstallSave(directory, "original-sql-source-tables.json", names); e != nil {
		return zero, e
	}
	observed, e := owner.ObserveOriginalSQLCoverageCensus(ctx, password, enrollment, definitionFile, definitionSHA)
	if e != nil {
		return zero, e
	}
	record := struct {
		Version, DefinitionSHA256, State string
		Census                           adapter.SQLCoverageCensusFacts
	}{"original-sql-live-coverage-source-collection.v1", definitionSHA, "unadmitted_original_database_census_not_locked_not_backfilled_not_adopted", observed.Facts()}
	file, sha, e := nativeInstallSave(directory, "original-sql-coverage.census.json", record)
	return OriginalCoverageSourceOutput{file, sha}, e
}

func originalMinIOCoverageScopes(p *minioPermissionProductionInputs, credentialSHA string) ([]OriginalMinIOCoverageSource, error) {
	if p == nil || p.target.Bucket == p.catalog.Bucket || !formalCandidateDigest(credentialSHA) {
		return nil, install.ErrInstall
	}
	selections := []struct{ purpose, bucket, prefix string }{{"artifact", p.target.Bucket, p.target.Root}, {"staging_unknown", p.target.Bucket, p.target.RemoteStagingRoot}, {"catalog_holds", p.catalog.Bucket, p.catalog.Root}}
	out := []OriginalMinIOCoverageSource{}
	seen := map[string]bool{}
	for _, selection := range selections {
		if selection.prefix == "" || !strings.HasSuffix(selection.prefix, "/") {
			return nil, install.ErrInstall
		}
		prefix := strings.TrimSuffix(selection.prefix, "/")
		if prefix == "" || selection.bucket == "" || seen[selection.bucket+"/"+prefix] {
			return nil, install.ErrInstall
		}
		seen[selection.bucket+"/"+prefix] = true
		scope := adapter.S3CoverageScope{Endpoint: p.grant.Provider.Endpoint, Region: p.grant.Provider.Region, Bucket: selection.bucket, Prefix: prefix, CASHA256: p.grant.Provider.CASHA256, CredentialSHA256: credentialSHA}
		raw, e := json.Marshal(scope)
		if e != nil {
			return nil, e
		}
		sum := sha256.Sum256(raw)
		source := reg.SourceRecord{SourceID: "original-minio-live-coverage-" + selection.purpose, RecordID: "unadmitted-minio-" + selection.purpose, RecordVersion: p.definition.TargetSHA256, ContentSHA256: hex.EncodeToString(sum[:])}
		out = append(out, OriginalMinIOCoverageSource{Purpose: selection.purpose, Census: adapter.S3CoverageCensusFacts{Source: source, Scope: scope}})
	}
	return out, nil
}

// Actual original provider collector. These are COMPLETE LIVE censuses only,
// deliberately not PreparedCoverage, immutable snapshots, history/backfill,
// writer fences or the four-partition adoption proof. All3 C-owned publication
// scopes are selected from the SAME pinned original definition/target/catalog;
// callers cannot replace prefixes/endpoints with request data or a path list.
func CollectOriginalMinIOCoverageSources(ctx context.Context, owner *install.Installer, kube kubernetes.Interface, password []byte, enrollment install.EnrollmentPin, definitionFile, definitionSHA string, admin MinIONativeAdminFiles, directory string) (result OriginalCoverageSourceOutput, resultErr error) {
	if ctx == nil || ctx.Err() != nil || owner == nil || kube == nil || nativeInstallEmptyDirectory(directory) != nil {
		return result, install.ErrInstall
	}
	if e := owner.AuthenticateOriginalCoverageCensus(ctx, password, enrollment, definitionFile, definitionSHA); e != nil {
		return result, e
	}
	p, e := readMinIOPermissionProductionInputs(definitionFile, definitionSHA)
	if e != nil {
		return result, e
	}
	defer p.clear()
	if minioPermissionKubernetesCheck(ctx, kube, p) != nil {
		return result, install.ErrInstall
	}
	native, e := nativeInstallAdmin(p.grant.Provider, ctx, MinIONativeAdminFiles{UserFile: admin.UserFile, PasswordFile: admin.PasswordFile})
	if e != nil {
		return result, e
	}
	defer native.close()
	if _, e = native.collectNativeInstallServer(ctx, p.grant.Profile); e != nil {
		return result, e
	}
	// A temporary0600 copy adapts the ORIGINAL raw admin files to the existing
	// census's closed3-field credential wire shape. It creates no new account,
	// prints no value and is removed only if its own inode still occupies name.
	private := map[string]string{"access_key": native.credential.AccessKey, "secret_key": native.credential.SecretKey, "session_token": ""}
	credential, e := ce.Canonical(private)
	delete(private, "access_key")
	delete(private, "secret_key")
	if e != nil {
		return result, e
	}
	defer clear(credential)
	root, e := os.OpenRoot(directory)
	if e != nil {
		return result, e
	}
	defer root.Close()
	name := ".original-inventory-credential.json"
	file := filepath.Join(directory, name)
	secretFile, e := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return result, e
	}
	original, e := secretFile.Stat()
	if e != nil {
		secretFile.Close()
		return result, e
	}
	removed := false
	removeOwned := func() error {
		current, e := root.Lstat(name)
		if e != nil || !os.SameFile(original, current) {
			return install.ErrInstall
		}
		return root.Remove(name)
	}
	defer func() {
		if !removed {
			if e := removeOwned(); e != nil && resultErr == nil {
				resultErr = install.ErrInstall
			}
		}
	}()
	_, writeErr := secretFile.Write(credential)
	syncErr := secretFile.Sync()
	closeErr := secretFile.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return result, install.ErrInstall
	}
	sha := hash(credential)
	scopes, e := originalMinIOCoverageScopes(p, sha)
	if e != nil {
		return result, e
	}
	ca, e := pinnedDeploymentFile(p.grant.Provider.CAFile, p.grant.Provider.CASHA256, 65536)
	if e != nil {
		return result, e
	}
	collection := OriginalMinIOCoverageCollection{Version: "original-minio-live-coverage-source-collection.v1", DefinitionSHA256: definitionSHA, State: "unadmitted_live_native_EOF_not_immutable_not_fenced_not_adopted", Scopes: []OriginalMinIOCoverageSource{}}
	for _, scope := range scopes {
		if e = owner.AuthenticateOriginalCoverageCensus(ctx, password, enrollment, definitionFile, definitionSHA); e != nil {
			return result, e
		}
		census, e := adapter.NewS3CoverageCensus(adapter.S3CoverageCensusConfig{Source: scope.Census.Source, Scope: scope.Census.Scope, CAPEM: ca, CredentialsFile: file})
		if e != nil {
			return result, e
		}
		observed, e := census.Observe(ctx)
		if e != nil {
			return result, e
		}
		scope.Census = observed.Facts()
		if _, _, e = nativeInstallSave(directory, "minio-"+scope.Purpose+".census.json", scope); e != nil {
			return result, e
		}
		collection.Scopes = append(collection.Scopes, scope)
	}
	if e = owner.AuthenticateOriginalCoverageCensus(ctx, password, enrollment, definitionFile, definitionSHA); e != nil {
		return result, e
	}
	if minioPermissionKubernetesCheck(ctx, kube, p) != nil {
		return result, install.ErrInstall
	}
	if _, e = native.collectNativeInstallServer(ctx, p.grant.Profile); e != nil {
		return result, e
	}
	if e = removeOwned(); e != nil {
		return result, e
	}
	removed = true
	result.File, result.SHA256, e = nativeInstallSave(directory, "original-minio-coverage.collection.json", collection)
	return result, e
}
