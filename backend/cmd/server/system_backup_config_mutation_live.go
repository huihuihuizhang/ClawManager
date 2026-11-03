package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"

	materials "clawreef/internal/systembackupbootstrapmaterials"
	registry "clawreef/internal/systembackupbootstrapsecurity"
	ca "clawreef/internal/systembackupcatrust"
	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
	nonce "clawreef/internal/systembackupnoncebootstrap"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/gin-gonic/gin"
)

const backupMutationCompositionVersion = "original-first-enable-production-composition.v1"

// Private independently pinned source locators and original binding data only.
// Every constructor below is concrete; no interface, grant or Passed field is
// deserialized. Actual source authentication/native/SQL checks run per attempt.
type backupMutationComposition struct {
	Version                                                      string
	CaptureSourceFile, CaptureSourcePinFile, CaptureSourceSHA256 string
	RegistryDirectory, NonceDirectory, CapacityReportFile        string
	LargeSmokeBytes                                              int64
	Terminal                                                     install.BootstrapTerminalFiles
	Classification                                               install.FunctionalClassificationFiles
	StatusRelay                                                  install.StatusRelayReferenceFiles
	SixReferences                                                install.SixReferenceFiles
	SourceRegistries                                             install.BootstrapSourceRegistryFiles
	SourceNativeRegistries                                       execution.BootstrapSourceNativeRegistryFiles
	Catalog                                                      execution.CatalogInitialInventoryTerminalInput
	Signing                                                      install.OriginalSignerMutationSourceFiles
	KEKFile, KEKSHA256                                           string
	Nonce                                                        nonce.Binding
	ArtifactCA, EvidenceCA                                       ca.Binding
}

func loadBackupConfigMutationProduction(db *sql.DB, database, secret string, getenv func(string) string) (*sec.ConfigMutationProduction, error) {
	if getenv == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	switch getenv("SYSTEM_BACKUP_CONFIG_MUTATION_ENABLED") {
	case "", "false":
		return nil, nil
	case "true":
	default:
		return nil, sec.ErrRegistrationUnavailable
	}
	if db == nil || getenv("SYSTEM_BACKUP_READ_SESSIONS_ENABLED") != "true" || getenv("SYSTEM_BACKUP_READ_LIVE_ENABLED") != "true" || len(secret) < 32 {
		return nil, sec.ErrRegistrationUnavailable
	}
	file, pin := getenv("SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_FILE"), getenv("SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_SHA256")
	raw, e := install.ReadPrivateFile(file, 262144)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != pin {
		return nil, sec.ErrRegistrationUnavailable
	}
	canonical, e := jsoncanonicalizer.Transform(raw)
	if e != nil || !bytes.Equal(raw, canonical) {
		return nil, sec.ErrRegistrationUnavailable
	}
	var d backupMutationComposition
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || decoder.Decode(new(any)) != io.EOF || d.Version != backupMutationCompositionVersion || d.RegistryDirectory != d.Terminal.RegistryDirectory || d.RegistryDirectory != d.Classification.RegistryDirectory || d.CaptureSourceFile != d.Signing.CaptureSourceFile || d.CaptureSourcePinFile != d.Signing.CaptureSourcePinFile || d.CaptureSourceSHA256 != d.Signing.CaptureSourceSHA256 {
		return nil, sec.ErrRegistrationUnavailable
	}
	sourceRaw, e := install.ReadPrivateFile(d.CaptureSourceFile, 262144)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	sourceSum := sha256.Sum256(sourceRaw)
	sourcePin, e := install.ReadPrivateFile(d.CaptureSourcePinFile, 64)
	if e != nil || hex.EncodeToString(sourceSum[:]) != d.CaptureSourceSHA256 || string(sourcePin) != d.CaptureSourceSHA256 {
		return nil, sec.ErrRegistrationUnavailable
	}
	identity := sec.DatabaseIdentity{ServerUUID: getenv("SYSTEM_BACKUP_READ_SESSIONS_SERVER_UUID"), Database: database}
	installation := getenv("SYSTEM_BACKUP_REGISTRATION_INSTALLATION_ID")
	capture := install.NewCaptureSigningConsumer(d.CaptureSourceFile, d.CaptureSourcePinFile)
	artifact, e := ca.New(d.ArtifactCA)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	evidence, e := ca.New(d.EvidenceCA)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	nonces, e := nonce.New(d.Nonce)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	security, e := materials.NewEnableOnlySecurityOwners(capture, d.Terminal, artifact, evidence, nonces, registry.NewIssuers(d.RegistryDirectory))
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	relations, e := install.NewOriginalRelationEnableOnlyMutation(capture, install.EnableOnlyRelationFiles{Classification: d.Classification, StatusRelay: d.StatusRelay, Terminal: d.Terminal})
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	sixOriginal, e := install.NewOriginalSixReference(capture, d.SixReferences)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	six, e := install.NewSixReferenceEnableOnlyMutation(sixOriginal)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	sourceOriginal, e := execution.NewBootstrapSourceRegistryTerminalResourceWithNativeRegistries(capture, d.SourceRegistries, d.SourceNativeRegistries)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	sources, e := execution.NewBootstrapSourceRegistryEnableOnlyMutation(sourceOriginal, d.Terminal)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	kube, e := capture.OpenTerminalKubernetes(ctx)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	minio, e := execution.NewOriginalMinIOConfigMutationReferences(db, kube, d.Catalog)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	signers, e := install.NewOriginalSignerConfigMutationReferences(db, d.Signing)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	kek, e := materials.LoadOriginalSQLMutationKEKResource(db, d.KEKFile, d.KEKSHA256)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	deployment, e := sec.NewProcessDeploymentSwitch(installation, identity)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	r := sec.ConfigMutationResolverSources{Registries: map[string]sec.ConfigMutationResourceValidator{}, References: map[string]sec.ConfigMutationResourceValidator{}, CrossResources: relations.CrossResources(), Deployment: deployment.Observe}
	merge := func(to map[string]sec.ConfigMutationResourceValidator, from map[string]sec.ConfigMutationResourceValidator) error {
		for k, v := range from {
			if _, found := to[k]; found || v == nil {
				return sec.ErrRegistrationUnavailable
			}
			to[k] = v
		}
		return nil
	}
	for _, group := range []map[string]sec.ConfigMutationResourceValidator{security.Registries(), relations.Registries(), {"parts": sources, "source_writers": sources, "redis_sources": sources, "secret_allowlist": sources}} {
		if merge(r.Registries, group) != nil {
			return nil, sec.ErrRegistrationUnavailable
		}
	}
	sixRefs := map[string]sec.ConfigMutationResourceValidator{}
	for _, key := range sixOriginal.TerminalKeys() {
		sixRefs[strings.TrimPrefix(key, "reference:")] = six
	}
	for _, group := range []map[string]sec.ConfigMutationResourceValidator{security.References(), relations.References(), sixRefs, minio.References(), signers.References(), {"kek": kek}} {
		if merge(r.References, group) != nil {
			return nil, sec.ErrRegistrationUnavailable
		}
	}
	if len(r.Registries) != 9 || len(r.References) != 20 || len(sec.MissingConfigMutationProductionOwners(r)) != 0 {
		return nil, sec.ErrRegistrationUnavailable
	}
	return sec.NewConfigMutationProduction(sec.ConfigMutationProductionConfig{DB: db, Database: identity, InstallationID: installation, SessionSecret: []byte(secret), RegistryDirectory: d.RegistryDirectory, NonceDirectory: d.NonceDirectory, CapacityReportFile: d.CapacityReportFile, LargeSmokeBytes: d.LargeSmokeBytes, Resources: r})
}

func registerBackupConfigMutationLive(admin *gin.RouterGroup, production *sec.ConfigMutationProduction) {
	if admin == nil || production == nil {
		return
	}
	handler := func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 90*time.Second)
		defer cancel()
		production.ServeHTTP(c.Writer, c.Request.WithContext(ctx))
	}
	admin.PUT("/system-backup-config", handler)
	admin.POST("/system-backup-config/rollback", handler)
}
