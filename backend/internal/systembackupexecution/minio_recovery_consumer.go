package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"reflect"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	ma "clawreef/internal/systembackupminioauthority"
	sec "clawreef/internal/systembackupsecurity"
	"k8s.io/client-go/kubernetes"
)

// Trusted deployment descriptor locator, installed before capture. No file
// hash is accepted from a projection/task/HTTP request. The future signed
// projection is selected by a fixed path inside this descriptor.
type MinIORecoveryProjectionInput struct{ File, SHA256 string }

type minioRecoverySession struct {
	metadata   *ma.VerifiedRuntimeMetadataRead
	input      MinIORecoveryProjectionInput
	descriptor ma.MinIORecoveryDescriptor
	wire       []byte
	proof      *ma.VerifiedMinIORecoveryProjection
	expected   ma.SQLExpected
	until      time.Time
}

func readMinIORecoveryDescriptor(in MinIORecoveryProjectionInput) (ma.MinIORecoveryDescriptor, error) {
	raw, e := pinnedDeploymentFile(in.File, in.SHA256, 65536)
	if e != nil {
		return ma.MinIORecoveryDescriptor{}, e
	}
	d, e := ma.DecodeMinIORecoveryDescriptor(raw)
	if e != nil {
		return ma.MinIORecoveryDescriptor{}, minioPermissionFailure("recovery-original-descriptor")
	}
	return d, nil
}

// The original independently installed SQL actor is locked before head/grant.
// This helper has no provider/network/filesystem capability.
func lockMinIORecoveryActor(ctx context.Context, tx *sql.Tx, actor ma.Actor) error {
	var username, role, provider string
	var active bool
	if tx == nil || actor.LocalAdminUserID < 1 || tx.QueryRowContext(ctx, `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE`, actor.LocalAdminUserID).Scan(&username, &role, &active, &provider) != nil || username != actor.LocalAdminUsername || role != "admin" || !active || provider != "local" {
		return minioPermissionFailure("recovery-original-admin")
	}
	return nil
}

func prepareMinIORecoverySession(ctx context.Context, db *sql.DB, in *MinIORecoveryProjectionInput, permission MinIOPublicationPermissionInput) (*minioRecoverySession, error) {
	return prepareMinIORecoverySessionSelected(ctx, db, in, permission, nil)
}
func prepareMinIORuntimeRecoverySession(ctx context.Context, s *DeploymentService, in *MinIORecoveryProjectionInput, permission MinIOPublicationPermissionInput) (*minioRecoverySession, error) {
	if s == nil {
		return nil, minioPermissionFailure("runtime-metadata-service")
	}
	return prepareMinIORecoverySessionSelected(ctx, s.publisherVerifierDB, in, permission, s)
}
func prepareMinIORecoverySessionSelected(ctx context.Context, db *sql.DB, in *MinIORecoveryProjectionInput, permission MinIOPublicationPermissionInput, runtime *DeploymentService) (*minioRecoverySession, error) {
	if in == nil {
		return nil, nil
	}
	if db == nil {
		return nil, minioPermissionFailure("recovery-original-sql-reader")
	}
	d, e := readMinIORecoveryDescriptor(*in)
	if e != nil || d.PermissionSourceFile != permission.File || string(d.PermissionSourceSHA256) != permission.SHA256 {
		return nil, minioPermissionFailure("recovery-source-selection")
	}
	wire, e := install.ReadPrivateFile(d.ProjectionFile, 65536)
	if e != nil {
		return nil, minioPermissionFailure("recovery-source-missing")
	}
	var metadata *ma.VerifiedRuntimeMetadataRead
	if runtime != nil {
		if runtime.Forward == nil || runtime.Runtime == nil || runtime.Runtime.Owner == nil {
			return nil, minioPermissionFailure("runtime-metadata-original-composition")
		}
		source := ma.RuntimeMetadataConsentSource{File: os.Getenv("SYSTEM_BACKUP_MINIO_RUNTIME_METADATA_SOURCE_FILE"), SHA256: os.Getenv("SYSTEM_BACKUP_MINIO_RUNTIME_METADATA_SOURCE_SHA256"), OriginalForwardFile: os.Getenv("SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT_FILE"), OriginalForwardSHA256: os.Getenv("SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT_SHA256")}
		metadata, e = ma.PrepareRuntimeMetadataRead(ctx, runtime.Runtime.Owner.Client, d, ma.Digest(in.SHA256), source, runtime.Forward)
		if e != nil {
			return nil, e
		}
	}
	tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var current *ma.SQLCurrentSnapshot
	if metadata == nil {
		if lockMinIORecoveryActor(ctx, tx, d.Actor) != nil {
			return nil, minioPermissionFailure("recovery-original-admin-prefix")
		}
		current, e = ma.ReadSQLCurrent(ctx, tx, d.Pin)
	} else {
		current, _, e = ma.ReadSQLCurrentForOriginalRuntimeMetadata(ctx, tx, d.Pin, metadata)
	}
	if e != nil {
		return nil, e
	}
	expected, now, e := current.Comparison()
	if e != nil {
		return nil, e
	}
	proof, e := ma.VerifyMinIORecoveryProjection(wire, d, current, now)
	if e != nil {
		return nil, e
	}
	record, e := proof.Record()
	if e != nil || tx.Rollback() != nil {
		return nil, minioPermissionFailure("recovery-original-readback")
	}
	s := &minioRecoverySession{metadata: metadata, input: *in, descriptor: d, wire: bytes.Clone(wire), proof: proof, expected: expected, until: record.Until}
	if s.local() != nil {
		return nil, minioPermissionFailure("recovery-source-tail")
	}
	return s, nil
}

func (s *minioRecoverySession) local() error {
	if s == nil {
		return nil
	}
	if s.metadata != nil && s.metadata.CheckLocal() != nil {
		return minioPermissionFailure("runtime-metadata-original-local")
	}
	if !time.Now().Before(s.until) {
		return minioPermissionFailure("recovery-original-until")
	}
	d, e := readMinIORecoveryDescriptor(s.input)
	if e != nil || !reflect.DeepEqual(d, s.descriptor) {
		return minioPermissionFailure("recovery-descriptor-drift")
	}
	wire, e := install.ReadPrivateFile(d.ProjectionFile, 65536)
	if e != nil || !bytes.Equal(wire, s.wire) || s.proof == nil || !s.proof.Matches(wire) {
		return minioPermissionFailure("recovery-projection-drift")
	}
	return nil
}

func sameMinIORecoverySession(a, b *minioRecoverySession) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if (a.metadata == nil) != (b.metadata == nil) {
		return false
	}
	if a.metadata != nil {
		left, e := a.metadata.Fingerprint()
		right, re := b.metadata.Fingerprint()
		if e != nil || re != nil || left != right {
			return false
		}
	}
	return a.input == b.input && reflect.DeepEqual(a.descriptor, b.descriptor) && reflect.DeepEqual(a.expected, b.expected) && bytes.Equal(a.wire, b.wire) && a.until.Equal(b.until)
}

func (s *DeploymentService) readOriginalMinIOEnableLineage(ctx context.Context, recovery *minioRecoverySession, oldSHA string, version uint64, currentSHA string) (string, error) {
	if oldSHA == currentSHA {
		return "", nil
	}
	if recovery == nil || version != 2 || s == nil || s.publisherVerifierDB == nil {
		return "", minioPermissionFailure("original-config-lineage-missing")
	}
	tx, e := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	if recovery.metadata != nil {
		actual, fingerprint, e := ma.ReadSQLCurrentForOriginalRuntimeMetadata(ctx, tx, recovery.descriptor.Pin, recovery.metadata)
		if e != nil {
			return "", e
		}
		g, _, _, e := actual.Declarations()
		current := s.Forward.DeploymentBinding()
		_, now, ce := actual.Comparison()
		if e != nil || ce != nil || g.ConfigSHA256 != ma.Digest(oldSHA) || current.ConfigVersion != version || current.ConfigSHA256 != currentSHA || fingerprint == "" || recovery.recheck(actual, now) != nil {
			return "", minioPermissionFailure("runtime-metadata-lineage")
		}
		if tx.Rollback() != nil {
			return "", minioPermissionFailure("runtime-metadata-view-close")
		}
		return fingerprint, nil
	}
	if lockMinIORecoveryActor(ctx, tx, recovery.descriptor.Actor) != nil {
		return "", minioPermissionFailure("original-lineage-admin-prefix")
	}
	lineage, e := sec.ReadOriginalEnabledOnlyLineage(ctx, tx, s.Config.InstallationID, oldSHA, version, currentSHA)
	if e != nil {
		return "", e
	}
	actual, e := ma.ReadSQLCurrent(ctx, tx, recovery.descriptor.Pin)
	if e != nil {
		return "", e
	}
	g, _, _, e := actual.Declarations()
	_, now, ce := actual.Comparison()
	actor, ae := lineage.ActorID()
	if e != nil || ce != nil || ae != nil || g.ConfigSHA256 != ma.Digest(oldSHA) || g.Actor.LocalAdminUserID != actor || recovery.recheck(actual, now) != nil {
		return "", minioPermissionFailure("original-lineage-sql-source")
	}
	authSHA, e := lineage.AuthorizationConfigSHA256(ctx, tx)
	if e != nil || authSHA != oldSHA || !lineage.Matches(s.Config.InstallationID, oldSHA, version, currentSHA) {
		return "", minioPermissionFailure("original-lineage-scope")
	}
	fingerprint, e := lineage.Fingerprint()
	if e != nil || tx.Rollback() != nil {
		return "", minioPermissionFailure("original-lineage-readback")
	}
	return fingerprint, nil
}
func (s *minioRecoverySession) recheck(current *ma.SQLCurrentSnapshot, now time.Time) error {
	if s == nil {
		return nil
	}
	if s.local() != nil || !now.Before(s.until) {
		return minioPermissionFailure("recovery-window")
	}
	proof, e := ma.VerifyMinIORecoveryProjection(s.wire, s.descriptor, current, now)
	if e != nil {
		return e
	}
	a, _ := proof.SHA256()
	b, _ := s.proof.SHA256()
	if a != b {
		return minioPermissionFailure("recovery-original-change")
	}
	return nil
}

// The old provider/identity/ref source remains unchanged. Only this dedicated
// live-Kubernetes read uses the independently verified new incarnation. Native
// HTTP account/policy/TLS checks continue using the original endpoint/CA/refset.
func minioCurrentRecoveryResources(ctx context.Context, k kubernetes.Interface, cfg minioPermissionConfiguration, p minioPermissionProvider, s *minioRecoverySession) (string, error) {
	if s == nil {
		return minioPermissionKubernetes(ctx, k, cfg, p)
	}
	if s.local() != nil {
		return "", minioPermissionFailure("recovery-original-local")
	}
	r, e := s.proof.Record()
	if e != nil {
		return "", e
	}
	original := r.OriginalProvider
	if cfg.Installation != r.Target.InstallationID || cfg.Namespace != r.Target.Namespace || cfg.NamespaceUID != r.Target.NamespaceUID || !bytes.Equal(cfg.Issuer, s.descriptor.Pin.IssuerPublic) || cfg.GrantSHA256 != string(originalPermissionGrantSHA(r)) || p.Endpoint != original.Endpoint || p.Region != original.Region || p.CASHA256 != string(original.CASHA256) || p.SPKISHA256 != string(original.SPKISHA256) || p.DeploymentID != original.DeploymentID || p.Deployment != (minioPermissionObject{original.Deployment.Name, original.Deployment.UID}) || p.ReplicaSet != (minioPermissionObject{original.ReplicaSet.Name, original.ReplicaSet.UID}) || p.Pod != (minioPermissionObject{original.Pod.Name, original.Pod.UID}) || p.Service != (minioPermissionObject{original.Service.Name, original.Service.UID}) || p.ServiceAccount != (minioPermissionObject{original.ServiceAccount.Name, original.ServiceAccount.UID}) || p.Container != original.Container || p.ImageID != original.ImageID || p.Node != original.Node || p.NodeUID != original.NodeUID {
		return "", minioPermissionFailure("recovery-original-provider-binding")
	}
	live := p
	live.Pod = minioPermissionObject{r.Transition.NewPod.Name, r.Transition.NewPod.UID}
	first, e := minioPermissionKubernetes(ctx, k, cfg, live)
	if e != nil {
		return "", e
	}
	actual, e := ma.CollectMinIORecoveryResources(ctx, k, r.Target, original, r.Transition.NewPod, r.Transition.NewContainerID)
	if e != nil || s.proof.CompareCurrentResources(actual) != nil || s.local() != nil {
		return "", minioPermissionFailure("recovery-current-native-resource")
	}
	wire, e := ce.Canonical(struct {
		Current   string
		Resources ma.MinIORecoveryResources
	}{first, actual})
	if e != nil {
		return "", e
	}
	return hash(wire), nil
}

// This is taken from the independently verified SQL declaration, not a new
// identity calculated from the successor Pod. Filled by the signed record.
func originalPermissionGrantSHA(r ma.MinIORecoveryProjection) ma.Digest {
	return r.PermissionGrantSHA256
}

func observeOriginalMinIOPermissionsRecovered(ctx context.Context, k kubernetes.Interface, file, sha string, s *minioRecoverySession) (MinIOOriginalPermissionObservation, error) {
	p, e := readMinIOPermissionProductionInputs(file, sha)
	if e != nil {
		return MinIOOriginalPermissionObservation{}, e
	}
	defer p.clear()
	if s != nil && (s.descriptor.DefinitionSHA256 != ma.Digest(sha) || s.local() != nil) {
		return MinIOOriginalPermissionObservation{}, minioPermissionFailure("recovery-original-definition")
	}
	observed, e := observeOriginalMinIOPermissionsWithRecovery(ctx, k, p, sha, s)
	if e != nil {
		return MinIOOriginalPermissionObservation{}, e
	}
	last, e := readMinIOPermissionProductionInputs(file, sha)
	if e != nil {
		return MinIOOriginalPermissionObservation{}, e
	}
	last.clear()
	return observed, nil
}

func (r *OriginalCatalogInitialInventory) observeRecovery(ctx context.Context, s *minioRecoverySession) error {
	if s == nil {
		return r.observe(ctx)
	}
	p, e := readMinIOPermissionProductionInputs(r.base.input.DefinitionFile, r.base.input.DefinitionSHA256)
	if e != nil {
		return e
	}
	defer p.clear()
	first, e := minioCurrentRecoveryResources(ctx, r.base.kube, p.configuration, p.grant.Provider, s)
	if e != nil {
		return e
	}
	if e = r.observe(ctx); e != nil {
		return e
	} // exact original immutable inventory GETs
	last, e := minioCurrentRecoveryResources(ctx, r.base.kube, p.configuration, p.grant.Provider, s)
	if e != nil || first != last {
		return minioPermissionFailure("recovery-inventory-resource-tail")
	}
	return nil
}
