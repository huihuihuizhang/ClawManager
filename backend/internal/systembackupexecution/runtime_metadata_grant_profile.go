package systembackupexecution

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"time"

	c "clawreef/internal/systembackupcontroller"
	ma "clawreef/internal/systembackupminioauthority"
)

// Runs also during database admission before Runtime/Kube factories exist.
// Consent/actual SQL/Forward signature verification selects a privilege matrix;
// this never creates the opaque native metadata-read authority used by tasks.
func (s *DeploymentService) checkRuntimeMetadataGrantProfile(ctx context.Context, db *sql.DB) (bool, error) {
	file, sha := os.Getenv("SYSTEM_BACKUP_MINIO_RUNTIME_METADATA_SOURCE_FILE"), os.Getenv("SYSTEM_BACKUP_MINIO_RUNTIME_METADATA_SOURCE_SHA256")
	if file == "" && sha == "" {
		return false, nil
	}
	if s == nil || !s.ForwardEnabled || s.Forward == nil || db == nil || s.Config.RuntimeSources == nil || s.captureMaterials == nil || s.captureMaterials.ControlEvidence == nil || s.formalVerifier == nil || s.formalVerifier.ProviderPermits == nil || s.Config.PublicationTarget == nil || s.metadataControllerPodName == "" {
		return false, c.ErrExecutionAuthority
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	input := MinIORecoveryProjectionInput{File: os.Getenv("SYSTEM_BACKUP_MINIO_RECOVERY_SOURCE_FILE"), SHA256: os.Getenv("SYSTEM_BACKUP_MINIO_RECOVERY_SOURCE_SHA256")}
	d, e := readMinIORecoveryDescriptor(input)
	if e != nil || d.Pin.Target.InstallationID != s.Config.InstallationID || d.Pin.Target.Namespace != s.Config.Namespace || d.Pin.Target.NamespaceUID != s.Config.NamespaceUID {
		return false, c.ErrExecutionAuthority
	}
	source := ma.RuntimeMetadataConsentSource{File: file, SHA256: sha, OriginalForwardFile: os.Getenv("SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT_FILE"), OriginalForwardSHA256: os.Getenv("SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT_SHA256")}
	view, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return false, e
	}
	consent, e := ma.VerifyRuntimeMetadataProfileConsent(ctx, view, d, ma.Digest(input.SHA256), source, s.Forward)
	closed := view.Rollback()
	if e != nil || closed != nil || consent.Workload.Pod.Name != s.metadataControllerPodName {
		return false, c.ErrExecutionAuthority
	}
	g := s.Forward.DeploymentBinding()
	if consent.RuntimeDatabaseAccount != g.DatabaseAccount {
		return false, c.ErrExecutionAuthority
	}
	if (c.SQLMinIOMetadataReadGrantProbe{DB: db, Schema: g.Database, User: strings.Split(g.DatabaseAccount, "@")[0], Runtime: true, ProviderPermits: true, Publication: true}).Check(ctx) != nil {
		return false, c.ErrExecutionAuthority
	}
	return true, nil
}
