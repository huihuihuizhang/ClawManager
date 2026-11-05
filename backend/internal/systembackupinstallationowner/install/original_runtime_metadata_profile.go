package install

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"strings"

	c "clawreef/internal/systembackupcontroller"
	ma "clawreef/internal/systembackupminioauthority"
)

// Trusted original-owner/deployment environment, never an HTTP request flag.
// Valid consent permits the dedicated exact profile; old base remains exact.
func (i *Installer) originalRuntimeMetadataProfile(ctx context.Context, db *sql.DB, account string) (bool, error) {
	file, sha := os.Getenv("SYSTEM_BACKUP_MINIO_RUNTIME_METADATA_SOURCE_FILE"), os.Getenv("SYSTEM_BACKUP_MINIO_RUNTIME_METADATA_SOURCE_SHA256")
	if file == "" && sha == "" {
		return false, nil
	}
	source := ma.RuntimeMetadataConsentSource{File: file, SHA256: sha, OriginalForwardFile: os.Getenv("SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT_FILE"), OriginalForwardSHA256: os.Getenv("SYSTEM_BACKUP_ORIGINAL_FORWARD_GRANT_SHA256")}
	descriptorPin := BootstrapSourceFilePin{File: os.Getenv("SYSTEM_BACKUP_MINIO_RECOVERY_SOURCE_FILE"), SHA256: os.Getenv("SYSTEM_BACKUP_MINIO_RECOVERY_SOURCE_SHA256")}
	raw, e := readBootstrapSourcePin(descriptorPin, 65536)
	if e != nil {
		return false, ErrInstall
	}
	d, e := ma.DecodeMinIORecoveryDescriptor(raw)
	target := i.plan.Target
	if e != nil || !bytes.Equal(d.Pin.IssuerPublic, i.public) || d.Pin.Enrollment.PlanSHA256 != ma.Digest(i.planHash) || d.Pin.Enrollment.ID != i.plan.EnrollmentID || d.Pin.Target.InstallationID != target.InstallationID || d.Pin.Target.ServerUUID != target.ServerUUID || d.Pin.Target.Database != target.Database || d.Pin.Target.ConsumerDatabaseAccount != target.DatabaseAccount || d.Pin.Target.Namespace != target.Namespace || d.Pin.Target.NamespaceUID != target.NamespaceUID {
		return false, ErrInstall
	}
	view, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return false, ErrInstall
	}
	consent, e := ma.VerifyRuntimeMetadataProfileConsent(ctx, view, d, ma.Digest(descriptorPin.SHA256), source, nil)
	closed := view.Rollback()
	if e != nil || closed != nil || consent.RuntimeDatabaseAccount != account {
		return false, ErrInstall
	}
	actual, e := ma.CollectRuntimeMetadataWorkload(ctx, i.kube, d.Pin.Target, consent.Workload.Deployment.Name, consent.Workload.Pod.Name, consent.Workload.ControllerOwner)
	if e != nil || actual != consent.Workload {
		return false, ErrInstall
	}
	if (c.SQLMinIOMetadataReadGrantProbe{DB: db, Schema: target.Database, User: strings.Split(account, "@")[0], Runtime: true, ProviderPermits: true, Publication: true}).Check(ctx) == nil {
		return true, nil
	}
	// Before SQL enrollment, the independently read-back consent can coexist
	// only with the exact old base profile. Caller verifies that exact matrix.
	return false, nil
}
