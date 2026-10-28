package publicadapter

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	d "clawreef/internal/systembackupdispatch"
	"k8s.io/apimachinery/pkg/util/validation"
)

// RestoreTarget is B's proposed OBSERVED isolated-drill descriptor. It contains
// no DSN, Secret value, arbitrary filesystem path or authority bit. It is not a
// new create-request DTO. D/A must close its embedding and current proof policy
// before a target profile can consume it. Real migration is not enabled here.
type RestoreTarget struct {
	SchemaVersion      string           `json:"schema_version"`
	Kind               string           `json:"kind"`
	InstallationID     string           `json:"installation_id"`
	MatrixKey          string           `json:"matrix_key"`
	Namespace          string           `json:"namespace"`
	NamespaceUID       string           `json:"namespace_uid"`
	DatabaseName       string           `json:"database_name"`
	DatabaseServerUUID string           `json:"database_server_uuid"`
	SchemaSHA256       string           `json:"schema_sha256"`
	AdminPolicy        string           `json:"admin_policy"`
	StartPolicy        string           `json:"start_policy"`
	IsolationEvidence  RelayEvidence    `json:"isolation_evidence"`
	Storage            []RestoreStorage `json:"storage"`
}
type RestoreStorage struct {
	SourceMountSHA256 string        `json:"source_mount_sha256"`
	Kind              string        `json:"kind"`
	ClaimName         string        `json:"claim_name"`
	ClaimUID          string        `json:"claim_uid"`
	PVUID             string        `json:"pv_uid"`
	NodeName          string        `json:"node_name"`
	WriterProof       RelayEvidence `json:"writer_proof"`
}

var drillDB = regexp.MustCompile(`^cm_drill_[a-z0-9_]{1,55}$`)
var restoreTask = regexp.MustCompile(`^(spf|sdr)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var databaseID = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type SourceDatabase struct{ Name, ServerUUID string }

// RestoreTargetProof must use the original A/D scope, independent current SQL
// observer/cluster identity and DB clock. It proves admin-only blank target,
// isolation, all target resource identities, current grants and writer proofs.
// Structural validation alone grants no permission to restore or provision.
type RestoreTargetProof interface {
	VerifyRestoreTarget(context.Context, d.Authority, RestoreTarget) error
}

func CheckRestoreTarget(ctx context.Context, a d.Authority, target RestoreTarget, source SourceDatabase, proof RestoreTargetProof) error {
	if ctx == nil || ctx.Err() != nil || nilValue(proof) || !uuid.MatchString(source.ServerUUID) || !databaseID.MatchString(source.Name) {
		return d.ErrNotReady
	}
	if !restoreTask.MatchString(a.TaskPublicID) || a.ClaimOwner == "" || a.ClaimRowVersion == 0 || a.AttemptNo == 0 || a.ConfigVersion == 0 || !hexHash.MatchString(a.ConfigSHA256) {
		return d.ErrNotReady
	}
	if !time.Now().Before(a.DeadlineAt) {
		return &Failure{"deadline_exceeded"}
	}
	if (a.TaskType != "preflight" || a.TaskPublicID[:4] != "spf_" || a.Phase != "preflight") && (a.TaskType != "drill" || a.TaskPublicID[:4] != "sdr_" || (a.Phase != "restore" && a.Phase != "normalize" && a.Phase != "verify")) {
		return d.ErrNotReady
	}
	if err := validateRestoreTarget(a, target, source); err != nil {
		return err
	}
	// Copy through the closed decoder so an owner callback cannot mutate caller
	// slices or change the target after it was bound by the controller.
	raw, err := json.Marshal(target)
	if err != nil {
		return d.ErrNotReady
	}
	var detached RestoreTarget
	if decodeStrict(raw, &detached) != nil {
		return d.ErrNotReady
	}
	if err := proof.VerifyRestoreTarget(ctx, a, detached); err != nil {
		return classify(err)
	}
	if err := ctx.Err(); err != nil {
		return classify(err)
	}
	if !time.Now().Before(a.DeadlineAt) {
		return &Failure{"deadline_exceeded"}
	}
	return nil
}

func validateRestoreTarget(a d.Authority, t RestoreTarget, source SourceDatabase) error {
	if t.SchemaVersion != "system-backup-b-restore-target.v1" || t.Kind != "isolated_drill" || !installation.MatchString(t.InstallationID) || t.InstallationID != a.InstallationID || !strings.HasPrefix(t.Namespace, "cm-drill-") || len(validation.IsDNS1123Label(t.Namespace)) != 0 || !uuid.MatchString(t.NamespaceUID) || !drillDB.MatchString(t.DatabaseName) || !uuid.MatchString(t.DatabaseServerUUID) || (t.DatabaseServerUUID == source.ServerUUID && strings.EqualFold(t.DatabaseName, source.Name)) || !hexHash.MatchString(t.SchemaSHA256) || t.AdminPolicy != "replace_bootstrap_with_source_admin" || t.StartPolicy != "stopped_tasks_disabled" || !evidenceID.MatchString(t.IsolationEvidence.PublicID) || !hexHash.MatchString(t.IsolationEvidence.SHA256) || t.Storage == nil || len(t.Storage) > 10000 {
		return &Failure{"isolation_invalid"}
	}
	switch t.MatrixKey {
	case "k8s-cluster", "k3s-cluster", "k8s-single-node", "k3s-single-node":
	default:
		return &Failure{"isolation_invalid"}
	}
	seen, claims := map[string]bool{}, map[string]bool{}
	for _, s := range t.Storage {
		if !hexHash.MatchString(s.SourceMountSHA256) || seen[s.SourceMountSHA256] || len(validation.IsDNS1123Subdomain(s.ClaimName)) != 0 || !uuid.MatchString(s.ClaimUID) || !uuid.MatchString(s.PVUID) || claims[s.ClaimUID] || !evidenceID.MatchString(s.WriterProof.PublicID) || !hexHash.MatchString(s.WriterProof.SHA256) {
			return &Failure{"isolation_invalid"}
		}
		switch s.Kind {
		case "csi", "nfs":
		case "hostpath":
			if s.NodeName == "" {
				return &Failure{"isolation_invalid"}
			}
		default:
			return &Failure{"isolation_invalid"}
		}
		if s.NodeName != "" && len(validation.IsDNS1123Subdomain(s.NodeName)) != 0 {
			return &Failure{"isolation_invalid"}
		}
		seen[s.SourceMountSHA256], claims[s.ClaimUID] = true, true
	}
	return nil
}
