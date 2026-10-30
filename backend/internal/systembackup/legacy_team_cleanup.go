package systembackup

import (
	"context"
	"database/sql"
	"errors"
	"path"
	"regexp"
	"strings"
)

// Location is supplied by the historical configuration owner. It must be
// mapped by the original job's config hash, never today's bootstrap defaults.
type LegacyRecoveryLocation struct {
	ConfigSHA256   string
	Namespace      string
	RestoreRoot    string
	SourceRoot     string
	SourceDatabase string
	SourceBucket   string
}

var legacyRecoveryNamespace = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type LegacyCleanupCandidate struct {
	Kind             string `json:"kind"`
	Target           string `json:"target"`
	Server           string `json:"server,omitempty"`
	Namespace        string `json:"namespace,omitempty"`
	RequiredRunLabel string `json:"required_run_label"`
	ReceiptState     string `json:"receipt_state"`
	Blocker          string `json:"blocker"`
}
type LegacyCleanupInventory struct {
	LegacyRunID               string                   `json:"legacy_run_id"`
	BackupID                  string                   `json:"backup_id"`
	PublicOperationID         string                   `json:"public_operation_id"`
	OriginalStatus            string                   `json:"original_status"`
	RequiresOriginalExitProof bool                     `json:"requires_original_exit_proof"`
	Candidates                []LegacyCleanupCandidate `json:"candidates"`
}

// ReadLegacyCleanupInventory is read-only. These are candidates for the public
// controller, NOT ownership or exit attestations and never deletion authority.
// D must bind the original executor exit and live resource identity under its
// existing cleanup grant; 404, name matching or an expired lease do not suffice.
func (s Store) ReadLegacyCleanupInventory(ctx context.Context, run, operation string, location LegacyRecoveryLocation) (out LegacyCleanupInventory, err error) {
	if ctx == nil || ctx.Err() != nil {
		return out, errors.New("not_ready")
	}
	if s.DB == nil || s.InstallationID == "" || !publicRecoveryOperation.MatchString(operation) || operation[:4] != "sop_" || !publicIDPattern.MatchString(run) || run[:4] != "sdr_" ||
		!validHash(location.ConfigSHA256) || !legacyRecoveryNamespace.MatchString(location.Namespace) || location.SourceDatabase == "" || location.SourceBucket == "" || !path.IsAbs(location.RestoreRoot) || path.Clean(location.RestoreRoot) != location.RestoreRoot || location.RestoreRoot == "/" ||
		!path.IsAbs(location.SourceRoot) || location.SourceRoot == "/" || path.Clean(location.SourceRoot) != location.SourceRoot ||
		location.RestoreRoot == location.SourceRoot || strings.HasPrefix(location.RestoreRoot, location.SourceRoot+"/") || strings.HasPrefix(location.SourceRoot, location.RestoreRoot+"/") {
		return out, errors.New("validation_failed")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var kind, hash, backup, status string
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT operation,config_hash,COALESCE(source_backup_id,''),status,provisioning_json FROM system_team_data_backup_jobs WHERE public_id=?", run).Scan(&kind, &hash, &backup, &status, &raw)
	if err != nil {
		return out, err
	}
	defer clear(raw)
	if kind != "restore" || hash != location.ConfigSHA256 || !publicIDPattern.MatchString(backup) || backup[:4] != "sbk_" || len(raw) > 1<<20 {
		return out, errors.New("restore_ownership_unproven")
	}
	receipts := map[string]teamDataProvisionReceipt{}
	if len(raw) > 0 && string(raw) != "null" {
		if err = strictDecode(raw, &receipts); err != nil {
			return out, errors.New("restore_ownership_unproven")
		}
	}
	out = LegacyCleanupInventory{LegacyRunID: run, BackupID: backup, PublicOperationID: operation, OriginalStatus: status, RequiresOriginalExitProof: true, Candidates: []LegacyCleanupCandidate{}}
	for kind := range receipts {
		if kind != "database" && kind != "bucket" {
			return LegacyCleanupInventory{}, errors.New("restore_ownership_unproven")
		}
	}
	for _, kind := range []string{"database", "bucket"} {
		receipt, exists := receipts[kind]
		if !exists {
			continue
		}
		candidate := LegacyCleanupCandidate{Kind: kind, Target: receipt.Target, Server: receipt.Server, RequiredRunLabel: run, ReceiptState: receipt.State, Blocker: "live_ownership_and_original_exit_required"}
		switch kind {
		case "database":
			if receipt.Target != teamDataDatabase(run) || receipt.Target == location.SourceDatabase || receipt.Server == "" {
				return LegacyCleanupInventory{}, errors.New("restore_ownership_unproven")
			}
		case "bucket":
			if receipt.Target != teamDataBucket(run) || receipt.Target == location.SourceBucket || receipt.Server != "" {
				return LegacyCleanupInventory{}, errors.New("restore_ownership_unproven")
			}
		default:
			return LegacyCleanupInventory{}, errors.New("restore_ownership_unproven")
		}
		if receipt.State != "created" {
			candidate.Blocker = "creation_result_unconfirmed"
		}
		out.Candidates = append(out.Candidates, candidate)
	}
	// Historical records did not persist immutable Kubernetes/volume UIDs.
	// Preserve that gap explicitly rather than guessing from names or labels.
	out.Candidates = append(out.Candidates, LegacyCleanupCandidate{Kind: "workspace", Target: path.Join(location.RestoreRoot, run), RequiredRunLabel: run, Blocker: "original_volume_identity_required"}, LegacyCleanupCandidate{Kind: "kubernetes", Target: teamDataRedisName(run), Namespace: location.Namespace, RequiredRunLabel: run, Blocker: "original_resource_uid_required"})
	if err = tx.Commit(); err != nil {
		return LegacyCleanupInventory{}, err
	}
	return out, nil
}
