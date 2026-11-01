package systembackupexecution

import (
	"context"
	"database/sql"
	"strings"

	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

type publicationConfigReference struct{ Purpose, Identity, Version string }

func publicationSnapshotReferences(raw []byte, sha string) (map[string]publicationConfigReference, error) {
	values, err := publicationConfigValuesFromSnapshot(raw, sha)
	if err != nil {
		return nil, c.ErrExecutionAuthority
	}
	entries, ok := values["references"].([]any)
	if !ok || len(entries) == 0 || len(entries) > 64 {
		return nil, c.ErrExecutionAuthority
	}
	refs := map[string]publicationConfigReference{}
	for _, entry := range entries {
		value, ok := entry.(map[string]any)
		if !ok || len(value) != 3 {
			return nil, c.ErrExecutionAuthority
		}
		purpose, ok := value["purpose"].(string)
		if !ok || purpose == "" || len(purpose) > 64 {
			return nil, c.ErrExecutionAuthority
		}
		identity, ok := value["identity_hash"].(string)
		if !ok || !formalCandidateDigest(identity) {
			return nil, c.ErrExecutionAuthority
		}
		version, ok := value["version"].(string)
		if !ok || version == "" || len(version) > 128 || version == "current" || version == "latest" || strings.ContainsAny(version, "\x00\r\n") {
			return nil, c.ErrExecutionAuthority
		}
		if _, found := refs[purpose]; found {
			return nil, c.ErrExecutionAuthority
		}
		refs[purpose] = publicationConfigReference{purpose, identity, version}
	}
	return refs, nil
}

// SAME original transaction/installation/task/config snapshot. Current columns
// never become original authority; SQL identifiers come only from this list.
func checkOriginalPublicationReferencesTx(ctx context.Context, tx *sql.Tx, facts security.PublisherCaptureFacts, expected ...publicationConfigReference) error {
	if tx == nil || len(expected) == 0 || len(expected) > 8 {
		return c.ErrExecutionAuthority
	}
	columns := []string{}
	seen := map[string]bool{}
	for _, ref := range expected {
		switch ref.Purpose {
		case "artifact_write", "artifact_read", "artifact_ca", "catalog_read", "catalog_append", "acceptance_signing", "catalog_signing", "capture_signing":
		default:
			return c.ErrExecutionAuthority
		}
		if seen[ref.Purpose] {
			return c.ErrExecutionAuthority
		}
		seen[ref.Purpose] = true
		columns = append(columns, "cfg."+ref.Purpose+"_identity_hash", "cfg."+ref.Purpose+"_ref_version")
	}
	columns = append(columns, "b.config_snapshot_json", "b.config_snapshot_size_bytes", "cfg.config_size_bytes")
	query := "SELECT " + strings.Join(columns, ",") + ` FROM system_backup_v2_configs cfg JOIN system_backup_v2_backups b ON b.origin_installation_id=cfg.origin_installation_id AND b.config_version=cfg.version AND b.config_snapshot_sha256=cfg.config_sha256 WHERE cfg.origin_installation_id=? AND cfg.version=? AND cfg.config_sha256=? AND b.public_id=? FOR SHARE`
	actual := make([]string, 2*len(expected))
	dest := make([]any, 0, len(actual)+3)
	for i := range actual {
		dest = append(dest, &actual[i])
	}
	var raw []byte
	var taskSize, configSize int64
	dest = append(dest, &raw, &taskSize, &configSize)
	if err := tx.QueryRowContext(ctx, query, facts.InstallationID, facts.ConfigVersion, facts.ConfigSHA256, facts.BackupPublicID).Scan(dest...); err != nil {
		return c.ErrExecutionAuthority
	}
	defer clear(raw)
	if taskSize != int64(len(raw)) || configSize != taskSize {
		return c.ErrExecutionAuthority
	}
	original, err := publicationSnapshotReferences(raw, facts.ConfigSHA256)
	if err != nil {
		return err
	}
	for i, ref := range expected {
		got, found := original[ref.Purpose]
		if !found || got != ref || actual[2*i] != ref.Identity || actual[2*i+1] != ref.Version {
			return c.ErrExecutionAuthority
		}
	}
	return nil
}
