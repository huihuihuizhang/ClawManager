package systembackupread

import "encoding/json"

// AdmissionConfig is read inside the already-authorized submission transaction.
// The original canonical bytes and materialized SQL fields must agree. This
// function opens no transaction and never commits or authorizes a mutation.
type AdmissionConfig struct {
	Version   uint64
	SHA256    string
	Canonical json.RawMessage
	Values    ConfigResourceDTO
}

type AdmissionRow interface{ Scan(...any) error }

func ReadAdmissionConfig(query func(string, ...any) AdmissionRow, installation string) (AdmissionConfig, error) {
	return ReadControlConfig(query, installation, true)
}

// Recovery operations may read an explicitly disabled config. Disabling new
// work must not hide the pinned control budget needed to cancel unstarted work.
func ReadControlConfig(query func(string, ...any) AdmissionRow, installation string, requireEnabled bool) (AdmissionConfig, error) {
	const prefix = `SELECT c.schema_version,c.origin_installation_id,c.version,c.row_version,
c.config_sha256,c.config_size_bytes,c.canonical_config_json,c.created_by,c.change_reason,c.created_at,
s.active_config_version,s.last_effective_enabled,`
	row, err := scanConfigSnapshot(query(prefix+configMaterializedSelect()+`
FROM system_backup_v2_installation_state s JOIN system_backup_v2_configs c
ON c.origin_installation_id=s.origin_installation_id AND c.version=s.active_config_version
WHERE s.origin_installation_id=? FOR UPDATE`, installation), installation)
	if err != nil {
		return AdmissionConfig{}, ErrUnavailable
	}
	dto, err := ProjectConfigResource(row)
	if err != nil || !dto.Active || requireEnabled && !dto.EffectiveEnabled {
		return AdmissionConfig{}, ErrUnavailable
	}
	return AdmissionConfig{row.version, row.configSHA256, append(json.RawMessage(nil), row.canonical...), dto}, nil
}

func SubmissionOperationColumns() string { return operationProjectionColumns }
func ScanSubmissionOperation(row AdmissionRow, installation string) (OperationDTO, error) {
	snapshot, err := scanOperation(row, installation)
	if err != nil {
		return OperationDTO{}, err
	}
	return ProjectOperation(snapshot)
}

// SubmissionTaskColumns and ScanSubmissionTask use exactly the same closed
// projection as authorized reads; no config bytes or provider locators escape.
func SubmissionTaskColumns() string { return taskProjectionColumns }
func ScanSubmissionTask(row AdmissionRow, kind TaskKind, installation string) (TaskHeader, error) {
	table, ok := taskTables[kind]
	if !ok {
		return TaskHeader{}, ErrInvalid
	}
	return scanTask(row, kind, table, installation)
}
