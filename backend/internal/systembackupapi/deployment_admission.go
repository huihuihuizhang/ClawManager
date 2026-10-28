package systembackupapi

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	contract "clawreef/internal/systembackupcontract"
	read "clawreef/internal/systembackupread"
)

// DeploymentTaskAdmission binds the public writer to the installation's real
// execution readiness and physical capacity. It performs no external actions.
type DeploymentTaskAdmission struct {
	profile      ExecutionProfile
	raw          []byte
	hash         string
	capacityFile string
}

func NewAdmittedTaskWriter(profile ExecutionProfile, capacityFile string, enabled bool) (TaskWriter, error) {
	raw, hash, err := profile.canonical()
	if err != nil || capacityFile == "" {
		return nil, &Error{"not_ready"}
	}
	return NewPublicSQLTaskWriter(NewTaskRequestContract(), &DeploymentTaskAdmission{profile, raw, hash, capacityFile}, enabled)
}

type taskInputGuard interface {
	storeInputs(TaskWriteSQL, string) error
}
type deploymentAdmissionGuard struct {
	admission *DeploymentTaskAdmission
	identity  TaskSubmissionIdentity
	kind      read.TaskKind
	config    uint64
	request   []byte
	until     time.Time
}

func (a *DeploymentTaskAdmission) Admit(q TaskWriteSQL, identity TaskSubmissionIdentity, c TaskConfigSnapshot, kind read.TaskKind, raw []byte) (TaskCreation, TaskAdmissionGuard, error) {
	var out TaskCreation
	if a == nil || identity.InstallationID != a.profile.InstallationID || c.Matrix == "" {
		return out, nil, &Error{"not_ready"}
	}
	var engine string
	if q.QueryRow("SELECT engine FROM system_backup_v2_engine_bindings WHERE scope='installation' FOR UPDATE").Scan(&engine) != nil || engine != "v2" {
		return out, nil, &Error{"not_ready"}
	}
	var values contract.ConfigValues
	if json.Unmarshal(c.CanonicalJSON, &values) != nil || !values.Enabled {
		return out, nil, &Error{"not_ready"}
	}
	runner := "k8s"
	if a.profile.Orchestrator == "k3s" {
		runner = "k3s"
	}
	if c.Matrix != runner+"-"+a.profile.Profile {
		return out, nil, &Error{"not_ready"}
	}
	var pending uint64
	if q.QueryRow(`SELECT (SELECT COUNT(*) FROM system_backup_v2_backups WHERE origin_installation_id=? AND status='pending') + (SELECT COUNT(*) FROM system_backup_v2_preflights WHERE origin_installation_id=? AND status='pending') + (SELECT COUNT(*) FROM system_backup_v2_restore_drills WHERE origin_installation_id=? AND status='pending') + (SELECT COUNT(*) FROM system_backup_v2_artifact_verifications WHERE origin_installation_id=? AND status='pending')`, identity.InstallationID, identity.InstallationID, identity.InstallationID, identity.InstallationID).Scan(&pending) != nil {
		return out, nil, &Error{"not_ready"}
	}
	if values.Concurrency.MaxPendingTasks < 1 || pending >= uint64(values.Concurrency.MaxPendingTasks) {
		return out, nil, &Error{"capacity_exceeded"}
	}
	if err := reserveControlCapacity(q, a.capacityFile, values.Capacity.ControlMetadataCapacityBytes, int64(len(c.CanonicalJSON)+len(a.raw)+len(raw))+65536); err != nil {
		return out, nil, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return out, nil, &Error{"validation_failed"}
	}
	if kind == read.BackupTask {
		var purpose string
		var parts []string
		if json.Unmarshal(fields["task_purpose"], &purpose) != nil || json.Unmarshal(fields["requested_parts"], &parts) != nil {
			return out, nil, &Error{"validation_failed"}
		}
		if purpose == "acceptance" && (a.profile.TargetClass != "dr-ready-external" || len(a.profile.TargetRisks) != 0) {
			return out, nil, &Error{"backup_target_risk_rejected"}
		}
		refs := map[string]contract.ConfigReference{}
		for _, r := range values.References {
			refs[r.Purpose] = r
		}
		out.Backup = &BackupCreation{Orchestrator: a.profile.Orchestrator, Profile: a.profile.Profile, Runner: runner, Purpose: purpose, Parts: parts, TargetRisks: append([]string{}, a.profile.TargetRisks...), TargetClass: a.profile.TargetClass, FailureDomain: a.profile.FailureDomain, ArtifactReadIdentity: refs["artifact_read"].IdentityHash, ArtifactReadVersion: refs["artifact_read"].Version, ArtifactCAIdentity: refs["artifact_ca"].IdentityHash, ArtifactCAVersion: refs["artifact_ca"].Version}
	} else if kind == read.PreflightTask {
		var sourceType, sourceID, mode string
		if json.Unmarshal(fields["source_artifact_type"], &sourceType) != nil || json.Unmarshal(fields["source_public_id"], &sourceID) != nil || json.Unmarshal(fields["preflight_mode"], &mode) != nil || sourceType != "backup" || !validSourceBackupID(sourceID) {
			return out, nil, &Error{"not_ready"}
		}
		var profile, target string
		if json.Unmarshal(fields["target_profile"], &profile) != nil || json.Unmarshal(fields["restore_target_config_ref"], &target) != nil || profile != a.profile.Profile || target != a.profile.RestoreTargetRef {
			return out, nil, &Error{"validation_failed"}
		}
		var manifest string
		var acceptance *string
		var usable bool
		if q.QueryRow("SELECT manifest_checksum,acceptance_checksum,artifact_usable FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND status='succeeded' AND artifact_state='committed' FOR SHARE", identity.InstallationID, sourceID).Scan(&manifest, &acceptance, &usable) != nil || !usable || manifest == "" {
			return out, nil, &Error{"artifact_unavailable"}
		}
		out.Preflight = &PreflightCreation{SourceType: sourceType, SourcePublicID: sourceID, Mode: mode, TargetProfile: a.profile.Profile, TargetConfigRef: a.profile.RestoreTargetRef, TargetConfigHash: a.profile.RestoreTargetHash, SourceManifest: &manifest, SourceAcceptance: acceptance, Compatibility: "supported"}
	} else {
		return out, nil, &Error{"not_ready"}
	}
	g := &deploymentAdmissionGuard{admission: a, identity: identity, kind: kind, config: c.Version, request: bytes.Clone(raw)}
	if err := g.check(q, true); err != nil {
		return TaskCreation{}, nil, err
	}
	return out, g, nil
}

func (g *deploymentAdmissionGuard) ValidUntil() time.Time        { return g.until }
func (g *deploymentAdmissionGuard) Recheck(q TaskWriteSQL) error { return g.check(q, false) }
func (g *deploymentAdmissionGuard) check(q TaskWriteSQL, initial bool) error {
	var until, now time.Time
	var ready bool
	var protocol, parts string
	var acceptance bool
	if g == nil || q.QueryRow(`SELECT ready AND checked_at<=UTC_TIMESTAMP(6),expires_at,UTC_TIMESTAMP(6),execution_protocol,supported_parts,acceptance_ready FROM system_backup_v2_execution_readiness WHERE origin_installation_id=? AND task_type=? AND config_version=? AND profile_sha256=? FOR SHARE`, g.identity.InstallationID, string(g.kind), g.config, g.admission.hash).Scan(&ready, &until, &now, &protocol, &parts, &acceptance) != nil || !ready || !now.Before(until) || protocol != "public-v1" {
		return &Error{"not_ready"}
	}
	if g.kind == read.BackupTask {
		var request struct {
			Parts   []string `json:"requested_parts"`
			Purpose string   `json:"task_purpose"`
		}
		if json.Unmarshal(g.request, &request) != nil || (request.Purpose == "acceptance" && !acceptance) {
			return &Error{"not_ready"}
		}
		allowed := map[string]bool{}
		for _, part := range strings.Split(parts, ",") {
			allowed[part] = true
		}
		for _, part := range request.Parts {
			if !allowed[part] {
				return &Error{"not_ready"}
			}
		}
	}
	if initial {
		g.until = until
	} else if !g.until.Equal(until) {
		return &Error{"not_ready"}
	}
	return nil
}
func (g *deploymentAdmissionGuard) storeInputs(q TaskWriteSQL, id string) error {
	if !writerOne(q.Exec("INSERT INTO system_backup_v2_execution_inputs(origin_installation_id,task_public_id,task_type,profile_json,profile_sha256,request_json) VALUES(?,?,?,?,?,?)", g.identity.InstallationID, id, string(g.kind), g.admission.raw, g.admission.hash, g.request)) {
		return &Error{"not_ready"}
	}
	return nil
}

var _ TaskAdmission = (*DeploymentTaskAdmission)(nil)
var _ TaskAdmissionGuard = (*deploymentAdmissionGuard)(nil)
