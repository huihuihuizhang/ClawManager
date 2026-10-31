package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"sort"
	"time"

	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	security "clawreef/internal/systembackupsecurity"
	"github.com/google/uuid"
)

// Register the ACTUAL finite source census selection under the current original
// preparing claim. Neither a caller success flag nor an external hash can
// manufacture this proof; its input is produced by this live source authority.
func (x *originalSourceMetadataAuthority) registerSourceExclusion(ctx context.Context, observed productionSQLSourceMetadata) (ce.EvidenceRef, error) {
	var zero ce.EvidenceRef
	if x.Recheck(ctx) != nil || observed.Schema.Validate() != nil || observed.Schema.PolicySHA256 != domain.BusinessCapturePolicySHA256() {
		return zero, d.ErrNotReady
	}
	s, m := x.service, x.service.captureMaterials
	if m.ControlEvidence == nil || m.ControlEvidence.Validate() != nil {
		return zero, d.ErrNotReady
	}
	input := *m.ControlEvidence
	schemaRaw, err := pinnedDeploymentFile(input.SchemaRegistryFile, input.SchemaRegistrySHA256, 8<<20)
	if err != nil {
		return zero, d.ErrNotReady
	}
	redactionRaw, err := pinnedDeploymentFile(input.RedactionRegistryFile, input.RedactionRegistrySHA256, 65536)
	if err != nil {
		return zero, d.ErrNotReady
	}
	schemaPin, _, names, err := ce.ReadPolicies(schemaRaw, redactionRaw, input)
	if err != nil || validateOriginalControlPolicy(schemaRaw, names, observed.Census.Control) != nil {
		return zero, d.ErrNotReady
	}
	excluded := map[string]bool{}
	for _, name := range names {
		excluded[name] = true
	}
	if len(observed.Census.Control) == 0 || !sort.StringsAreSorted(observed.Census.Control) {
		return zero, d.ErrNotReady
	}
	for _, name := range observed.Census.Control {
		if !excluded[name] {
			return zero, d.ErrNotReady
		}
	}
	for _, name := range observed.Schema.Tables {
		if excluded[name] {
			return zero, d.ErrNotReady
		}
	}
	identity, err := ce.SourceIdentity(s.Config.SourceServerUUID, s.Config.SourceDatabase)
	if err != nil {
		return zero, d.ErrNotReady
	}
	namesRaw, err := ce.Canonical(names)
	if err != nil {
		return zero, d.ErrNotReady
	}
	scope := ce.Scope{Installation: x.input.Authority.InstallationID, Backup: x.input.Authority.TaskPublicID, Attempt: x.input.Authority.AttemptNo}
	payload, err := ce.Canonical(ce.SourceExclusionProof{Version: "system-backup-source-control-exclusion.v1", Scope: scope, ConfigSHA256: x.input.Authority.ConfigSHA256, SourceIdentitySHA256: identity, Registry: schemaPin, ExcludedNamesSHA256: ce.SHA256(namesRaw), IncludedControlCount: 0})
	if err != nil {
		return zero, d.ErrNotReady
	}
	defer clear(payload)
	entry := ce.RegisteredEvidence{PublicID: "sev_" + uuid.NewSHA1(uuid.NameSpaceOID, []byte("system-backup-source-control-exclusion.v1\x00"+scope.Installation+"\x00"+scope.Backup+"\x00"+ce.SHA256(payload))).String(), SHA256: ce.SHA256(payload), OwnerType: "backup", OwnerID: scope.Backup, Type: "verifier_report", Payload: payload}
	if s.checkSourceIdentity(ctx, s.Source) != nil || x.Recheck(ctx) != nil {
		return zero, d.ErrNotReady
	}
	gate := x.owner.Gate.Authority
	if wrapper, ok := gate.Authorization.(deploymentAuthorization); !ok || wrapper.Service != s {
		return zero, d.ErrNotReady
	}
	tx, err := gate.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, d.ErrNotReady
	}
	defer tx.Rollback()
	guard, err := gate.Bind(ctx, tx, x.input.Authority)
	if err != nil {
		return zero, err
	}
	var capacity, retention int64
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR SHARE", scope.Installation, x.input.Authority.ConfigVersion).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 {
		return zero, d.ErrNotReady
	}
	until := now.Add(time.Duration(retention) * time.Second).UTC().Truncate(time.Microsecond)
	if !until.After(x.input.Authority.DeadlineAt) || (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).ReserveExecutionPayload(ctx, tx, capacity, len(payload)) != nil {
		return zero, d.ErrNotReady
	}
	if err := ce.RegisterSQL(ctx, tx, scope, []ce.RegisteredEvidence{entry}, until); err != nil {
		return zero, err
	}
	ref := ce.EvidenceRef{PublicID: entry.PublicID, SHA256: entry.SHA256}
	actual, err := ce.LoadRegisteredSQL(ctx, tx, scope, ref)
	if err != nil || ce.SHA256(actual.Payload) != entry.SHA256 || guard.Recheck(ctx, tx) != nil {
		return zero, d.ErrNotReady
	}
	clear(actual.Payload)
	if s.checkProductionCaptureMaterials() != nil {
		return zero, d.ErrNotReady
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return zero, c.ErrExecutionCommitUnknown
	}
	if x.Recheck(ctx) != nil || s.checkSourceIdentity(ctx, s.Source) != nil {
		return zero, d.ErrNotReady
	}
	return ref, nil
}

// ReadPolicies authenticates the independently pinned frozen v12 decisions.
// This additionally binds their finite control scope and classifications to
// the actual complete original census and existing reviewed SQL policy map.
func validateOriginalControlPolicy(raw []byte, policyNames, observed []string) error {
	if len(observed) == 0 || !sort.StringsAreSorted(observed) || !reflect.DeepEqual(policyNames, observed) {
		return d.ErrNotReady
	}
	// Use explicit wire names; unknown fields remain owned by ReadPolicies.
	var document struct {
		Objects []struct {
			Type           string `json:"object_type"`
			Name           string `json:"name"`
			Category       string `json:"category"`
			Classification string `json:"data_classification"`
			Backup         string `json:"backup_strategy"`
			Restore        string `json:"restore_strategy"`
		} `json:"objects"`
	}
	if json.Unmarshal(raw, &document) != nil {
		return d.ErrNotReady
	}
	seen := map[string]bool{}
	for _, object := range document.Objects {
		if object.Category != "system_backup" || object.Type != "table" {
			continue
		}
		policy, known := root.Policy(object.Name)
		if !known || seen[object.Name] || policy.Category != object.Category || policy.Classification != object.Classification || policy.BackupStrategy != object.Backup || policy.RestoreStrategy != object.Restore {
			return d.ErrNotReady
		}
		seen[object.Name] = true
	}
	if len(seen) != len(observed) {
		return d.ErrNotReady
	}
	for _, name := range observed {
		if !seen[name] {
			return d.ErrNotReady
		}
	}
	return nil
}
