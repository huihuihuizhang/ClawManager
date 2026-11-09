package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sync/atomic"
	"time"

	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackupinstallationowner/install"
)

type bootstrapSourceSQLFacts struct {
	inventory b.SourceInventory
	metadata  productionSQLSourceMetadata
	bindings  []observedSourceRuntimeBinding
	pods      []observedSourceRuntimePod
	clock     time.Time
}

func (x *bootstrapSourceRegistryReader) checkSQLIdentity(ctx context.Context, q sourceIdentityReader, binding install.BootstrapSourceConnection, verified *atomic.Bool, floor *time.Time) error {
	if x.access.Check(x.ctx) != nil || q == nil || verified == nil || !verified.Load() {
		return install.ErrInstall
	}
	var account, role, database, server string
	var rawClock any
	if q.QueryRowContext(ctx, "SELECT CURRENT_USER(),CURRENT_ROLE(),DATABASE(),@@server_uuid,UTC_TIMESTAMP(6)").Scan(&account, &role, &database, &server, &rawClock) != nil || account != binding.Account || role != "NONE" || database != binding.Database || server != binding.ServerUUID {
		return install.ErrInstall
	}
	now, err := decodeSourceObservationSQLTime(rawClock)
	if err != nil || now.Before(*floor) || now.Before(x.association.NotBefore) || !now.Before(x.association.Until) {
		return install.ErrInstall
	}
	*floor = now
	rows, err := q.QueryContext(ctx, "SHOW GRANTS FOR CURRENT_USER")
	if err != nil {
		return install.ErrInstall
	}
	var grants []string
	for rows.Next() {
		var grant string
		if rows.Scan(&grant) != nil || len(grants) >= 1000 || len(grant) > 16384 {
			rows.Close()
			return install.ErrInstall
		}
		grants = append(grants, grant)
	}
	if errors.Join(rows.Err(), rows.Close()) != nil || domain.ValidateBusinessSourceGrants(database, grants) != nil {
		return install.ErrInstall
	}
	template := x.materials.Operations["capture-database"].Request.Database
	if template == nil || template.SchemaCensus == nil || domain.CheckBusinessSchemaCensus(ctx, q, *template.SchemaCensus) != nil || x.access.Check(x.ctx) != nil {
		return install.ErrInstall
	}
	return nil
}

// Actual least-privilege TLS SQL session, one read-only RepeatableRead snapshot,
// original domain closed readers and full EOF. This does not use control SQL or
// a caller-supplied database; no gate/task/config enabling occurs.
func (x *bootstrapSourceRegistryReader) readSourceSQL() (*bootstrapSourceSQLFacts, error) {
	binding, err := x.connection("source_sql")
	if err != nil {
		return nil, install.ErrInstall
	}
	db, verified, err := openBootstrapSourceSQL(x.ctx, x.access, binding)
	if err != nil {
		return nil, install.ErrInstall
	}
	defer db.Close()
	conn, err := db.Conn(x.physical)
	if err != nil {
		return nil, install.ErrInstall
	}
	defer conn.Close()
	floor := time.Time{}
	if x.checkSQLIdentity(x.physical, conn, binding, verified, &floor) != nil {
		return nil, install.ErrInstall
	}
	tx, err := conn.BeginTx(x.physical, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, install.ErrInstall
	}
	defer tx.Rollback()
	if x.checkSQLIdentity(x.physical, tx, binding, verified, &floor) != nil {
		return nil, install.ErrInstall
	}
	out := &bootstrapSourceSQLFacts{inventory: b.SourceInventory{Database: binding.Database, ServerUUID: binding.ServerUUID, Users: []int{}, Instances: []b.InstanceIdentity{}}, bindings: []observedSourceRuntimeBinding{}, pods: []observedSourceRuntimePod{}}
	users, owners := map[int]bool{}, map[int]int{}
	rows, err := tx.QueryContext(x.physical, "SELECT id FROM users ORDER BY id")
	if err != nil {
		return nil, install.ErrInstall
	}
	for rows.Next() {
		var id int
		if rows.Scan(&id) != nil || id <= 0 || users[id] || len(users) >= 100000 {
			rows.Close()
			return nil, install.ErrInstall
		}
		users[id] = true
		out.inventory.Users = append(out.inventory.Users, id)
	}
	if errors.Join(rows.Err(), rows.Close()) != nil {
		return nil, install.ErrInstall
	}
	out.inventory.Instances, err = domain.ReadSourceInstances(x.physical, tx)
	if err != nil {
		return nil, install.ErrInstall
	}
	if out.inventory.Instances == nil {
		out.inventory.Instances = []b.InstanceIdentity{}
	}
	supported := map[b.AgentKind]bool{}
	if x.config.RuntimeSources == nil {
		return nil, install.ErrInstall
	}
	for _, kind := range x.config.RuntimeSources.Supported {
		supported[kind] = true
	}
	if bindRuntimeTestScope(x.config, &out.inventory) != nil {
		return nil, install.ErrInstall
	}
	for n, instance := range out.inventory.Instances {
		if deferredRuntimeTestInstance(x.config, instance) {
			if !users[instance.UserID] || owners[instance.ID] != 0 {
				return nil, ErrSourceWriterObservationIncomplete
			}
			owners[instance.ID] = instance.UserID
			continue
		}
		if instance.Status == "stopped" && !isCurrentStoppedPro(instance) {
			return nil, mountInputError("stopped_original_snapshot_and_witness_required", instance.ID, "")
		}
		if instance.ID <= 0 || instance.UserID <= 0 || instance.Generation <= 0 || !users[instance.UserID] || owners[instance.ID] != 0 || n > 0 && out.inventory.Instances[n-1].ID >= instance.ID || instance.Status != "running" && !isCurrentStoppedPro(instance) {
			return nil, ErrSourceWriterObservationIncomplete
		}
		if !supported[b.AgentKind{Type: instance.Type, Mode: instance.Mode, Variant: instance.Variant, OS: instance.OS}] || instance.Namespace != x.config.Namespace && !((instance.Mode == "lite" || isCurrentStoppedPro(instance)) && instance.Namespace == "") && !(isRunningTenantPro(instance) && validTenantProNamespace(x.config.Namespace, instance)) {
			return nil, ErrSourceWriterObservationIncomplete
		}
		owners[instance.ID] = instance.UserID
	}
	out.inventory.TeamFacts, err = team.ReadSourceFacts(x.physical, tx, users, owners)
	if err != nil || out.inventory.TeamFacts == nil || out.inventory.TeamFacts.Validate(users, owners) != nil {
		return nil, install.ErrInstall
	}
	out.inventory.TeamFacts.SharedFiles, err = domain.ReadTeamFileSource(x.physical, tx)
	if err != nil {
		return nil, err
	}
	skills, err := domain.ReadSkillCaptureInventory(x.physical, tx, users, owners)
	if err != nil {
		return nil, install.ErrInstall
	}
	out.inventory.Skills = &skills
	out.metadata, err = x.readSourceSQLMetadata(x.physical, tx, out.inventory.Instances, binding, verified, &floor)
	if err != nil {
		return nil, install.ErrInstall
	}
	if x.checkRuntimeImagePolicies(out) != nil {
		return nil, install.ErrInstall
	}
	if x.readSourceRuntimeRows(tx, out) != nil || x.checkSQLIdentity(x.physical, tx, binding, verified, &floor) != nil || tx.Commit() != nil || x.access.Check(x.ctx) != nil {
		return nil, install.ErrInstall
	}
	out.clock = floor
	return out, nil
}

func (x *bootstrapSourceRegistryReader) readSourceRuntimeRows(tx *sql.Tx, out *bootstrapSourceSQLFacts) error {
	rows, err := tx.QueryContext(x.physical, "SELECT instance_id,COALESCE(runtime_pod_id,0),COALESCE(generation,0),COALESCE(gateway_port,0),COALESCE(gateway_pid,0),COALESCE(gateway_id,''),COALESCE(workspace_path,''),state FROM instance_runtime_bindings ORDER BY instance_id")
	if err != nil {
		return install.ErrInstall
	}
	for rows.Next() {
		var row observedSourceRuntimeBinding
		if rows.Scan(&row.Instance, &row.RuntimePod, &row.Generation, &row.Port, &row.PID, &row.Gateway, &row.Workspace, &row.State) != nil || row.Instance <= 0 || len(out.bindings) >= 10000 || len(out.bindings) > 0 && out.bindings[len(out.bindings)-1].Instance >= row.Instance {
			rows.Close()
			return install.ErrInstall
		}
		out.bindings = append(out.bindings, row)
	}
	if errors.Join(rows.Err(), rows.Close()) != nil {
		return install.ErrInstall
	}
	rows, err = tx.QueryContext(x.physical, "SELECT id,COALESCE(pod_uid,''),pod_name,namespace,COALESCE(agent_endpoint,''),deployment_name,state,draining FROM runtime_pods ORDER BY id")
	if err != nil {
		return install.ErrInstall
	}
	for rows.Next() {
		var row observedSourceRuntimePod
		if rows.Scan(&row.ID, &row.UID, &row.Name, &row.Namespace, &row.Endpoint, &row.Deployment, &row.State, &row.Draining) != nil || row.ID <= 0 || len(out.pods) >= 10000 || len(out.pods) > 0 && out.pods[len(out.pods)-1].ID >= row.ID {
			rows.Close()
			return install.ErrInstall
		}
		out.pods = append(out.pods, row)
	}
	if errors.Join(rows.Err(), rows.Close()) != nil {
		return install.ErrInstall
	}
	return nil
}

func sameBootstrapSourceSQL(a, b *bootstrapSourceSQLFacts) bool {
	// Different observation timestamps are expected; source DATA must be exact.
	return a != nil && b != nil && !b.clock.Before(a.clock) && reflect.DeepEqual(a.inventory, b.inventory) && reflect.DeepEqual(a.metadata, b.metadata) && reflect.DeepEqual(a.bindings, b.bindings) && reflect.DeepEqual(a.pods, b.pods)
}

// Policy selection is a runtime requirement. The whole original SQL projection
// and every image/owner fact remain intact. Only the original explicitly signed
// two-source test scope may defer these runtime policy matches.
func (x *bootstrapSourceRegistryReader) checkRuntimeImagePolicies(out *bootstrapSourceSQLFacts) error {
	if x == nil || out == nil || x.materials.Discovery == nil || bindRuntimeTestScope(x.config, &out.inventory) != nil {
		return install.ErrInstall
	}
	for _, instance := range out.inventory.Instances {
		if deferredRuntimeTestInstance(x.config, instance) {
			continue
		}
		matched := false
		for _, policy := range x.materials.Discovery.RuntimePolicies {
			matched = matched || productionImageMatches(out.metadata.Images[instance.ID], policy, x.materials.Discovery.RuntimeImageReferences)
		}
		if !matched {
			return install.ErrInstall
		}
	}
	return nil
}
