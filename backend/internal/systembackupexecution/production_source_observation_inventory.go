package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/team"
)

type observedSourceInventory struct {
	sql    *observedSourceSQL
	source b.SourceInventory
	sha256 string
}

// No task projection, control-row writes or supplied reader callbacks. Every
// identity/keyset comes from one authenticated original source SQL snapshot.
func (x *sourceSQLObservation) observeInventory(ctx context.Context) (*observedSourceInventory, error) {
	baseline, err := x.observe(ctx)
	if err != nil {
		sourceObservationDetailRejected(sourceInventoryBaseline)
		return nil, err
	}
	tx, err := x.source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, sourceObservationDetailRejected(sourceInventoryBegin)
	}
	defer tx.Rollback()
	s := x.delegation.service
	if x.recheck(ctx) != nil {
		return nil, sourceObservationDetailRejected(sourceInventoryOriginal)
	}
	if s.checkSourceIdentity(ctx, tx) != nil {
		return nil, sourceObservationDetailRejected(sourceInventoryIdentity)
	}
	source := b.SourceInventory{Database: baseline.database, ServerUUID: baseline.server, Users: []int{}, Instances: []b.InstanceIdentity{}}
	rows, err := tx.QueryContext(ctx, "SELECT id FROM users ORDER BY id")
	if err != nil {
		return nil, sourceObservationDetailRejected(sourceInventoryUsersRead)
	}
	users, owners := map[int]bool{}, map[int]int{}
	for rows.Next() {
		var id int
		if ctx.Err() != nil || rows.Scan(&id) != nil || id <= 0 || users[id] || len(users) >= 100000 {
			rows.Close()
			return nil, sourceObservationDetailRejected(sourceInventoryUsersShape)
		}
		users[id] = true
		source.Users = append(source.Users, id)
	}
	if errors.Join(rows.Err(), rows.Close()) != nil {
		return nil, sourceObservationDetailRejected(sourceInventoryUsersEOF)
	}
	source.Instances, err = domain.ReadSourceInstances(ctx, tx)
	if err != nil {
		return nil, sourceObservationDetailRejected(sourceInventoryInstancesRead)
	}
	if source.Instances == nil {
		source.Instances = []b.InstanceIdentity{}
	}
	if !reflect.DeepEqual(source.Instances, baseline.instances) {
		return nil, sourceObservationDetailRejected(sourceInventoryInstancesDrift)
	}
	if s.validateRuntimeInventory(source) != nil {
		return nil, sourceObservationDetailRejected(sourceInventoryRuntime)
	}
	for _, instance := range source.Instances {
		if !users[instance.UserID] || owners[instance.ID] != 0 {
			return nil, sourceObservationDetailRejected(sourceInventoryInstanceOwner)
		}
		owners[instance.ID] = instance.UserID
	}
	source.TeamFacts, err = team.ReadSourceFacts(ctx, tx, users, owners)
	if err != nil || source.TeamFacts == nil || source.TeamFacts.Validate(users, owners) != nil {
		return nil, sourceObservationDetailRejected(sourceInventoryTeams)
	}
	skills, err := domain.ReadSkillCaptureInventory(ctx, tx, users, owners)
	if err != nil {
		return nil, sourceObservationDetailRejected(sourceInventorySkills)
	}
	source.Skills = &skills
	metadata, err := readProductionSQLMetadata(ctx, s, tx, source.Instances)
	if err != nil {
		return nil, sourceObservationDetailRejected(sourceInventoryMetadataRead)
	}
	if !reflect.DeepEqual(metadata, baseline.metadata) {
		return nil, sourceObservationDetailRejected(sourceInventoryMetadataDrift)
	}
	if s.checkSourceIdentity(ctx, tx) != nil {
		return nil, sourceObservationDetailRejected(sourceInventoryIdentityTail)
	}
	if tx.Commit() != nil {
		return nil, sourceObservationDetailRejected(sourceInventoryCommit)
	}
	if x.recheck(ctx) != nil {
		return nil, sourceObservationDetailRejected(sourceInventoryOriginalTail)
	}
	if !time.Now().Before(baseline.until) {
		return nil, sourceObservationDetailRejected(sourceInventoryDeadline)
	}
	raw, err := json.Marshal(source)
	if err != nil || len(raw) > 8<<20 {
		return nil, sourceObservationDetailRejected(sourceInventoryProjection)
	}
	return &observedSourceInventory{sql: baseline, source: source, sha256: hash(raw)}, nil
}
