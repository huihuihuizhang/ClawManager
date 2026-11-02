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
	d "clawreef/internal/systembackupdispatch"
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
		return nil, err
	}
	tx, err := x.source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, d.ErrNotReady
	}
	defer tx.Rollback()
	s := x.delegation.service
	if x.recheck(ctx) != nil || s.checkSourceIdentity(ctx, tx) != nil {
		return nil, d.ErrNotReady
	}
	source := b.SourceInventory{Database: baseline.database, ServerUUID: baseline.server, Users: []int{}, Instances: []b.InstanceIdentity{}}
	rows, err := tx.QueryContext(ctx, "SELECT id FROM users ORDER BY id")
	if err != nil {
		return nil, d.ErrNotReady
	}
	users, owners := map[int]bool{}, map[int]int{}
	for rows.Next() {
		var id int
		if ctx.Err() != nil || rows.Scan(&id) != nil || id <= 0 || users[id] || len(users) >= 100000 {
			rows.Close()
			return nil, d.ErrNotReady
		}
		users[id] = true
		source.Users = append(source.Users, id)
	}
	if errors.Join(rows.Err(), rows.Close()) != nil {
		return nil, d.ErrNotReady
	}
	source.Instances, err = domain.ReadSourceInstances(ctx, tx)
	if err != nil {
		return nil, d.ErrNotReady
	}
	if source.Instances == nil {
		source.Instances = []b.InstanceIdentity{}
	}
	if !reflect.DeepEqual(source.Instances, baseline.instances) || s.validateRuntimeInventory(source) != nil {
		return nil, d.ErrNotReady
	}
	for _, instance := range source.Instances {
		if !users[instance.UserID] || owners[instance.ID] != 0 {
			return nil, d.ErrNotReady
		}
		owners[instance.ID] = instance.UserID
	}
	source.TeamFacts, err = team.ReadSourceFacts(ctx, tx, users, owners)
	if err != nil || source.TeamFacts == nil || source.TeamFacts.Validate(users, owners) != nil {
		return nil, d.ErrNotReady
	}
	skills, err := domain.ReadSkillCaptureInventory(ctx, tx, users, owners)
	if err != nil {
		return nil, d.ErrNotReady
	}
	source.Skills = &skills
	metadata, err := readProductionSQLMetadata(ctx, s, tx, source.Instances)
	if err != nil || !reflect.DeepEqual(metadata, baseline.metadata) || s.checkSourceIdentity(ctx, tx) != nil || tx.Commit() != nil || x.recheck(ctx) != nil || !time.Now().Before(baseline.until) {
		return nil, d.ErrNotReady
	}
	raw, err := json.Marshal(source)
	if err != nil || len(raw) > 8<<20 {
		return nil, d.ErrNotReady
	}
	return &observedSourceInventory{sql: baseline, source: source, sha256: hash(raw)}, nil
}
