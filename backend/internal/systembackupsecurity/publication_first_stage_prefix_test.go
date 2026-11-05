package systembackupsecurity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
)

// This exercises the real prepared-record entry with an authenticated v1
// signing owner. It checks SQL request order, not InnoDB concurrency.
type firstPrefixModel struct {
	state *signingSQLTestState
	deny  bool
	order []string
}
type firstPrefixConnector struct{ model *firstPrefixModel }

func (c firstPrefixConnector) Driver() driver.Driver { return proofDriver{} }
func (c firstPrefixConnector) Connect(context.Context) (driver.Conn, error) {
	return &firstPrefixConn{firstStageConn: &firstStageConn{signingSQLConn: &signingSQLConn{s: c.model.state}}, model: c.model}, nil
}

type firstPrefixConn struct {
	*firstStageConn
	model     *firstPrefixModel
	stateHeld bool
}

func (c *firstPrefixConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	c.stateHeld = false
	return c.signingSQLConn.BeginTx(ctx, opts)
}
func (c *firstPrefixConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if query == "SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR SHARE" {
		c.model.order = append(c.model.order, "state")
		if c.working == nil || c.readOnly || len(args) != 1 || args[0].Value != c.s.f.pin.InstallationID || c.model.deny {
			return nil, errors.New("original state prefix unavailable")
		}
		c.stateHeld = true
		return registrationRow(int64(1)), nil
	}
	if strings.HasPrefix(query, "SELECT row_version FROM system_backup_v2_backups") {
		c.model.order = append(c.model.order, "task-exclusive")
		if !c.stateHeld {
			return nil, errors.New("task lock requested before original state prefix")
		}
	}
	return c.firstStageConn.QueryContext(ctx, query, args)
}
func TestPublicationStageFirstOriginalOwnerStateBeforeTask(t *testing.T) {
	for _, deny := range []bool{false, true} {
		name := "original-v1-task1"
		if deny {
			name = "state-rejected-before-task"
		}
		t.Run(name, func(t *testing.T) {
			f, state, _, oldSigners := newSigningSQLFixture(t)
			oldSigners.Close()
			state.grant.ConfigVersion = 1
			for i := range f.record.Permissions {
				grant := state.grant
				f.record.Permissions[i].SQLOwner = &grant
			}
			f.writeRecord(true)
			model := &firstPrefixModel{state: state, deny: deny}
			db := sql.OpenDB(firstPrefixConnector{model: model})
			t.Cleanup(func() { db.Close() })
			prepared := firstStagePrepared(t, f, db, state.claim, "acceptance_record")
			model.order = nil
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			err = prepared.StageFirst(context.Background(), tx)
			if deny {
				if err == nil || strings.Join(model.order, ",") != "state" || state.writes != 0 {
					t.Fatalf("rejected prefix reached task/write: err=%v order=%v writes=%d", err, model.order, state.writes)
				}
			} else {
				if err != nil || len(model.order) < 2 || model.order[0] != "state" || model.order[1] != "task-exclusive" {
					t.Fatalf("original owner order: err=%v order=%v", err, model.order)
				}
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if state.commits != 0 || len(state.evidence) != 0 {
				t.Fatal("stage escaped caller rollback")
			}
		})
	}
}
