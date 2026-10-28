package systembackupproducer

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"testing"
	"time"
)

type deploymentSQLPolicy struct {
	scope   Scope
	next    recoveryDeploymentRow
	current *recoveryDeploymentRow
}

func (p *deploymentSQLPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	row, found, err := readRecoveryDeployment(ctx, tx, scope, true)
	if err != nil {
		return GuardPlan{}, err
	}
	if found {
		p.current = &row
	} else {
		p.current = nil
	}
	return GuardPlan{BindingHash: Hash(bytes.Repeat([]byte{'a'}, 64)), Deadlines: []time.Time{time.Date(2026, 10, 10, 2, 0, 0, 0, time.UTC)}}, nil
}

func (p *deploymentSQLPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, _ GuardPlan, _ time.Time) error {
	return recheckRecoveryDeployment(ctx, tx, scope, p.next)
}

func TestRecoveryDeploymentCASAndRollback(t *testing.T) {
	r, err := DecodeResult(fixtures(t).Positive[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC)
	db := &fakeDB{now: now, server: string(r.Scope.ServerUUID), database: string(r.Scope.Database)}
	var stored *recoveryDeploymentRow
	var before *recoveryDeploymentRow
	failCAS := false
	db.beginRecord = func() {
		if stored != nil {
			copy := *stored
			before = &copy
		} else {
			before = nil
		}
	}
	db.rollbackRecord = func() { stored = before }
	db.queryRecord = func(q string, args []driver.NamedValue) (driver.Rows, error) {
		if q != recoveryDeploymentLockSQL && q != recoveryDeploymentReadSQL || len(args) != 1 {
			return nil, ErrInvalid
		}
		if stored == nil {
			return &emptyFenceRows{}, nil
		}
		v := *stored
		return &fakeRows{values: []driver.Value{v.installation, v.workload, v.issuer, v.subject,
			v.managerIssuer, v.actor, v.admission, v.clientCA, v.certificate, v.statProfile,
			v.enabled, v.epoch, v.authorizedUntil, v.version}}, nil
	}
	db.execRecord = func(q string, args []driver.NamedValue) (driver.Result, error) {
		if failCAS {
			return driver.RowsAffected(0), nil
		}
		switch q {
		case recoveryDeploymentInsertSQL:
			if stored != nil || len(args) != 15 {
				return driver.RowsAffected(0), nil
			}
			stored = &recoveryDeploymentRow{installation: args[1].Value.(string), workload: args[2].Value.([]byte),
				issuer: args[3].Value.([]byte), subject: args[4].Value.([]byte), managerIssuer: args[5].Value.([]byte),
				actor: args[6].Value.([]byte), admission: args[7].Value.([]byte), clientCA: args[8].Value.([]byte),
				certificate: args[9].Value.([]byte), statProfile: args[10].Value.([]byte), enabled: args[11].Value.(bool),
				epoch: args[12].Value.(int64), authorizedUntil: args[13].Value.(time.Time), version: args[14].Value.(int64)}
			return driver.RowsAffected(1), nil
		case recoveryDeploymentUpdateSQL:
			if stored == nil || len(args) != 18 || stored.installation != args[14].Value.(string) ||
				!bytes.Equal(stored.workload, args[15].Value.([]byte)) || stored.epoch != args[16].Value.(int64) || stored.version != args[17].Value.(int64) {
				return driver.RowsAffected(0), nil
			}
			stored = &recoveryDeploymentRow{installation: stored.installation, workload: args[0].Value.([]byte),
				issuer: args[1].Value.([]byte), subject: args[2].Value.([]byte), managerIssuer: args[3].Value.([]byte),
				actor: args[4].Value.([]byte), admission: args[5].Value.([]byte), clientCA: args[6].Value.([]byte),
				certificate: args[7].Value.([]byte), statProfile: args[8].Value.([]byte), enabled: args[9].Value.(bool),
				epoch: args[10].Value.(int64), authorizedUntil: args[11].Value.(time.Time), version: args[12].Value.(int64)}
			return driver.RowsAffected(1), nil
		}
		return nil, ErrInvalid
	}
	conn := sql.OpenDB(fakeConnector{db})
	t.Cleanup(func() { conn.Close() })
	fill := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	initial := recoveryDeploymentRow{installation: string(r.Scope.Installation), workload: fill('a'), issuer: fill('b'),
		subject: fill('c'), managerIssuer: fill('d'), actor: fill('e'), admission: fill('f'), clientCA: fill('g'),
		certificate: fill('h'), statProfile: fill('i'), enabled: true, epoch: 1, version: 1, authorizedUntil: now.Add(time.Hour)}
	run := func(next recoveryDeploymentRow) error {
		p := &deploymentSQLPolicy{scope: r.Scope, next: next}
		tx, err := NewTransactions(conn, r.Scope, p)
		if err != nil {
			return err
		}
		tx.clock = func() time.Time { return db.now }
		_, err = tx.Run(context.Background(), func(ctx context.Context, work *Transaction) error {
			return stageRecoveryDeployment(ctx, work, r.Scope, p.current, next)
		})
		return err
	}
	if err := run(initial); err != nil || stored == nil || !reflect.DeepEqual(*stored, initial) {
		t.Fatal("insert", err, stored)
	}
	next := initial
	next.enabled, next.epoch, next.version = false, 2, 2
	if err := run(next); err != nil || !reflect.DeepEqual(*stored, next) {
		t.Fatal("disable", err, stored)
	}
	stale := initial
	stale.epoch, stale.version = 3, 3
	failCAS = true
	if err := run(stale); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(*stored, next) {
		t.Fatal("failed CAS must roll back", err, stored)
	}
	if err := run(initial); !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(*stored, next) {
		t.Fatal("epoch regression must fail", err, stored)
	}
}
