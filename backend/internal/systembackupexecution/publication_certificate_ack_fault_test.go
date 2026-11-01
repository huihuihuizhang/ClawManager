package systembackupexecution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"testing"
)

// Named driver-unit DATA only. This prevents the fault injector from consuming
// its flag on a legitimate read-only validation commit. It supplies no SQL,
// owner, current task, capture receipt or signing authority.
func TestCertificateCommitACKFaultPreservesReadOnlyCommitsUnit(t *testing.T) {
	for _, mode := range []string{"read-only", "write", "read-only-native-error", "write-native-error"} {
		t.Run(mode, func(t *testing.T) {
			var armed atomic.Bool
			armed.Store(true)
			probe := &certificateACKDriverProbe{}
			if mode == "read-only-native-error" || mode == "write-native-error" {
				probe.commitErr = errors.New("named native driver commit error DATA")
			}
			options := driver.TxOptions{Isolation: driver.IsolationLevel(sql.LevelRepeatableRead), ReadOnly: mode == "read-only" || mode == "read-only-native-error"}
			conn := &aCertificateWriteACKConn{aPublicationACKConn{Conn: probe, lose: &armed}}
			tx, err := conn.BeginTx(context.Background(), options)
			if err != nil || probe.options != options {
				t.Fatal("fault proxy changed native transaction options", err)
			}
			err = tx.Commit()
			if probe.commits != 1 {
				t.Fatal("fault proxy did not commit the underlying transaction exactly once")
			}
			if probe.commitErr != nil {
				if !errors.Is(err, probe.commitErr) || !armed.Load() {
					t.Fatal("native commit error was replaced or consumed ACK fault", err)
				}
			} else if options.ReadOnly {
				if err != nil || !armed.Load() {
					t.Fatal("read-only commit consumed later write ACK fault", err)
				}
			} else if !errors.Is(err, errAPublicationACKLost) || armed.Load() {
				t.Fatal("successful native write commit did not lose precisely one ACK", err)
			}
		})
	}
}

type certificateACKDriverProbe struct {
	options   driver.TxOptions
	commits   int
	commitErr error
}

func (p *certificateACKDriverProbe) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("named driver unit has no SQL operations")
}
func (p *certificateACKDriverProbe) Close() error { return nil }
func (p *certificateACKDriverProbe) Begin() (driver.Tx, error) {
	return p, nil
}
func (p *certificateACKDriverProbe) BeginTx(_ context.Context, options driver.TxOptions) (driver.Tx, error) {
	p.options = options
	return p, nil
}
func (p *certificateACKDriverProbe) Commit() error {
	p.commits++
	return p.commitErr
}
func (p *certificateACKDriverProbe) Rollback() error { return nil }
