package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	batchv1 "k8s.io/api/batch/v1"
)

// Native current-column fixture only: the added Job row is named test DATA,
// not a Kubernetes observation or admitted new collector. The complete original
// fixture independently exercises the real EnsureJob -> first Bind call path.
func TestOriginalInitialBindingCurrentSQL(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires isolated local MySQL")
	}
	var loseCommit atomic.Bool
	delivery := &dHeldClockDelay{initialFacts: true, duration: 2500 * time.Millisecond}
	options := &consumerFixtureOptions{WrapControlConnector: func(conn driver.Connector) driver.Connector {
		return aPublicationACKConnector{Connector: dHeldClockConnector{Connector: conn, delay: delivery}, lose: &loseCommit}
	}}
	owner, _, admin, db, authority, originalJob, _, _, _ := newConsumerMySQLFixtureOptions(t, options)
	ctx := context.Background()
	// This focused current-column fixture predates heartbeat writes. Match the
	// real 098 migration column; do not change any role or production schema.
	if _, err := admin.ExecContext(ctx, `ALTER TABLE system_backup_v2_backups ADD COLUMN heartbeat_at DATETIME(6) NULL`); err != nil {
		t.Fatal(err)
	}
	var originalKeyUse []byte
	if err := admin.QueryRowContext(ctx, `SELECT key_use_json FROM system_backup_v2_runtime_resources WHERE observed_uid=?`, originalJob.UID).Scan(&originalKeyUse); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := admin.QueryRowContext(ctx, `SELECT request_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND observed_uid=?`, authority.TaskPublicID, originalJob.UID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var job batchv1.Job
	if json.Unmarshal(raw, &job) != nil {
		t.Fatal("original fixture Job JSON")
	}
	job.Name = "initial-binding-data"
	delete(job.Annotations, kube.RequestHashAnnotation)
	intent, err := kube.Intent("Job", &job)
	if err != nil {
		t.Fatal(err)
	}
	record := kube.ResourceRecord{Intent: intent, Revision: 1, CreateDispatched: true, UID: "initial-binding-data-uid", ResourceVersion: "1"}
	_, err = admin.ExecContext(ctx, `INSERT INTO system_backup_v2_runtime_resources(task_public_id,resource_kind,namespace_name,resource_name,resource_owner,request_sha256,request_json,row_version,create_dispatched,observed_uid,resource_version,lifecycle,attempt_no,phase) VALUES(?,'Job',?,?,?,?,?,1,TRUE,?,'1','ready',?,'capture')`, authority.TaskPublicID, intent.Identity.Namespace, intent.Identity.Name, authority.TaskPublicID, intent.RequestSHA256, intent.RequestJSON, record.UID, authority.AttemptNo)
	if err != nil {
		t.Fatal(err)
	}
	store := c.SQLExecutionWorkStore{Queue: c.SQLExecutionQueue{DB: db, InstallationID: authority.InstallationID, Owner: authority.ClaimOwner, ApplicationScope: owner.Gate.Authority.ApplicationScope, Policy: c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}}, Authority: owner.Gate.Authority, Records: owner.Gate.Records}
	setLease := func() {
		t.Helper()
		result, err := admin.ExecContext(ctx, `UPDATE system_backup_v2_backups SET controller_lease_expires_at=TIMESTAMPADD(SECOND,20,UTC_TIMESTAMP(6)) WHERE public_id=?`, authority.TaskPublicID)
		if err != nil {
			t.Fatal(err)
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			t.Fatal("fixture claim reset", count, err)
		}
	}
	readLease := func(view interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	}) time.Time {
		t.Helper()
		var value time.Time
		if err := view.QueryRowContext(ctx, `SELECT controller_lease_expires_at FROM system_backup_v2_backups WHERE public_id=?`, authority.TaskPublicID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	census := func(tx *sql.Tx) [4]uint64 {
		t.Helper()
		var v [4]uint64
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM system_backup_v2_evidence),(SELECT COUNT(*) FROM system_backup_v2_runtime_resources),(SELECT COUNT(*) FROM system_backup_v2_job_observations),(SELECT COUNT(*) FROM system_backup_v2_execution_records)`).Scan(&v[0], &v[1], &v[2], &v[3]); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, name := range []string{"healthy-rollback", "key-use", "binding", "revoked", "stopped", "unknown-create", "stolen-owner", "expired-claim", "expired-task", "expired-hold", "canceled"} {
		t.Run(name, func(t *testing.T) {
			setLease()
			before := readLease(admin)
			err := store.RunWithExecutionHeartbeat(ctx, authority, func(active context.Context) error {
				_, err := c.WithOriginalControllerBinding(active, authority, record, func(scoped context.Context) (d.JobBinding, error) {
					tx, err := db.BeginTx(scoped, nil)
					if err != nil {
						return d.JobBinding{}, err
					}
					defer tx.Rollback()
					guard, err := owner.Gate.Authority.Bind(scoped, tx, authority)
					if err != nil {
						return d.JobBinding{}, err
					}
					beforeRows := census(tx)
					var update string
					switch name {
					case "key-use":
						update = `UPDATE system_backup_v2_runtime_resources SET key_use_json='{"nonce":"old"}' WHERE observed_uid='initial-binding-data-uid'`
					case "binding":
						update = `UPDATE system_backup_v2_runtime_resources SET binding_json='{"UID":"old"}' WHERE observed_uid='initial-binding-data-uid'`
					case "revoked":
						update = `UPDATE system_backup_v2_runtime_resources SET revoked=TRUE WHERE observed_uid='initial-binding-data-uid'`
					case "stopped":
						update = `UPDATE system_backup_v2_runtime_resources SET stopped_at=UTC_TIMESTAMP(6) WHERE observed_uid='initial-binding-data-uid'`
					case "unknown-create":
						update = `UPDATE system_backup_v2_runtime_resources SET observed_uid='',resource_version='' WHERE observed_uid='initial-binding-data-uid'`
					case "stolen-owner":
						update = `UPDATE system_backup_v2_backups SET controller_owner=CONCAT(controller_owner,'-stolen')`
					case "expired-claim":
						update = `UPDATE system_backup_v2_backups SET controller_lease_expires_at=UTC_TIMESTAMP(6)`
					case "expired-task":
						update = `UPDATE system_backup_v2_backups SET deadline_at=UTC_TIMESTAMP(6)`
					case "expired-hold":
						update = `UPDATE system_backup_v2_maintenance_locks SET absolute_hold_deadline_at=UTC_TIMESTAMP(6)`
					}
					if update != "" {
						field := map[string]string{"key-use": "key_use_json", "binding": "binding_json", "revoked": "revoked", "stopped": "stopped_at", "unknown-create": "CONCAT(observed_uid,':',resource_version)"}[name]
						verify := `SELECT ` + field + ` FROM system_backup_v2_runtime_resources WHERE resource_name='initial-binding-data'`
						if name == "stolen-owner" {
							verify = `SELECT controller_owner FROM system_backup_v2_backups`
						}
						if name == "expired-claim" {
							verify = `SELECT controller_lease_expires_at FROM system_backup_v2_backups`
						}
						if name == "expired-task" {
							verify = `SELECT deadline_at FROM system_backup_v2_backups`
						}
						if name == "expired-hold" {
							verify = `SELECT absolute_hold_deadline_at FROM system_backup_v2_maintenance_locks`
						}
						var original, changed []byte
						if err := tx.QueryRowContext(scoped, verify).Scan(&original); err != nil {
							t.Fatal(err)
						}
						result, err := tx.ExecContext(scoped, update)
						if err != nil {
							return d.JobBinding{}, err
						}
						n, err := result.RowsAffected()
						if err != nil || n != 1 || tx.QueryRowContext(scoped, verify).Scan(&changed) != nil || bytes.Equal(original, changed) {
							t.Fatal("actual first binding mutation", n, err)
						}
					}
					if name == "canceled" {
						// An actual committed cancellation is tested separately below;
						// this original cooperative cancellation must issue no renewal.
						child, cancel := context.WithCancel(scoped)
						cancel()
						if _, err := c.PrepareOriginalFirstBinding(child, tx, authority, guard); err == nil {
							t.Fatal("canceled binding context accepted")
						}
						return d.JobBinding{}, nil
					}
					fresh, err := c.PrepareOriginalFirstBinding(scoped, tx, authority, guard)
					allowed := name == "healthy-rollback"
					if (err == nil) != allowed {
						t.Fatal("current first binding decision", name, err)
					}
					if allowed {
						if !guard.ValidUntil().IsZero() || fresh == guard || !fresh.ValidUntil().After(before) {
							t.Fatal("old guard renewed or fresh original claim not observed")
						}
						binding := []byte(`{"fixture":"first-binding-data"}`)
						if _, err := tx.ExecContext(scoped, `UPDATE system_backup_v2_runtime_resources SET binding_json=? WHERE observed_uid=?`, binding, record.UID); err != nil {
							t.Fatal(err)
						}
						if err := c.RecheckOriginalFirstBindingCommit(scoped, tx, authority, fresh, binding); err != nil {
							t.Fatal("actual first binding final tail", err)
						}
						if got := readLease(tx); !got.After(before) {
							t.Fatal("fresh claim not actually written")
						}
					}
					if census(tx) != beforeRows {
						t.Fatal("first binding changed original evidence/resource/observation census")
					}
					return d.JobBinding{}, nil
				})
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			if !readLease(admin).Equal(before) {
				t.Fatal("rolled back first binding changed committed claim")
			}
		})
	}
	// A spent first-coordination attempt stays read-only after an explicit
	// rollback. Unknown commit is independently marked by the live wrapper.
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback-read-only", true: "unknown-read-only"}[unknown], func(t *testing.T) {
			setLease()
			err := store.RunWithExecutionHeartbeat(ctx, authority, func(active context.Context) error {
				for attempt := 0; attempt < 2; attempt++ {
					_, err := c.WithOriginalControllerBinding(active, authority, record, func(scoped context.Context) (d.JobBinding, error) {
						tx, err := db.BeginTx(scoped, nil)
						if err != nil {
							return d.JobBinding{}, err
						}
						defer tx.Rollback()
						guard, err := owner.Gate.Authority.Bind(scoped, tx, authority)
						if err != nil {
							return d.JobBinding{}, err
						}
						fresh, err := c.PrepareOriginalFirstBinding(scoped, tx, authority, guard)
						if (err == nil) != (attempt == 0) {
							t.Fatal("spent binding reissued after rollback/unknown", attempt, err)
						}
						if attempt == 0 && fresh == guard {
							t.Fatal("first binding did not coordinate")
						}
						if unknown && attempt == 0 {
							return d.JobBinding{}, c.ErrExecutionCommitUnknown
						}
						return d.JobBinding{}, nil
					})
					if err != nil && !(unknown && attempt == 0 && errors.Is(err, c.ErrExecutionCommitUnknown)) {
						return err
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, status := range []string{"pending", "running"} {
		t.Run("committed-cancel-"+status, func(t *testing.T) {
			setLease()
			before := readLease(admin)
			result, err := admin.ExecContext(ctx, `INSERT INTO system_backup_v2_operations(origin_installation_id,target_type,target_public_id,operation_type,status) VALUES(?,'backup',?,'cancel',?)`, authority.InstallationID, authority.TaskPublicID, status)
			if err != nil {
				t.Fatal(err)
			}
			if n, e := result.RowsAffected(); e != nil || n != 1 {
				t.Fatal("actual committed cancellation", n, e)
			}
			t.Cleanup(func() {
				result, err := admin.ExecContext(ctx, `DELETE FROM system_backup_v2_operations WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND operation_type='cancel' AND status=?`, authority.InstallationID, authority.TaskPublicID, status)
				if err != nil {
					t.Error(err)
					return
				}
				if n, e := result.RowsAffected(); e != nil || n != 1 {
					t.Error("owned cancellation cleanup", n, e)
				}
			})
			var count uint64
			if err := admin.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_operations WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND operation_type='cancel' AND status=?`, authority.InstallationID, authority.TaskPublicID, status).Scan(&count); err != nil || count != 1 {
				t.Fatal("committed cancellation independently missing", count, err)
			}
			err = store.RunWithExecutionHeartbeat(ctx, authority, func(active context.Context) error {
				_, err := c.WithOriginalControllerBinding(active, authority, record, func(scoped context.Context) (d.JobBinding, error) {
					tx, err := db.BeginTx(scoped, nil)
					if err != nil {
						return d.JobBinding{}, err
					}
					defer tx.Rollback()
					guard, err := owner.Gate.Authority.Bind(scoped, tx, authority)
					if err == nil {
						guard.Invalidate()
						t.Fatal("current committed cancel acquired initial-binding authority")
					}
					return d.JobBinding{}, nil
				})
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			if !readLease(admin).Equal(before) {
				t.Fatal("canceled task renewed its first binding claim")
			}
		})
	}
	t.Run("actual-heartbeat-cannot-revive-expired-lock-wait", func(t *testing.T) {
		if _, err := admin.ExecContext(ctx, `UPDATE system_backup_v2_backups SET controller_lease_expires_at=TIMESTAMPADD(SECOND,2,UTC_TIMESTAMP(6)) WHERE public_id=?`, authority.TaskPublicID); err != nil {
			t.Fatal(err)
		}
		originalUntil := readLease(admin)
		var originalOwner string
		var originalVersion uint64
		var originalHeartbeat sql.NullTime
		if err := admin.QueryRowContext(ctx, `SELECT controller_owner,row_version,heartbeat_at FROM system_backup_v2_backups WHERE public_id=?`, authority.TaskPublicID).Scan(&originalOwner, &originalVersion, &originalHeartbeat); err != nil {
			t.Fatal(err)
		}
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		locker, err := db.BeginTx(bounded, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer locker.Rollback()
		var lockedUntil time.Time
		if err := locker.QueryRowContext(bounded, `SELECT controller_lease_expires_at FROM system_backup_v2_backups WHERE public_id=? FOR UPDATE`, authority.TaskPublicID).Scan(&lockedUntil); err != nil || !lockedUntil.Equal(originalUntil) {
			t.Fatal("original lease row not locked", err)
		}
		var database string
		if err := admin.QueryRowContext(bounded, "SELECT DATABASE()").Scan(&database); err != nil {
			t.Fatal(err)
		}
		finished := make(chan error, 1)
		queueOnly := c.SQLExecutionWorkStore{Queue: store.Queue}
		go func() { finished <- queueOnly.RenewExecutionLease(bounded, authority) }()
		waiting := false
		for !waiting {
			var count uint64
			if err := admin.QueryRowContext(bounded, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE=w.ENGINE AND l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME='system_backup_v2_backups'`, database).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count > 0 {
				waiting = true
				break
			}
			select {
			case err := <-finished:
				t.Fatal("renewal did not actually wait", err)
			case <-bounded.Done():
				t.Fatal(bounded.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
		for {
			var now time.Time
			if err := admin.QueryRowContext(bounded, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
				t.Fatal(err)
			}
			if !now.Before(originalUntil.Add(20 * time.Millisecond)) {
				break
			}
			select {
			case <-bounded.Done():
				t.Fatal(bounded.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
		if err := locker.Rollback(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-finished:
			if !errors.Is(err, c.ErrClaimLost) {
				t.Errorf("expired original claim renewed after a real lock wait: %v", err)
			}
		case <-bounded.Done():
			t.Fatal(bounded.Err())
		}
		var ownerAfter string
		var versionAfter uint64
		var heartbeatAfter sql.NullTime
		if err := admin.QueryRowContext(ctx, `SELECT controller_owner,row_version,heartbeat_at FROM system_backup_v2_backups WHERE public_id=?`, authority.TaskPublicID).Scan(&ownerAfter, &versionAfter, &heartbeatAfter); err != nil {
			t.Fatal(err)
		}
		if !readLease(admin).Equal(originalUntil) || ownerAfter != originalOwner || versionAfter != originalVersion || heartbeatAfter.Valid != originalHeartbeat.Valid || !heartbeatAfter.Time.Equal(originalHeartbeat.Time) {
			t.Error("expired lock waiter changed committed lease/owner/version/heartbeat")
		}
		err = store.RunWithExecutionHeartbeat(ctx, authority, func(active context.Context) error {
			_, err := c.WithOriginalControllerBinding(active, authority, record, func(scoped context.Context) (d.JobBinding, error) {
				tx, err := db.BeginTx(scoped, nil)
				if err != nil {
					return d.JobBinding{}, err
				}
				defer tx.Rollback()
				guard, err := owner.Gate.Authority.Bind(scoped, tx, authority)
				if err == nil {
					guard.Invalidate()
					t.Error("expired original scope acquired a new binding after lock wait")
				}
				return d.JobBinding{}, nil
			})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("actual-heartbeat-waits-for-first-binding", func(t *testing.T) {
		setLease()
		job.Name = "initial-binding-heartbeat-data"
		currentIntent, err := kube.Intent("Job", &job)
		if err != nil {
			t.Fatal(err)
		}
		currentRecord := kube.ResourceRecord{Intent: currentIntent, Revision: 1, CreateDispatched: true, UID: "initial-binding-heartbeat-uid", ResourceVersion: "1"}
		if _, err := admin.ExecContext(ctx, `INSERT INTO system_backup_v2_runtime_resources(task_public_id,resource_kind,namespace_name,resource_name,resource_owner,request_sha256,request_json,row_version,create_dispatched,observed_uid,resource_version,lifecycle,attempt_no,phase) VALUES(?,'Job',?,?,?,?,?,1,TRUE,?,'1','ready',?,'capture')`, authority.TaskPublicID, currentIntent.Identity.Namespace, currentIntent.Identity.Name, authority.TaskPublicID, currentIntent.RequestSHA256, currentIntent.RequestJSON, currentRecord.UID, authority.AttemptNo); err != nil {
			t.Fatal(err)
		}
		var database string
		if err := admin.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&database); err != nil {
			t.Fatal(err)
		}
		bounded, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		locked, release := make(chan struct{}), make(chan struct{})
		finished := make(chan error, 1)
		var firstUntil time.Time
		var firstHeartbeat time.Time
		err = store.RunWithExecutionHeartbeat(bounded, authority, func(active context.Context) error {
			go func() {
				_, err := c.WithOriginalControllerBinding(active, authority, currentRecord, func(scoped context.Context) (d.JobBinding, error) {
					tx, err := db.BeginTx(scoped, nil)
					if err != nil {
						return d.JobBinding{}, err
					}
					defer tx.Rollback()
					guard, err := owner.Gate.Authority.Bind(scoped, tx, authority)
					if err != nil {
						return d.JobBinding{}, err
					}
					close(locked)
					select {
					case <-release:
					case <-scoped.Done():
						return d.JobBinding{}, scoped.Err()
					}
					fresh, err := c.PrepareOriginalFirstBinding(scoped, tx, authority, guard)
					if err != nil {
						return d.JobBinding{}, err
					}
					firstUntil = readLease(tx)
					if err := tx.QueryRowContext(scoped, `SELECT heartbeat_at FROM system_backup_v2_backups WHERE public_id=?`, authority.TaskPublicID).Scan(&firstHeartbeat); err != nil {
						return d.JobBinding{}, err
					}
					binding := []byte(`{"fixture":"heartbeat-first-binding-data"}`)
					if _, err := tx.ExecContext(scoped, `UPDATE system_backup_v2_runtime_resources SET binding_json=? WHERE observed_uid=?`, binding, currentRecord.UID); err != nil {
						return d.JobBinding{}, err
					}
					if err := c.RecheckOriginalFirstBindingCommit(scoped, tx, authority, fresh, binding); err != nil {
						return d.JobBinding{}, err
					}
					return d.JobBinding{}, tx.Commit()
				})
				finished <- err
			}()
			select {
			case <-locked:
			case err := <-finished:
				return err
			case <-active.Done():
				return active.Err()
			}
			// Only this owned schema is observed. The default five-second
			// heartbeat must actually reach MySQL and wait on the original lock.
			waited := false
			for !waited {
				var count uint64
				if err := admin.QueryRowContext(active, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE=w.ENGINE AND l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME='system_backup_v2_backups'`, database).Scan(&count); err != nil {
					close(release)
					return err
				}
				if count > 0 {
					waited = true
					break
				}
				select {
				case <-active.Done():
					close(release)
					return active.Err()
				case <-time.After(30 * time.Millisecond):
				}
			}
			close(release)
			select {
			case err := <-finished:
				if err != nil {
					return err
				}
			case <-active.Done():
				return active.Err()
			}
			for db.Stats().InUse != 0 {
				select {
				case <-active.Done():
					return active.Err()
				case <-time.After(10 * time.Millisecond):
				}
			}
			if got := readLease(admin); got.Before(firstUntil) {
				t.Errorf("delayed real heartbeat shortened the first-binding claim: first=%s current=%s", firstUntil, got)
			}
			var heartbeatAfter time.Time
			if err := admin.QueryRowContext(ctx, `SELECT heartbeat_at FROM system_backup_v2_backups WHERE public_id=?`, authority.TaskPublicID).Scan(&heartbeatAfter); err != nil {
				return err
			}
			if heartbeatAfter.Before(firstHeartbeat) {
				t.Error("delayed real heartbeat moved heartbeat_at backwards")
			}
			return nil
		})
		if err != nil {
			t.Fatal("real first binding/heartbeat overlap", err)
		}
	})
	t.Run("concurrent-original-two-binding-transactions", func(t *testing.T) {
		setLease()
		records := make([]kube.ResourceRecord, 2)
		for i, name := range []string{"initial-binding-parallel-one", "initial-binding-parallel-two"} {
			copy := job.DeepCopy()
			copy.Name = name
			current, err := kube.Intent("Job", copy)
			if err != nil {
				t.Fatal(err)
			}
			records[i] = kube.ResourceRecord{Intent: current, Revision: 1, CreateDispatched: true, UID: name + "-uid", ResourceVersion: "1"}
			result, err := admin.ExecContext(ctx, `INSERT INTO system_backup_v2_runtime_resources(task_public_id,resource_kind,namespace_name,resource_name,resource_owner,request_sha256,request_json,row_version,create_dispatched,observed_uid,resource_version,lifecycle,attempt_no,phase) VALUES(?,'Job',?,?,?,?,?,1,TRUE,?,'1','ready',?,'capture')`, authority.TaskPublicID, current.Identity.Namespace, current.Identity.Name, authority.TaskPublicID, current.RequestSHA256, current.RequestJSON, records[i].UID, authority.AttemptNo)
			if err != nil {
				t.Fatal(err)
			}
			if n, e := result.RowsAffected(); e != nil || n != 1 {
				t.Fatal("parallel binding test row", n, e)
			}
		}
		err := store.RunWithExecutionHeartbeat(ctx, authority, func(active context.Context) error {
			start := make(chan struct{})
			finished := make(chan error, 2)
			for _, r := range records {
				go func(r kube.ResourceRecord) {
					<-start
					_, err := c.WithOriginalControllerBinding(active, authority, r, func(scoped context.Context) (d.JobBinding, error) {
						tx, err := db.BeginTx(scoped, nil)
						if err != nil {
							return d.JobBinding{}, err
						}
						defer tx.Rollback()
						guard, err := owner.Gate.Authority.Bind(scoped, tx, authority)
						if err != nil {
							return d.JobBinding{}, err
						}
						fresh, err := c.PrepareOriginalFirstBinding(scoped, tx, authority, guard)
						if err != nil {
							return d.JobBinding{}, err
						}
						value := d.JobBinding{Namespace: r.Intent.Identity.Namespace, Name: r.Intent.Identity.Name, UID: r.UID, Generation: 1}
						raw, err := json.Marshal(value)
						if err != nil {
							return d.JobBinding{}, err
						}
						result, err := tx.ExecContext(scoped, `UPDATE system_backup_v2_runtime_resources SET binding_json=? WHERE observed_uid=? AND binding_json IS NULL`, raw, r.UID)
						if err != nil {
							return d.JobBinding{}, err
						}
						if n, e := result.RowsAffected(); e != nil || n != 1 {
							return d.JobBinding{}, errors.New("parallel original binding did not affect exactly one row")
						}
						if err := c.RecheckOriginalFirstBindingCommit(scoped, tx, authority, fresh, raw); err != nil {
							return d.JobBinding{}, err
						}
						return value, tx.Commit()
					})
					finished <- err
				}(r)
			}
			close(start)
			for range records {
				if err := <-finished; err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal("concurrent original binding transactions", err)
		}
		for _, r := range records {
			var raw []byte
			var value d.JobBinding
			if err := admin.QueryRowContext(ctx, `SELECT binding_json FROM system_backup_v2_runtime_resources WHERE observed_uid=?`, r.UID).Scan(&raw); err != nil || json.Unmarshal(raw, &value) != nil || value.UID != r.UID || value.Name != r.Intent.Identity.Name {
				t.Fatal("parallel bindings crossed original Job identities", err)
			}
		}
	})
	t.Run("actual-original-cutoff-after-renewal-row-delivery", func(t *testing.T) {
		result, err := admin.ExecContext(ctx, `UPDATE system_backup_v2_backups SET controller_lease_expires_at=TIMESTAMPADD(SECOND,2,UTC_TIMESTAMP(6)) WHERE public_id=?`, authority.TaskPublicID)
		if err != nil {
			t.Fatal(err)
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			t.Fatal("actual short original claim", n, e)
		}
		originalUntil := readLease(admin)
		delivery.armed.Store(false)
		delivery.fired.Store(false)
		delivery.armAfterInitialBinding.Store(true)
		err = store.RunWithExecutionHeartbeat(ctx, authority, func(active context.Context) error {
			_, err := c.WithOriginalControllerBinding(active, authority, record, func(scoped context.Context) (d.JobBinding, error) {
				tx, err := db.BeginTx(scoped, nil)
				if err != nil {
					return d.JobBinding{}, err
				}
				defer tx.Rollback()
				guard, err := owner.Gate.Authority.Bind(scoped, tx, authority)
				if err != nil {
					return d.JobBinding{}, err
				}
				if _, err := c.PrepareOriginalFirstBinding(scoped, tx, authority, guard); err == nil {
					t.Fatal("fresh claim revived an original cutoff crossed during actual row delivery")
				}
				var now time.Time
				if err := tx.QueryRowContext(scoped, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil || now.Before(originalUntil) || !delivery.fired.Load() || delivery.armAfterInitialBinding.Load() {
					t.Fatal("post-renewal original cutoff fault did not actually trigger", err, now, originalUntil)
				}
				if !guard.ValidUntil().IsZero() {
					t.Fatal("retired original guard revived after actual cutoff")
				}
				return d.JobBinding{}, nil
			})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if !readLease(admin).Equal(originalUntil) {
			t.Fatal("expired original scope committed its provisional new lease")
		}
	})
	t.Run("actual-commit-ack-loss-read-only", func(t *testing.T) {
		setLease()
		before := readLease(admin)
		binding := d.JobBinding{JobUnitKey: "initial-binding-data", Namespace: intent.Identity.Namespace, Name: intent.Identity.Name, UID: record.UID, Generation: 1}
		bindingRaw, err := json.Marshal(binding)
		if err != nil {
			t.Fatal(err)
		}
		err = store.RunWithExecutionHeartbeat(ctx, authority, func(active context.Context) error {
			_, err := c.WithOriginalControllerBinding(active, authority, record, func(scoped context.Context) (d.JobBinding, error) {
				tx, err := db.BeginTx(scoped, nil)
				if err != nil {
					return d.JobBinding{}, err
				}
				defer tx.Rollback()
				guard, err := owner.Gate.Authority.Bind(scoped, tx, authority)
				if err != nil {
					return d.JobBinding{}, err
				}
				fresh, err := c.PrepareOriginalFirstBinding(scoped, tx, authority, guard)
				if err != nil {
					return d.JobBinding{}, err
				}
				result, err := tx.ExecContext(scoped, `UPDATE system_backup_v2_runtime_resources SET binding_json=? WHERE observed_uid=? AND binding_json IS NULL`, bindingRaw, record.UID)
				if err != nil {
					return d.JobBinding{}, err
				}
				n, err := result.RowsAffected()
				if err != nil || n != 1 {
					t.Fatal("original binding first write", n, err)
				}
				if err := c.RecheckOriginalFirstBindingCommit(scoped, tx, authority, fresh, bindingRaw); err != nil {
					return d.JobBinding{}, err
				}
				loseCommit.Store(true)
				if err := tx.Commit(); !errors.Is(err, errAPublicationACKLost) {
					t.Fatal("native committed transaction did not lose only ACK", err)
				}
				return d.JobBinding{}, c.ErrExecutionCommitUnknown
			})
			if !errors.Is(err, c.ErrExecutionCommitUnknown) {
				t.Fatal("unknown first commit changed", err)
			}
			var observed []byte
			if err := admin.QueryRowContext(ctx, `SELECT binding_json FROM system_backup_v2_runtime_resources WHERE observed_uid=?`, record.UID).Scan(&observed); err != nil || !bytes.Equal(bindingRaw, observed) {
				t.Fatal("lost ACK did not leave actual committed original binding", err)
			}
			afterCommit := readLease(admin)
			if !afterCommit.After(before) {
				t.Fatal("native first commit did not persist its fresh claim")
			}
			// This is a native helper/SQL readback, not PublicJobOwner.Bind's
			// certificate/plan admission. The complete fixture covers that entry.
			got, err := c.WithOriginalControllerBinding(active, authority, record, func(scoped context.Context) (d.JobBinding, error) {
				tx, err := db.BeginTx(scoped, nil)
				if err != nil {
					return d.JobBinding{}, err
				}
				defer tx.Rollback()
				guard, err := owner.Gate.Authority.Bind(scoped, tx, authority)
				if err != nil {
					return d.JobBinding{}, err
				}
				var raw []byte
				var current d.JobBinding
				if err := tx.QueryRowContext(scoped, `SELECT binding_json FROM system_backup_v2_runtime_resources WHERE observed_uid=? FOR UPDATE`, record.UID).Scan(&raw); err != nil {
					return d.JobBinding{}, err
				}
				if err := json.Unmarshal(raw, &current); err != nil || current != binding {
					t.Fatal("existing binding readback differs", err)
				}
				if err := guard.Recheck(scoped, tx); err != nil {
					return d.JobBinding{}, err
				}
				return current, tx.Commit()
			})
			if err != nil || got != binding || !readLease(admin).Equal(afterCommit) {
				t.Fatal("unknown retry renewed or replaced committed binding", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	var oldKey []byte
	if err := admin.QueryRowContext(ctx, `SELECT key_use_json FROM system_backup_v2_runtime_resources WHERE observed_uid=?`, originalJob.UID).Scan(&oldKey); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldKey, originalKeyUse) {
		t.Fatal("first-binding fixture changed the original nonce or key-use Until")
	}
}
