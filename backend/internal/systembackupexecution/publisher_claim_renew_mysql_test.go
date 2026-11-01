package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// An owned metadata-row protocol probe, not publisher artifact authority.
func TestOriginalPublisherRenewRefusesExpiredLockWaitMySQL(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("owned local MySQL required")
	}
	_, _, admin, db, a, _, _, _, _ := newConsumerMySQLFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if _, err := admin.ExecContext(ctx, `ALTER TABLE system_backup_v2_backups ADD COLUMN heartbeat_at DATETIME(6) NULL`); err != nil {
		t.Fatal(err)
	}
	r, err := admin.ExecContext(ctx, `UPDATE system_backup_v2_backups SET status='validating',heartbeat_at=UTC_TIMESTAMP(6),controller_lease_expires_at=TIMESTAMPADD(SECOND,2,UTC_TIMESTAMP(6)) WHERE public_id=?`, a.TaskPublicID)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := r.RowsAffected(); err != nil || n != 1 {
		t.Fatal("owned row not set", n, err)
	}
	var before, heartbeat time.Time
	var owner, database string
	var version uint64
	if err := admin.QueryRowContext(ctx, `SELECT controller_lease_expires_at,heartbeat_at,controller_owner,row_version,DATABASE() FROM system_backup_v2_backups WHERE public_id=?`, a.TaskPublicID).Scan(&before, &heartbeat, &owner, &version, &database); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var locked time.Time
	if err := tx.QueryRowContext(ctx, `SELECT controller_lease_expires_at FROM system_backup_v2_backups WHERE public_id=? FOR UPDATE`, a.TaskPublicID).Scan(&locked); err != nil || !locked.Equal(before) {
		t.Fatal("original row lock", err)
	}
	finished := make(chan error, 1)
	go func() {
		_, err := (c.ClaimCoordinator{Executor: db, InstallationID: a.InstallationID}).Renew(ctx, c.ClaimToken{Target: c.Target{Kind: c.TargetBackup, PublicID: a.TaskPublicID}, Owner: owner, RowVersion: version}, c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second})
		finished <- err
	}()
	for {
		var waits int
		if err := admin.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE=w.ENGINE AND l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME='system_backup_v2_backups'`, database).Scan(&waits); err != nil {
			t.Fatal(err)
		}
		if waits > 0 {
			break
		}
		select {
		case err := <-finished:
			t.Fatal("renew did not wait", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	for {
		var now time.Time
		if err := admin.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
			t.Fatal(err)
		}
		if !now.Before(before.Add(20 * time.Millisecond)) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if !errors.Is(err, c.ErrClaimLost) {
			t.Errorf("publisher renewal revived an expired claim after actual row-lock wait: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var after, heartbeatAfter time.Time
	var ownerAfter string
	var versionAfter uint64
	if err := admin.QueryRowContext(ctx, `SELECT controller_lease_expires_at,heartbeat_at,controller_owner,row_version FROM system_backup_v2_backups WHERE public_id=?`, a.TaskPublicID).Scan(&after, &heartbeatAfter, &ownerAfter, &versionAfter); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	if !after.Equal(before) || !heartbeatAfter.Equal(heartbeat) || ownerAfter != owner || versionAfter != version {
		t.Errorf("expired publisher claim changed durable lease/heartbeat/owner/version: before=%s/%d after=%s/%d", before, version, after, versionAfter)
	}
}

func TestOriginalPublisherRenewCurrentCASMySQL(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("owned local MySQL required")
	}
	_, _, admin, db, a, job, _, _, _ := newConsumerMySQLFixture(t)
	ctx := context.Background()
	if _, err := admin.ExecContext(ctx, `ALTER TABLE system_backup_v2_backups ADD COLUMN heartbeat_at DATETIME(6) NULL`); err != nil {
		t.Fatal(err)
	}
	var originalBinding, originalKeyUse []byte
	if err := admin.QueryRowContext(ctx, `SELECT binding_json,key_use_json FROM system_backup_v2_runtime_resources WHERE observed_uid=?`, job.UID).Scan(&originalBinding, &originalKeyUse); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"db", "conn", "longer-original-lease", "wrong-owner", "wrong-version", "wrong-installation", "terminal", "expired"} {
		t.Run(mode, func(t *testing.T) {
			seconds := 30
			if mode == "longer-original-lease" {
				seconds = 60
			}
			if mode == "expired" {
				seconds = -1
			}
			status := "validating"
			if mode == "terminal" {
				status = "failed"
			}
			r, err := admin.ExecContext(ctx, `UPDATE system_backup_v2_backups SET status=?,controller_owner=?,row_version=?,heartbeat_at=UTC_TIMESTAMP(6),controller_lease_expires_at=TIMESTAMPADD(SECOND,?,UTC_TIMESTAMP(6)) WHERE public_id=?`, status, a.ClaimOwner, a.ClaimRowVersion, seconds, a.TaskPublicID)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := r.RowsAffected(); err != nil || n != 1 {
				t.Fatal("owned fixture row not set", n, err)
			}
			var before, heartbeat time.Time
			if err := admin.QueryRowContext(ctx, `SELECT controller_lease_expires_at,heartbeat_at FROM system_backup_v2_backups WHERE public_id=?`, a.TaskPublicID).Scan(&before, &heartbeat); err != nil {
				t.Fatal(err)
			}
			token := c.ClaimToken{Target: c.Target{Kind: c.TargetBackup, PublicID: a.TaskPublicID}, Owner: a.ClaimOwner, RowVersion: a.ClaimRowVersion}
			installation := a.InstallationID
			if mode == "wrong-owner" {
				token.Owner = "other-controller"
			}
			if mode == "wrong-version" {
				token.RowVersion++
			}
			if mode == "wrong-installation" {
				installation = "installation_other"
			}
			var executor c.Executor = db
			if mode == "conn" {
				conn, err := db.Conn(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				executor = conn
			}
			policy := c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}
			fresh, err := c.RenewClaimInInstallation(ctx, executor, installation, token, policy)
			healthy := mode == "db" || mode == "conn" || mode == "longer-original-lease"
			if healthy {
				if err != nil || fresh.RowVersion != token.RowVersion+1 || fresh.Owner != token.Owner || fresh.Target != token.Target {
					t.Fatal("actual current CAS", fresh, err)
				}
			} else if !errors.Is(err, c.ErrClaimLost) || fresh != (c.ClaimToken{}) {
				t.Fatal("invalid renewal escaped", fresh, err)
			}
			var after, heartbeatAfter time.Time
			var ownerAfter string
			var versionAfter uint64
			if err := admin.QueryRowContext(ctx, `SELECT controller_lease_expires_at,heartbeat_at,controller_owner,row_version FROM system_backup_v2_backups WHERE public_id=?`, a.TaskPublicID).Scan(&after, &heartbeatAfter, &ownerAfter, &versionAfter); err != nil {
				t.Fatal(err)
			}
			if ownerAfter != a.ClaimOwner {
				t.Fatal("owner changed")
			}
			if healthy {
				if versionAfter != fresh.RowVersion || after.Before(before) || heartbeatAfter.Before(heartbeat) || !after.Equal(heartbeatAfter.Add(policy.TTL)) && !(mode == "longer-original-lease" && after.Equal(before)) {
					t.Fatal("actual monotonic renewal counter/clock", versionAfter, after, heartbeatAfter)
				}
				if got, err := c.RenewClaimInInstallation(ctx, executor, a.InstallationID, token, policy); !errors.Is(err, c.ErrClaimLost) || got != (c.ClaimToken{}) {
					t.Fatal("old RV accepted after renewal", got, err)
				}
			} else if versionAfter != a.ClaimRowVersion || !after.Equal(before) || !heartbeatAfter.Equal(heartbeat) {
				t.Fatal("invalid renewal changed durable row")
			}
		})
	}
	var binding, keyUse []byte
	if err := admin.QueryRowContext(ctx, `SELECT binding_json,key_use_json FROM system_backup_v2_runtime_resources WHERE observed_uid=?`, job.UID).Scan(&binding, &keyUse); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalBinding, binding) || !bytes.Equal(originalKeyUse, keyUse) {
		t.Fatal("generic claim renewal changed original Job/key-use bytes")
	}
}

func TestOriginalPublisherRenewRejectsChangedOwnerOrVersionAfterLockWaitMySQL(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("owned local MySQL required")
	}
	_, _, admin, db, a, _, _, _, _ := newConsumerMySQLFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := admin.ExecContext(ctx, `ALTER TABLE system_backup_v2_backups ADD COLUMN heartbeat_at DATETIME(6) NULL`); err != nil {
		t.Fatal(err)
	}
	var database string
	if err := admin.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&database); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"owner", "version"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := admin.ExecContext(ctx, `UPDATE system_backup_v2_backups SET status='validating',controller_owner=?,row_version=?,heartbeat_at=UTC_TIMESTAMP(6),controller_lease_expires_at=TIMESTAMPADD(SECOND,30,UTC_TIMESTAMP(6)) WHERE public_id=?`, a.ClaimOwner, a.ClaimRowVersion, a.TaskPublicID); err != nil {
				t.Fatal(err)
			}
			var before, heartbeat time.Time
			if err := admin.QueryRowContext(ctx, `SELECT controller_lease_expires_at,heartbeat_at FROM system_backup_v2_backups WHERE public_id=?`, a.TaskPublicID).Scan(&before, &heartbeat); err != nil {
				t.Fatal(err)
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			var locked time.Time
			if err := tx.QueryRowContext(ctx, `SELECT controller_lease_expires_at FROM system_backup_v2_backups WHERE public_id=? FOR UPDATE`, a.TaskPublicID).Scan(&locked); err != nil || !locked.Equal(before) {
				t.Fatal("original lock", err)
			}
			finished := make(chan error, 1)
			go func() {
				got, err := c.RenewClaimInInstallation(ctx, db, a.InstallationID, c.ClaimToken{Target: c.Target{Kind: c.TargetBackup, PublicID: a.TaskPublicID}, Owner: a.ClaimOwner, RowVersion: a.ClaimRowVersion}, c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second})
				if got != (c.ClaimToken{}) {
					finished <- errors.New("changed ownership returned a token")
					return
				}
				finished <- err
			}()
			for {
				var waits int
				if err := admin.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE=w.ENGINE AND l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME='system_backup_v2_backups'`, database).Scan(&waits); err != nil {
					t.Fatal(err)
				}
				if waits > 0 {
					break
				}
				select {
				case err := <-finished:
					t.Fatal("renew did not wait", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(20 * time.Millisecond):
				}
			}
			owner, version := a.ClaimOwner, a.ClaimRowVersion
			if mode == "owner" {
				owner = "committed-other-controller"
			} else {
				version++
			}
			r, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_backups SET controller_owner=?,row_version=? WHERE public_id=?`, owner, version, a.TaskPublicID)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := r.RowsAffected(); err != nil || n != 1 {
				t.Fatal("owned fault not applied", n, err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-finished:
				if !errors.Is(err, c.ErrClaimLost) {
					t.Fatal("changed authority renewed", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			var after, heartbeatAfter time.Time
			var ownerAfter string
			var versionAfter uint64
			if err := admin.QueryRowContext(ctx, `SELECT controller_lease_expires_at,heartbeat_at,controller_owner,row_version FROM system_backup_v2_backups WHERE public_id=?`, a.TaskPublicID).Scan(&after, &heartbeatAfter, &ownerAfter, &versionAfter); err != nil {
				t.Fatal(err)
			}
			if !after.Equal(before) || !heartbeatAfter.Equal(heartbeat) || ownerAfter != owner || versionAfter != version {
				t.Fatal("renew changed the committed takeover row")
			}
		})
	}
}
