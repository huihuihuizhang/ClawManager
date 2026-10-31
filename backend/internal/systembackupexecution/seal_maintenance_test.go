package systembackupexecution

import (
	"clawreef/internal/systembackup/staging"
	d "clawreef/internal/systembackupdispatch"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type sealMaintenanceModel struct {
	fault   string
	locked  bool
	queries int
	scope   staging.SealScope
}
type sealMaintenanceDriver struct{ m *sealMaintenanceModel }

func (drv sealMaintenanceDriver) Open(string) (driver.Conn, error) {
	return &sealMaintenanceConn{drv.m}, nil
}

type sealMaintenanceConn struct{ m *sealMaintenanceModel }

func (c *sealMaintenanceConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *sealMaintenanceConn) Close() error { return nil }
func (c *sealMaintenanceConn) Begin() (driver.Tx, error) {
	c.m.locked = true
	return sealMaintenanceTx{c.m}, nil
}

func (c *sealMaintenanceConn) BeginTx(_ context.Context, _ driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}

type sealMaintenanceTx struct{ m *sealMaintenanceModel }

func (t sealMaintenanceTx) Rollback() error { t.m.locked = false; return nil }
func (t sealMaintenanceTx) Commit() error   { return errors.New("cleanup must not mutate SQL") }
func (c *sealMaintenanceConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	m := c.m
	m.queries++
	s := m.scope
	row := func(v ...driver.Value) (driver.Rows, error) { return &resultRows{values: v}, nil }
	if !m.locked {
		return nil, errors.New("unlocked lookup")
	}
	switch {
	case q == "SELECT @@server_uuid,DATABASE()":
		server := "server"
		if m.fault == "server" {
			server = "other"
		}
		return row(server, "db")
	case strings.Contains(q, "FROM system_backup_v2_backups"):
		if len(args) != 2 || args[0].Value != s.Installation || args[1].Value != s.Task || !strings.HasSuffix(q, "FOR SHARE") {
			return nil, errors.New("task scope escaped")
		}
		if m.fault == "missing_task" {
			return row()
		}
		status := "failed"
		if m.fault == "active" {
			status = "capturing"
		}
		sha := s.ConfigSHA256
		if m.fault == "config" {
			sha = "other"
		}
		finished := time.Now().Add(-48 * time.Hour)
		if m.fault == "recent" {
			finished = time.Now()
		}
		return row(status, int64(s.ConfigVersion), sha, finished)
	case strings.Contains(q, "FROM system_backup_v2_runtime_resources"):
		if len(args) != 4 || args[0].Value != s.Task || args[1].Value != s.Namespace || args[2].Value != s.JobName || args[3].Value != s.JobUID || !strings.HasSuffix(q, "FOR SHARE") {
			return nil, errors.New("Job scope escaped")
		}
		if m.fault == "missing_job" {
			return row()
		}
		j := d.JobBinding{UID: s.JobUID, Name: s.JobName, Namespace: s.Namespace, JobUnitKey: s.Unit, Generation: s.Generation}
		if m.fault == "binding" {
			j.Generation++
		}
		raw, _ := json.Marshal(j)
		var result driver.Value
		if m.fault == "result" {
			result = strings.Repeat("f", 64)
		}
		var candidate driver.Value
		if m.fault == "candidate" {
			candidate = strings.Repeat("e", 64)
		}
		return row(m.fault != "not_revoked", result, candidate, raw, int64(s.Attempt))
	case strings.Contains(q, "FROM system_backup_v2_evidence"):
		if len(args) != 1 || args[0].Value != s.Task || !strings.HasSuffix(q, "FOR SHARE") {
			return nil, errors.New("evidence scope escaped")
		}
		if m.fault == "evidence" {
			return row("sev_retained")
		}
		if m.fault == "sql" {
			return nil, errors.New("db unavailable")
		}
		return row()
	case q == "SELECT UTC_TIMESTAMP(6)":
		return row(time.Now())
	}
	return nil, fmt.Errorf("unexpected query %s", q)
}

func TestSealMaintenanceRequiresTerminalRevokedUnreferencedJob(t *testing.T) {
	for _, mode := range []string{"ok", "server", "missing_task", "active", "config", "recent", "missing_job", "binding", "result", "candidate", "not_revoked", "evidence", "sql"} {
		t.Run(mode, func(t *testing.T) {
			scope := staging.SealScope{Installation: "installation_test", Task: "sbk_original", Phase: "capture", Unit: "workspace", Namespace: "ns", JobName: "job", JobUID: "uid", Attempt: 2, Generation: 3, ConfigVersion: 4, ConfigSHA256: strings.Repeat("a", 64), InvocationSHA256: strings.Repeat("b", 64), Binding: staging.Binding{BackupID: "sbk_original"}}
			intent := staging.SealIntent{Schema: "controller-staging-seal-intent.v1", Scope: scope, Original: staging.Receipt{Name: "source.enc", Size: 64, SHA256: strings.Repeat("c", 64)}}
			reference, err := staging.SealReferenceForIntent(intent)
			if err != nil {
				t.Fatal(err)
			}
			m := &sealMaintenanceModel{fault: mode, scope: scope}
			name := fmt.Sprintf("seal-maintenance-%s-%d", mode, time.Now().UnixNano())
			sql.Register(name, sealMaintenanceDriver{m})
			db, err := sql.Open(name, "")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			owner := SealMaintenance{DB: db, Installation: scope.Installation, ServerUUID: "server", Database: "db"}
			removed := false
			allowed, err := owner.WithUnreferencedSeal(context.Background(), intent, reference, func() error {
				if !m.locked {
					t.Fatal("SQL locks released before delete")
				}
				removed = true
				return nil
			})
			if mode == "ok" {
				if err != nil || !allowed || !removed {
					t.Fatal(allowed, err)
				}
			} else if allowed || removed {
				t.Fatal("unsafe orphan admission", mode)
			}
			if m.locked {
				t.Fatal("SQL locks leaked")
			}
		})
	}
}

func TestSealMaintenanceRejectsWrongReferenceBeforeSQL(t *testing.T) {
	scope := staging.SealScope{Installation: "installation_test", Task: "sbk_original", Phase: "capture", Unit: "workspace", Namespace: "ns", JobName: "job", JobUID: "uid", Attempt: 2, Generation: 3, ConfigVersion: 4, ConfigSHA256: strings.Repeat("a", 64), InvocationSHA256: strings.Repeat("b", 64), Binding: staging.Binding{BackupID: "sbk_original"}}
	intent := staging.SealIntent{Schema: "controller-staging-seal-intent.v1", Scope: scope, Original: staging.Receipt{Name: "source.enc", Size: 64, SHA256: strings.Repeat("c", 64)}}
	m := &sealMaintenanceModel{fault: "ok", scope: scope}
	name := fmt.Sprintf("seal-maintenance-ref-%d", time.Now().UnixNano())
	sql.Register(name, sealMaintenanceDriver{m})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	owner := SealMaintenance{DB: db, Installation: scope.Installation, ServerUUID: "server", Database: "db"}
	removed := false
	allowed, err := owner.WithUnreferencedSeal(context.Background(), intent, "controller-staging-seal.v1/seal-"+strings.Repeat("0", 64)+".enc", func() error { removed = true; return nil })
	if err == nil || allowed || removed || m.locked {
		t.Fatal("wrong reference reached SQL or removed a seal", allowed, err)
	}
}
