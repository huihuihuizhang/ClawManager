package systembackupevidence

import (
	"context"
	"database/sql/driver"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// Derive the metadata fixture from the actual published DDL and candidate
// receipt DDL, not the implementation's reference catalog. No SQL is executed.
func taskOwnerDDLColumns(t *testing.T) map[string]string {
	t.Helper()
	columns := map[string]string{}
	blocks := regexp.MustCompile(`(?ms)^CREATE TABLE (?:IF NOT EXISTS )?([a-z0-9_]+) \(\r?\n(.*?)^\) ENGINE`)
	fields := regexp.MustCompile(`(?m)^  ([a-z0-9_]*evidence_(?:public_)?id) (BIGINT|CHAR|VARCHAR)`)
	consume := func(raw []byte) {
		for _, block := range blocks.FindAllSubmatch(raw, -1) {
			for _, field := range fields.FindAllSubmatch(block[2], -1) {
				columns[string(block[1])+"."+string(field[1])] = strings.ToLower(string(field[2]))
			}
		}
	}
	files, err := filepath.Glob("../db/migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		name := filepath.Base(file)
		if strings.Contains(name, "backup_v2_") && name[:3] >= "096" && name[:3] <= "109" {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			consume(raw)
		}
	}
	raw, err := os.ReadFile("../../../docs/system-backup-d-download-admission-schema-proposal-20261019.sql")
	if err != nil {
		t.Fatal(err)
	}
	consume(raw)
	if !strings.Contains(string(raw), "ADD COLUMN download_evidence_id BIGINT UNSIGNED NULL") {
		t.Fatal("missing actual candidate operation reference")
	}
	columns["system_backup_v2_operations.download_evidence_id"] = "bigint"
	if len(columns) != 25 {
		t.Fatal("reference DDL changed; review the complete graph", len(columns), columns)
	}
	return columns
}

type sqlTaskOwnerModel struct {
	t                        *testing.T
	f                        *admissionTxFixture
	kind                     string
	metadata                 map[string]string
	deadline, created        time.Time
	version                  int64
	origin, taskType, schema string
	fault                    string
	lockedStages             []int
	ownerReads, chunkReads   int
	refs                     map[string][]int64
	producerMatch            bool
}

func newSQLTaskOwnerModel(t *testing.T, f *admissionTxFixture, kind string) *sqlTaskOwnerModel {
	m := &sqlTaskOwnerModel{t: t, f: f, kind: kind, metadata: taskOwnerDDLColumns(t), deadline: f.initial.OwnerDeadline, created: f.initial.CreatedAt.Add(-time.Hour), version: 17, origin: f.initial.Manifest.Identity.Installation, taskType: kind, schema: "system-backup-task.v1", refs: map[string][]int64{}}
	f.db.ownerQuery = m.query
	return m
}
func (m *sqlTaskOwnerModel) ownerRow() []driver.Value {
	hold := m.kind == "backup"
	return []driver.Value{int64(31), m.origin, m.f.initial.Manifest.Identity.OwnerID, m.taskType, m.schema, m.deadline, m.created, m.version, hold, hold}
}
func (m *sqlTaskOwnerModel) mark(stage int, q string) error {
	if !strings.HasSuffix(q, " FOR UPDATE") {
		return nil
	}
	if stage == 3 && m.f.db.ownerLocked {
		m.t.Error("new L3 reference lock after task owner")
		return ErrState
	}
	if stage == 5 && !m.f.db.ownerLocked {
		m.t.Error("L5 reference before task owner")
		return ErrState
	}
	m.lockedStages = append(m.lockedStages, stage)
	if stage == 4 {
		m.f.db.ownerLocked = true
		m.f.db.calls = append(m.f.db.calls, "real-task-owner")
	}
	return nil
}
func (m *sqlTaskOwnerModel) query(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, bool, error) {
	i := m.f.db.record.Manifest.Identity
	if q == taskDownloadPreviewCreatedSQL {
		if args[0].Value != i.ID || args[1].Value != i.Installation {
			m.t.Error("preview creation query lost installation/evidence binding")
			return nil, true, ErrInvalid
		}
		return admissionTxRow(m.f.db.record.CreatedAt), true, nil
	}
	if q == taskDownloadReferenceColumnsSQL {
		if len(args) != 0 {
			return nil, true, ErrInvalid
		}
		keys := make([]string, 0, len(m.metadata))
		for key := range m.metadata {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		rows := &admissionTxRows{width: 3}
		for _, key := range keys {
			pieces := strings.SplitN(key, ".", 2)
			rows.data = append(rows.data, []driver.Value{pieces[0], pieces[1], m.metadata[key]})
		}
		return rows, true, nil
	}
	if q == taskDownloadEvidenceKeySQL {
		var origin driver.Value = i.Installation
		if m.f.db.committedOrigin != nil {
			origin = *m.f.db.committedOrigin
			if origin == "" {
				origin = nil
			}
		}
		return admissionTxRow(int64(61), origin, i.OwnerType, i.OwnerID, i.Classification), true, nil
	}
	if q == "SELECT origin_installation_id FROM system_backup_v2_evidence WHERE public_id=?" {
		var origin driver.Value = i.Installation
		if m.f.db.committedOrigin != nil {
			origin = *m.f.db.committedOrigin
			if origin == "" {
				origin = nil
			}
		}
		return admissionTxRow(origin), true, nil
	}
	for _, table := range taskDownloadTables() {
		if !strings.HasPrefix(q, "SELECT id,origin_installation_id,public_id,task_type,schema_version,") || !strings.Contains(q, " FROM "+table.table+" WHERE ") {
			continue
		}
		m.ownerReads++
		if args[0].Value != i.Installation {
			m.t.Error("owner query lost installation")
			return nil, true, ErrInvalid
		}
		if !strings.Contains(q, "LIMIT 10001") && args[1].Value != i.OwnerID {
			m.t.Error("owner query lost original public ID")
			return nil, true, ErrInvalid
		}
		if strings.Contains(q, " ORDER BY id LIMIT 10001") {
			if err := m.mark(4, q); err != nil {
				return nil, true, err
			}
		}
		rows := &admissionTxRows{width: 10}
		if table.kind == m.kind && m.fault != "owner_missing" {
			rows.data = append(rows.data, m.ownerRow())
		}
		return rows, true, nil
	}
	for _, ref := range taskDownloadReferences() {
		if !strings.Contains(q, " FROM "+ref.table+" WHERE ") || !strings.Contains(q, "LIMIT 10001") {
			continue
		}
		if q != taskDownloadReferenceSQL(ref, strings.HasSuffix(q, " FOR UPDATE")) {
			m.t.Error("unreviewed reference SQL", q)
			return nil, true, ErrInvalid
		}
		first := 0
		if ref.scoped {
			if args[0].Value != i.Installation {
				m.t.Error("reference query lost installation", ref.table)
				return nil, true, ErrInvalid
			}
			first++
		}
		columns := append(append([]string{}, ref.columns...), ref.publicColumns...)
		for index, arg := range args[first:] {
			var want driver.Value = i.ID
			if m.metadata[ref.table+"."+columns[index]] == "bigint" {
				want = int64(61)
			}
			if arg.Value != want {
				m.t.Error("reference query lost evidence identity", ref.table, arg.Value, want)
				return nil, true, ErrInvalid
			}
		}
		if err := m.mark(ref.stage, q); err != nil {
			return nil, true, err
		}
		ids := append([]int64(nil), m.refs[ref.table]...)
		if ref.table == "system_backup_v2_operations" && len(m.f.db.m.op) > 0 {
			ids = append(ids, 73)
		}
		if ref.table == "system_backup_v2_download_admission_receipts" && len(m.f.db.m.receipt) > 0 {
			ids = append(ids, 73)
		}
		if ref.table == "system_backup_v2_download_result_receipts" && len(m.f.db.resultRetention) > 0 {
			ids = append(ids, 73)
		}
		rows := &admissionTxRows{width: 1}
		for _, id := range ids {
			rows.data = append(rows.data, []driver.Value{id})
		}
		return rows, true, nil
	}
	for _, table := range taskDownloadSystemProducerTables {
		if strings.HasPrefix(q, "SELECT evidence_id FROM "+table+" WHERE ") {
			stage := 0
			for _, d := range producerDownloadDefinitions() {
				if d.table == table {
					stage = d.stage
				}
			}
			if err := m.mark(stage, q); err != nil {
				return nil, true, err
			}
			rows := &admissionTxRows{width: 1}
			if m.producerMatch {
				rows.data = append(rows.data, []driver.Value{i.ID})
			}
			return rows, true, nil
		}
	}
	if strings.Contains(q, "FROM system_backup_v2_evidence_chunks") {
		m.chunkReads++
	}
	return nil, false, nil
}
