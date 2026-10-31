package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	security "clawreef/internal/systembackupsecurity"
)

type candidateSQLModel struct {
	a                d.Authority
	j                d.JobBinding
	now              time.Time
	digest           string
	writes, reserves int
	fault            string
}
type candidateSQLDriver struct{ m *candidateSQLModel }

func (d candidateSQLDriver) Open(string) (driver.Conn, error) { return &candidateSQLConn{d.m}, nil }

type candidateSQLConn struct{ m *candidateSQLModel }

func (c *candidateSQLConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *candidateSQLConn) Close() error              { return nil }
func (c *candidateSQLConn) Begin() (driver.Tx, error) { return resultTx{}, nil }
func (c *candidateSQLConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	m := c.m
	row := func(v ...driver.Value) (driver.Rows, error) { return &resultRows{values: v}, nil }
	switch {
	case strings.HasPrefix(q, "SELECT candidate_sha256"):
		if len(args) != 6 || args[0].Value != m.a.TaskPublicID || args[1].Value != int64(m.a.AttemptNo) || args[2].Value != m.a.Phase || args[3].Value != m.j.Namespace || args[4].Value != m.j.Name || args[5].Value != m.j.UID {
			return nil, errors.New("candidate escaped original task/attempt/Job")
		}
		if m.fault == "revoked" {
			return row()
		}
		if m.digest == "" {
			return row(nil)
		}
		return row(m.digest)
	case strings.HasPrefix(q, "SELECT control_metadata_capacity_bytes"):
		return row(int64(1 << 30))
	case q == "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)":
		return row("server", "database", m.now)
	case strings.HasPrefix(q, "SELECT sample_at,reserved_bytes"):
		return row(m.now, int64(0))
	}
	return nil, fmt.Errorf("unexpected candidate query: %s", q)
}
func (c *candidateSQLConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	switch {
	case strings.HasPrefix(q, "INSERT IGNORE INTO system_backup_v2_metadata_reservations"):
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(q, "UPDATE system_backup_v2_metadata_reservations"):
		c.m.reserves++
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(q, "UPDATE system_backup_v2_runtime_resources SET candidate_cipher"):
		if len(args) != 9 || args[3].Value != c.m.a.TaskPublicID || args[4].Value != int64(c.m.a.AttemptNo) || args[5].Value != c.m.a.Phase || args[8].Value != c.m.j.UID {
			return nil, errors.New("candidate write escaped original Job")
		}
		if c.m.fault == "lost-cas" {
			return driver.RowsAffected(0), nil
		}
		c.m.writes++
		c.m.digest = args[2].Value.(string)
		return driver.RowsAffected(1), nil
	}
	return nil, fmt.Errorf("candidate emitted noncandidate write: %s", q)
}

func TestFormalCandidateJournalReplaysOriginalWithoutPublishingResult(t *testing.T) {
	for _, fault := range []string{"", "changed-report", "revoked", "lost-cas", "capacity"} {
		t.Run(fault, func(t *testing.T) {
			a, j, _ := resultEvidenceFixture()
			m := &candidateSQLModel{a: a, j: j, now: time.Now().UTC(), fault: fault}
			name := fmt.Sprintf("formal-candidate-%s-%d", fault, time.Now().UnixNano())
			sql.Register(name, candidateSQLDriver{m})
			db, err := sql.Open(name, "")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			owner := &PublicJobOwner{}
			owner.Gate.Records.CapacityReportFile = filepath.Join(t.TempDir(), "capacity.json")
			report := security.CapacityReport{ServerUUID: "server", Database: "database", ObservedAt: m.now, AvailableBytes: 4 << 30}
			if fault == "capacity" {
				report.AvailableBytes = 0
			}
			raw, _ := json.Marshal(report)
			if err = os.WriteFile(owner.Gate.Records.CapacityReportFile, raw, 0600); err != nil {
				t.Fatal(err)
			}
			digest := strings.Repeat("a", 64)
			if fault == "changed-report" {
				m.digest = strings.Repeat("b", 64)
			}
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			err = owner.saveFormalCandidateTx(context.Background(), tx, a, j, "original-key", digest, []byte("opaque-candidate-report-ciphertext"))
			if (err == nil) != (fault == "") {
				t.Fatal("wrong candidate journal outcome", err)
			}
			if err != nil {
				return
			}
			// A committed write with lost ACK may be read/retried. It never
			// consumes capacity again and cannot become result/relay success.
			if err = owner.saveFormalCandidateTx(context.Background(), tx, a, j, "original-key", digest, []byte("different-seal-randomness")); err != nil {
				t.Fatal(err)
			}
			if m.writes != 1 || m.reserves != 1 {
				t.Fatal("candidate retried its mutation/reservation", m.writes, m.reserves)
			}
		})
	}
}

func TestFormalCandidateEncryptedCustodyRejectsCrossTaskAttemptAndJob(t *testing.T) {
	a, j, _ := resultEvidenceFixture()
	a.ConfigSHA256 = strings.Repeat("c", 64)
	r := FormalCandidateRecord{Version: "public-formal-candidate-record.v1", Authority: a, Job: j, InvocationSHA256: strings.Repeat("a", 64), Candidate: worker.FormalCaptureResult{InvocationSHA256: strings.Repeat("a", 64)}}
	raw, _ := json.Marshal(r)
	digest := hash(raw)
	key := bytes.Repeat([]byte{3}, 32)
	var sealed bytes.Buffer
	if err := staging.Seal(context.Background(), &sealed, key, formalCandidateBinding(a, j, digest), func(w io.Writer) error { _, err := w.Write(raw); return err }); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"", "installation", "task", "attempt", "phase", "config", "job-uid", "unit", "key", "truncated"} {
		t.Run(fault, func(t *testing.T) {
			changed, job := a, j
			material := append([]byte(nil), key...)
			cipher := append([]byte(nil), sealed.Bytes()...)
			switch fault {
			case "installation":
				changed.InstallationID = "other"
			case "task":
				changed.TaskPublicID = "sbk_other"
			case "attempt":
				changed.AttemptNo++
			case "phase":
				changed.Phase = "secret_capture"
			case "config":
				changed.ConfigSHA256 = strings.Repeat("f", 64)
			case "job-uid":
				job.UID = "other"
			case "unit":
				job.JobUnitKey = "other"
			case "key":
				material[0]++
			case "truncated":
				cipher = cipher[:len(cipher)-1]
			}
			got, err := openFormalCandidate(context.Background(), changed, job, digest, cipher, material)
			if (err == nil) != (fault == "") {
				t.Fatal("changed candidate custody opened", err)
			}
			if err == nil && got.InvocationSHA256 != r.InvocationSHA256 {
				t.Fatal("original report changed")
			}
		})
	}
}
