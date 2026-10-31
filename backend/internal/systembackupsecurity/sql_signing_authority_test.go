package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// This model uses real database/sql transactions and the production SQL,
// including original-task and exact evidence arguments. It does not prove
// InnoDB lock behavior, migration/grants installation or a real production owner.
type signingSQLTestState struct {
	t                                                     *testing.T
	f                                                     *installationSigningFixture
	grant                                                 SQLSigningOwnerGrant
	claim                                                 SQLSigningClaim
	now, lease, deadline                                  time.Time
	status, attemptStatus, parts, captureHash             string
	attempt, epoch                                        int64
	canceled, missingSource, sourceRunning, wrongDatabase bool
	evidence                                              map[string][]driver.Value
	writes, commits                                       int
}
type signingSQLConnector struct{ s *signingSQLTestState }

func (c signingSQLConnector) Driver() driver.Driver { return proofDriver{} }
func (c signingSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &signingSQLConn{s: c.s}, nil
}

type signingSQLConn struct {
	s        *signingSQLTestState
	working  map[string][]driver.Value
	readOnly bool
}

func (c *signingSQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *signingSQLConn) Close() error                        { return nil }
func (c *signingSQLConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *signingSQLConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if c.working != nil {
		return nil, errors.New("nested tx")
	}
	c.readOnly = o.ReadOnly
	c.working = map[string][]driver.Value{}
	for k, v := range c.s.evidence {
		c.working[k] = append([]driver.Value(nil), v...)
	}
	return &signingSQLTx{c}, nil
}

type signingSQLTx struct{ c *signingSQLConn }

func (t *signingSQLTx) Commit() error {
	if !t.c.readOnly {
		t.c.s.evidence = t.c.working
		t.c.s.commits++
	}
	t.c.working = nil
	return nil
}
func (t *signingSQLTx) Rollback() error { t.c.working = nil; return nil }
func (c *signingSQLConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.s
	// Production factory startup and original task lookup are bounded SELECTs
	// outside Stage; source authorization below still uses original SQL txs.
	if q == "SELECT CURRENT_USER(),@@server_uuid,DATABASE()" {
		server := s.grant.ServerUUID
		if s.wrongDatabase {
			server = "other-server"
		}
		return registrationRow(s.grant.DatabaseAccount, server, s.grant.Database), nil
	}
	if strings.HasPrefix(q, "SELECT request_id FROM system_backup_v2_backups") {
		if len(args) != 4 || args[0].Value != s.f.pin.InstallationID || args[1].Value != s.f.task.BackupPublicID || args[2].Value != s.claim.ControllerOwner || args[3].Value != int64(s.claim.RowVersion) || s.status != "validating" && s.status != "publishing" || !s.now.Before(s.lease) || !s.now.Before(s.deadline) {
			return &registrationTestRows{width: 1}, nil
		}
		return registrationRow(s.f.task.OperationID), nil
	}
	if c.working == nil && strings.HasPrefix(q, "SELECT attempt_no,status FROM system_backup_v2_attempts") {
		return registrationRow(s.attempt, s.attemptStatus), nil
	}
	if c.working == nil {
		return nil, errors.New("query outside original transaction")
	}
	switch {
	case strings.HasPrefix(q, "SELECT CURRENT_USER()"):
		server := s.grant.ServerUUID
		if s.wrongDatabase {
			server = "other-server"
		}
		return registrationRow(s.grant.DatabaseAccount, server, s.grant.Database, s.now), nil
	case strings.Contains(q, "FROM system_backup_v2_backups"):
		if len(args) != 2 || args[0].Value != s.f.pin.InstallationID || args[1].Value != s.f.task.BackupPublicID {
			return registrationRow(), nil
		}
		return registrationRow(s.f.pin.InstallationID, s.f.task.OperationID, s.status, s.claim.ControllerOwner, int64(s.claim.RowVersion), s.lease, s.deadline, int64(s.grant.ConfigVersion), s.grant.ConfigSHA256, "acceptance", s.parts), nil
	case strings.Contains(q, "FROM system_backup_v2_attempts"):
		return registrationRow(s.attempt, s.attemptStatus), nil
	case strings.Contains(q, "FROM system_backup_v2_operations"):
		v := int64(0)
		if s.canceled {
			v = 1
		}
		return registrationRow(v), nil
	case strings.Contains(q, "FROM system_backup_v2_runtime_captures"):
		if s.sourceRunning {
			return registrationRow(s.epoch, nil, nil), nil
		}
		return registrationRow(s.epoch, s.now.Add(-time.Second), s.now), nil
	case strings.Contains(q, "FROM system_backup_v2_execution_records"):
		if len(args) != 3 || args[2].Value != s.attempt {
			return registrationRow(), nil
		}
		if s.missingSource {
			return &registrationTestRows{width: 1}, nil
		}
		return registrationRow(s.captureHash), nil
	case strings.Contains(q, "FROM system_backup_v2_evidence"):
		id := args[0].Value.(string)
		v, ok := c.working[id]
		if !ok {
			return &registrationTestRows{width: 10}, nil
		}
		return registrationRow(v...), nil
	default:
		s.t.Errorf("unexpected signing SQL %s", q)
		return nil, errors.New("unexpected SQL")
	}
}
func (c *signingSQLConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if c.readOnly || c.working == nil || !strings.HasPrefix(q, "INSERT INTO system_backup_v2_evidence") || len(args) != 6 {
		return nil, errors.New("unexpected write")
	}
	id := args[0].Value.(string)
	if _, ok := c.working[id]; ok {
		return nil, errors.New("duplicate evidence")
	}
	c.working[id] = []driver.Value{bytes.Clone(args[2].Value.([]byte)), args[3].Value, args[4].Value, "backup", args[1].Value, "diagnostic", "inline", "healthy", "none", args[5].Value}
	c.s.writes++
	return driver.RowsAffected(1), nil
}

func newSigningSQLFixture(t *testing.T) (*installationSigningFixture, *signingSQLTestState, *sql.DB, *SQLInstallationArtifactSigners) {
	t.Helper()
	f := newInstallationSigningFixture(t)
	grant := SQLSigningOwnerGrant{ServerUUID: "isolated-server-uuid", Database: "isolated_backup", DatabaseAccount: "backup_signer@localhost", ControllerOwner: "original-controller", ConfigVersion: 3, ConfigSHA256: strings.Repeat("c", 64), Workload: f.task.Workload}
	for i := range f.record.Permissions {
		copy := grant
		f.record.Permissions[i].SQLOwner = &copy
	}
	f.writeRecord(true)
	now := time.Now().UTC()
	state := &signingSQLTestState{t: t, f: f, grant: grant, claim: SQLSigningClaim{ControllerOwner: grant.ControllerOwner, RowVersion: 11}, now: now, lease: now.Add(time.Minute), deadline: now.Add(2 * time.Minute), status: "validating", attemptStatus: "sealed", parts: "mysql,redis,object_storage,workspace,deployment_resources,secret_bundle", captureHash: strings.Repeat("d", 64), attempt: f.task.AttemptNo, epoch: 17, evidence: map[string][]driver.Value{}}
	db := sql.OpenDB(signingSQLConnector{state})
	t.Cleanup(func() { db.Close() })
	s, err := NewSQLInstallationArtifactSigners(context.Background(), db, f.reader, f.pin, f.mounts, f.task, state.claim)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return f, state, db, s
}

func signingSQLInput(t *testing.T, task ArtifactSigningTask, b TransitSigningBinding) []byte {
	t.Helper()
	typ := map[string]string{"capture_certificate": "clawmanager.system-backup.capture_certificate.v1", "acceptance_record": "clawmanager.system-backup.acceptance.v1", "catalog_record": "clawmanager.system-backup.catalog_record.v1"}[b.Purpose]
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": b.KeyID, "key_version": b.KeyVersion, "purpose": b.Purpose, "typ": typ})
	payload, _ := json.Marshal(map[string]any{"origin_installation_id": b.InstallationID, "backup_public_id": task.BackupPublicID, "attempt_no": task.AttemptNo, "signing_key": map[string]any{"purpose": b.Purpose, "key_id": b.KeyID, "key_version": b.KeyVersion}, "owner_frozen_test_evidence": "local SQL protocol model only"})
	header, err := jsoncanonicalizer.Transform(header)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = jsoncanonicalizer.Transform(payload)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload))
}

func stageSigningSQLFixture(t *testing.T, db *sql.DB, s *SQLInstallationArtifactSigners, purpose string, input []byte, commit bool) {
	t.Helper()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = s.StageSigningInput(context.Background(), tx, purpose, input); err != nil {
		t.Fatal(err)
	}
	if commit {
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSQLInstallationArtifactSignersAutomaticOriginalTaskToTLS(t *testing.T) {
	f, state, db, s := newSigningSQLFixture(t)
	for _, mount := range f.mounts {
		input := signingSQLInput(t, f.task, mount.Binding)
		stageSigningSQLFixture(t, db, s, mount.Binding.Purpose, input, false)
		if len(state.evidence) != 0 {
			t.Fatal("Stage committed caller transaction")
		}
		stageSigningSQLFixture(t, db, s, mount.Binding.Purpose, input, true)
		stageSigningSQLFixture(t, db, s, mount.Binding.Purpose, input, true)
		signer, _ := s.Signer(mount.Binding.Purpose)
		value, err := signer.Sign(context.Background(), input)
		if err != nil {
			t.Fatal(mount.Binding.Purpose, err)
		}
		h, err := s.History(context.Background())
		if err != nil || !ed25519.Verify(h.PurposeKeys(mount.Binding.Purpose)[0].PublicKey, input, value) {
			t.Fatal("SQL original owner did not verify", err)
		}
		// Preserve already committed evidence across rollback assertions for
		// the next purpose without confusing it with a new committed row.
		state.evidence = map[string][]driver.Value{}
	}
	if f.login != 3 || f.signed != 3 || f.authorized != 0 {
		t.Fatal("SQL factory fell back to fixture or offline task owner", f.login, f.signed, f.authorized)
	}
}

func TestSQLSigningAuthorityRejectsDriftBeforeProvider(t *testing.T) {
	for name, mutate := range map[string]func(*signingSQLTestState){
		"claim takeover":         func(s *signingSQLTestState) { s.claim.ControllerOwner = "other" },
		"claim version":          func(s *signingSQLTestState) { s.claim.RowVersion++ },
		"claim expired":          func(s *signingSQLTestState) { s.lease = s.now },
		"wrong database":         func(s *signingSQLTestState) { s.wrongDatabase = true },
		"cancellation":           func(s *signingSQLTestState) { s.canceled = true },
		"new attempt":            func(s *signingSQLTestState) { s.attempt++ },
		"missing source":         func(s *signingSQLTestState) { s.missingSource = true },
		"source not recovered":   func(s *signingSQLTestState) { s.sourceRunning = true },
		"missing domain":         func(s *signingSQLTestState) { s.parts = "workspace" },
		"new capture epoch":      func(s *signingSQLTestState) { s.epoch++ },
		"changed capture result": func(s *signingSQLTestState) { s.captureHash = strings.Repeat("e", 64) },
		"failed task":            func(s *signingSQLTestState) { s.status = "failed" },
	} {
		t.Run(name, func(t *testing.T) {
			f, state, db, s := newSigningSQLFixture(t)
			input := signingSQLInput(t, f.task, f.mounts[0].Binding)
			stageSigningSQLFixture(t, db, s, "capture_certificate", input, true)
			mutate(state)
			signer, _ := s.Signer("capture_certificate")
			value, err := signer.Sign(context.Background(), input)
			if err == nil || len(value) != 0 || f.login != 0 || f.signed != 0 {
				t.Fatal("drift reached provider")
			}
		})
	}
}

func TestSQLSigningAuthorityRefusesUncommittedAndReboundInput(t *testing.T) {
	f, state, db, s := newSigningSQLFixture(t)
	input := signingSQLInput(t, f.task, f.mounts[0].Binding)
	stageSigningSQLFixture(t, db, s, "capture_certificate", input, false)
	signer, _ := s.Signer("capture_certificate")
	if _, err := signer.Sign(context.Background(), input); err == nil || f.login != 0 {
		t.Fatal("uncommitted input authorized")
	}
	stageSigningSQLFixture(t, db, s, "capture_certificate", input, true)
	changedTask := f.task
	changedTask.AttemptNo++
	wrong := signingSQLInput(t, changedTask, f.mounts[0].Binding)
	tx, _ := db.BeginTx(context.Background(), nil)
	defer tx.Rollback()
	if s.StageSigningInput(context.Background(), tx, "capture_certificate", wrong) == nil {
		t.Fatal("cross-attempt input frozen")
	}
	id := signingInputEvidenceID(f.task, f.pin.InstallationID, "capture_certificate")
	v := state.evidence[id]
	raw := append(bytes.Clone(v[0].([]byte)), byte(' '))
	h := sha256.Sum256(raw)
	v[0] = raw
	v[1] = hex.EncodeToString(h[:])
	v[2] = int64(len(raw))
	v[4] = "sbk_other"
	state.evidence[id] = v
	if _, err := signer.Sign(context.Background(), input); err == nil || f.login != 0 {
		t.Fatal("foreign evidence authorized")
	}
}

func TestSQLSigningAuthorityRechecksAfterProviderAndCurrentMaterial(t *testing.T) {
	f, state, db, s := newSigningSQLFixture(t)
	input := signingSQLInput(t, f.task, f.mounts[0].Binding)
	stageSigningSQLFixture(t, db, s, "capture_certificate", input, true)
	f.afterSign = func() { state.canceled = true }
	signer, _ := s.Signer("capture_certificate")
	if value, err := signer.Sign(context.Background(), input); err == nil || len(value) != 0 || f.signed != 1 {
		t.Fatal("post-call cancellation did not discard signature")
	}
	state.canceled = false
	f.afterSign = nil
	f.record.Permissions[0].SQLOwner = nil
	f.writeRecord(false)
	if _, err := signer.Sign(context.Background(), input); err == nil || f.login != 1 {
		t.Fatal("revoked original SQL capability reached provider")
	}
}
