package systembackupsecurity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// These SQL protocol models exercise the production StageFirst and Stage;
// they do not establish InnoDB serialization or replace the TLS MySQL test.
type firstStageConnector struct {
	state     *signingSQLTestState
	onHistory func()
}

func (c firstStageConnector) Driver() driver.Driver { return proofDriver{} }
func (c firstStageConnector) Connect(context.Context) (driver.Conn, error) {
	return &firstStageConn{signingSQLConn: &signingSQLConn{s: c.state}, onHistory: c.onHistory}, nil
}

type firstStageConn struct {
	*signingSQLConn
	onHistory func()
}

func (c *firstStageConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.HasPrefix(query, "SELECT row_version FROM system_backup_v2_backups") {
		s := c.s
		if c.working == nil || c.readOnly || len(args) != 4 || args[0].Value != s.f.pin.InstallationID || args[1].Value != s.f.task.BackupPublicID || args[2].Value != s.claim.ControllerOwner || args[3].Value != int64(s.claim.RowVersion) || !s.now.Before(s.lease) || !s.now.Before(s.deadline) || s.status != "validating" && s.status != "publishing" {
			return &registrationTestRows{width: 1}, nil
		}
		return registrationRow(int64(s.claim.RowVersion)), nil
	}
	if strings.HasPrefix(query, "SELECT public_id FROM system_backup_v2_evidence") {
		if c.working == nil || len(args) != 1 || args[0].Value != c.s.f.task.BackupPublicID {
			return nil, errors.New("first-stage history outside original task")
		}
		var ids []string
		for id, row := range c.working {
			if strings.HasPrefix(id, "sev_asign_") && row[3] == "backup" && row[4] == args[0].Value {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		rows := &registrationTestRows{width: 1}
		for _, id := range ids {
			rows.data = append(rows.data, []driver.Value{id})
		}
		if c.onHistory != nil {
			c.onHistory()
		}
		return rows, nil
	}
	return c.signingSQLConn.QueryContext(ctx, query, args)
}

func firstStagePrepared(t *testing.T, f *installationSigningFixture, db *sql.DB, claim SQLSigningClaim, purpose string) *SQLPreparedPublicationRecord {
	t.Helper()
	factory, _, _, _ := publicationFactoryFixture(t, f, db)
	q, err := factory.ForTask(context.Background(), f.task.BackupPublicID, claim)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(q.Close)
	p, err := q.PreparePublicationRecord(context.Background(), purpose, publicationFixturePayload(t, f, q.signers.owners[purpose].binding))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func firstStageModel(t *testing.T, purpose string, onHistory func(*signingSQLTestState)) (*installationSigningFixture, *signingSQLTestState, *sql.DB, *SQLPreparedPublicationRecord) {
	t.Helper()
	f, state, _, _ := newSigningSQLFixture(t)
	connector := firstStageConnector{state: state}
	if onHistory != nil {
		connector.onHistory = func() { onHistory(state) }
	}
	db := sql.OpenDB(connector)
	t.Cleanup(func() { db.Close() })
	return f, state, db, firstStagePrepared(t, f, db, state.claim, purpose)
}

func firstStageHistoryRows(t *testing.T, a *SQLArtifactSigningAuthority, purpose string, otherWorkload, otherAttempt, chunked bool) (string, map[string][]driver.Value) {
	t.Helper()
	task, binding := a.task, a.binding
	binding.Purpose = purpose
	if otherWorkload {
		task.Workload.PodUID = "earlier-authenticated-pod"
		task.Workload.ServiceAccountUID = "earlier-authenticated-sa"
	}
	if otherAttempt {
		task.AttemptNo++
	}
	input := signingSQLInput(t, task, binding)
	if chunked {
		// A full valid JWS input with a larger inert payload, not padding
		// appended outside the protected input or a fabricated chunk count.
		payload := []byte(`{"attempt_no":` + fieldsVersion(task.AttemptNo) + `,"backup_public_id":"` + task.BackupPublicID + `","origin_installation_id":"` + binding.InstallationID + `","padding":"` + strings.Repeat("x", 6500) + `","signing_key":{"key_id":"` + binding.KeyID + `","key_version":"` + binding.KeyVersion + `","purpose":"` + purpose + `"}}`)
		var err error
		input, _, err = publicationInput(payload, task, binding)
		if err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(input)
	raw, err := json.Marshal(frozenSQLSigningInput{Version: "system-backup-original-sql-signing-input.v1", Authorization: ArtifactSigningAuthorizationRequest{Task: task, Signing: TransitSigningRequest{Binding: binding, InputSHA256: hex.EncodeToString(digest[:])}}, Input: input, CaptureResultSHA256: strings.Repeat("d", 64), CaptureEpoch: 17})
	if err != nil {
		t.Fatal(err)
	}
	id := signingInputEvidenceID(task, binding.InstallationID, purpose)
	rows := make(map[string][]driver.Value)
	// Production inserts every original chunk and its root with one expiry.
	expiry := time.Now().UTC().Add(time.Hour)
	store := func(key string, body []byte) {
		h := sha256.Sum256(body)
		rows[key] = []driver.Value{body, hex.EncodeToString(h[:]), int64(len(body)), "backup", task.BackupPublicID, "diagnostic", "inline", "healthy", "none", expiry}
	}
	if !chunked {
		store(id, raw)
		return id, rows
	}
	if len(raw) <= maxSigningEvidenceInlineBytes || len(raw) > maxFrozenSigningEvidenceBytes {
		t.Fatal("test must exercise the actual bounded chunk representation")
	}
	count := (len(raw) + signingEvidenceChunkBytes - 1) / signingEvidenceChunkBytes
	for n := 0; n < count; n++ {
		end := (n + 1) * signingEvidenceChunkBytes
		if end > len(raw) {
			end = len(raw)
		}
		body, _ := json.Marshal(frozenSigningChunk{Version: "system-backup-original-sql-signing-chunk.v1", Parent: id, Index: n, Count: count, Data: raw[n*signingEvidenceChunkBytes : end]})
		store(signingChunkID(id, n), body)
	}
	h := sha256.Sum256(raw)
	index, _ := json.Marshal(frozenSigningChunkIndex{Version: "system-backup-original-sql-signing-chunks.v1", Size: len(raw), Count: count, SHA256: hex.EncodeToString(h[:])})
	store(id, index)
	return id, rows
}

func TestPublicationStageFirstHistory(t *testing.T) {
	for _, test := range []struct {
		name, purpose              string
		workload, attempt, chunked bool
		change                     func(string, map[string][]driver.Value)
		allow                      bool
	}{
		{name: "same-input", purpose: "acceptance_record"},
		{name: "earlier-workload", purpose: "acceptance_record", workload: true},
		{name: "expired-earlier-workload", purpose: "acceptance_record", workload: true, change: func(id string, rows map[string][]driver.Value) { rows[id][9] = time.Now().Add(-time.Hour) }},
		{name: "unhealthy", purpose: "acceptance_record", change: func(id string, rows map[string][]driver.Value) { rows[id][7] = "unknown" }},
		{name: "chunked-earlier-workload", purpose: "acceptance_record", workload: true, chunked: true},
		{name: "rootless-chunks", purpose: "acceptance_record", chunked: true, change: func(id string, rows map[string][]driver.Value) { delete(rows, id) }},
		{name: "rootless-earlier-workload", purpose: "acceptance_record", workload: true, chunked: true, change: func(id string, rows map[string][]driver.Value) { delete(rows, id) }},
		{name: "missing-child", purpose: "capture_certificate", chunked: true, change: func(id string, rows map[string][]driver.Value) { delete(rows, signingChunkID(id, 0)) }},
		{name: "extra-child", purpose: "capture_certificate", change: func(id string, rows map[string][]driver.Value) {
			rows[signingChunkID(id, 99)] = append([]driver.Value(nil), rows[id]...)
		}},
		{name: "malformed-root", purpose: "capture_certificate", change: func(id string, rows map[string][]driver.Value) { rows[id][0] = []byte(`{}`) }},
		{name: "normal-capture", purpose: "capture_certificate", allow: true},
		{name: "normal-chunked-capture", purpose: "capture_certificate", chunked: true, allow: true},
		{name: "chunk-expiry-drift", purpose: "capture_certificate", chunked: true, change: func(id string, rows map[string][]driver.Value) {
			rows[id][9] = rows[id][9].(time.Time).Add(time.Second)
		}},
		{name: "expired-complete-other-purpose", purpose: "capture_certificate", allow: true, change: func(id string, rows map[string][]driver.Value) { rows[id][9] = time.Now().Add(-time.Hour) }},
		{name: "other-attempt", purpose: "acceptance_record", attempt: true, allow: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, state, db, p := firstStageModel(t, "acceptance_record", nil)
			id, rows := firstStageHistoryRows(t, p.task.signers.owners["acceptance_record"], test.purpose, test.workload, test.attempt, test.chunked)
			if test.change != nil {
				test.change(id, rows)
			}
			state.evidence = rows
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			err = p.StageFirst(context.Background(), tx)
			if test.allow && err != nil || !test.allow && !errors.Is(err, ErrPublicationFirstStage) {
				t.Fatalf("StageFirst allow=%v error=%v", test.allow, err)
			}
			if !test.allow && state.writes != 0 {
				t.Fatal("history rejection wrote signing evidence")
			}
			if f.login != 0 || f.signed != 0 {
				t.Fatal("StageFirst contacted provider")
			}
		})
	}
}

func TestPublicationStageFirstTransactionAndLegacyStage(t *testing.T) {
	for _, purpose := range []string{"acceptance_record", "catalog_record"} {
		t.Run(purpose, func(t *testing.T) {
			_, state, db, p := firstStageModel(t, purpose, nil)
			ctx := context.Background()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = p.StageFirst(ctx, tx); err != nil {
				t.Fatal(err)
			}
			if len(state.evidence) != 0 || state.commits != 0 {
				t.Fatal("StageFirst committed caller transaction")
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			tx, err = db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = p.StageFirst(ctx, tx); err != nil {
				t.Fatal("rollback consumed first use", err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			tx, err = db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = p.StageFirst(ctx, tx); !errors.Is(err, ErrPublicationFirstStage) {
				t.Fatal("committed input was first again", err)
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			stagePreparedPublication(t, db, p, true) // legacy Stage remains idempotent
		})
	}
}

func TestPublicationStageFirstCurrentAuthority(t *testing.T) {
	for _, phase := range []string{"before-lock", "during-history"} {
		t.Run(phase, func(t *testing.T) {
			var hook func(*signingSQLTestState)
			if phase == "during-history" {
				hook = func(state *signingSQLTestState) { state.claim.RowVersion++ }
			}
			_, state, db, p := firstStageModel(t, "acceptance_record", hook)
			if phase == "before-lock" {
				state.claim.RowVersion++
			}
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err = p.StageFirst(context.Background(), tx); err == nil || state.writes != 0 {
				t.Fatal("stale current claim admitted/written", err)
			}
		})
	}
	var p *SQLPreparedPublicationRecord
	if p.StageFirst(context.Background(), nil) == nil {
		t.Fatal("nil prepared record admitted")
	}
	_, state, db, prepared := firstStageModel(t, "acceptance_record", nil)
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if prepared.StageFirst(ctx, tx) == nil {
		t.Fatal("canceled operation admitted")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if prepared.StageFirst(context.Background(), tx) == nil || state.writes != 0 {
		t.Fatal("completed transaction admitted/written")
	}
}

func TestPublicationStageFirstHistoryBound(t *testing.T) {
	_, state, db, p := firstStageModel(t, "acceptance_record", nil)
	_, rows := firstStageHistoryRows(t, p.task.signers.owners["acceptance_record"], "capture_certificate", false, false, false)
	var sample []driver.Value
	for _, row := range rows {
		sample = row
	}
	for n := 0; n <= maxPublicationFirstStageRows; n++ {
		state.evidence[fmt.Sprintf("sev_asign_%064x", n)] = sample
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = p.StageFirst(context.Background(), tx); !errors.Is(err, ErrPublicationFirstStage) || state.writes != 0 {
		t.Fatal("incomplete bounded history admitted/written", err)
	}
}
