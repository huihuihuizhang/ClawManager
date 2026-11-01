package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

type aCertificateWriteACKConnector struct {
	driver.Connector
	lose *atomic.Bool
}

func (c aCertificateWriteACKConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &aCertificateWriteACKConn{aPublicationACKConn{Conn: conn, lose: c.lose}}, nil
}

type aCertificateWriteACKConn struct{ aPublicationACKConn }

func (c *aCertificateWriteACKConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	// Current signer validation legitimately commits read-only transactions
	// after the provider response. Those ACKs must stay untouched when testing
	// the later original signed-byte write commit.
	if options.ReadOnly {
		return tx, nil
	}
	return aPublicationACKTx{Tx: tx, lose: c.lose}, nil
}

// Called only AFTER the actual same original task's complete C/domain receipt,
// original Stage commit, one real external Sign and public verification. No
// capture Authority or test-local complete-capture receipt is manufactured.
func checkAOriginalCertificateKnownResume(t *testing.T, ctx context.Context, f *dOriginalSixPartTask, claim c.ClaimToken, capture publicationVerifiedCapture, prepared *preparedPublicationCaptureCertificate, signers *security.SQLPublicationTaskSigners, raw []byte, sum string, signs *atomic.Int64) {
	t.Helper()
	id := originalCaptureCertificateID(capture.Input.InstallationID, capture.Input.TaskPublicID, capture.Input.CaptureAttemptNo)
	type evidenceSnapshot struct {
		ID, Checksum, ActualSHA   string
		Bytes, Version            uint64
		Expires, Created, Updated time.Time
	}
	snapshot := func() []evidenceSnapshot {
		t.Helper()
		rows, err := f.db.QueryContext(ctx, `SELECT public_id,inline_payload,content_checksum,content_size_bytes,row_version,expires_at,created_at,updated_at FROM system_backup_v2_evidence WHERE owner_target_type='backup' AND owner_target_public_id=? AND LEFT(public_id,?)=? ORDER BY public_id`, f.publicID, len(id), id)
		if err != nil {
			t.Fatal("independent original certificate evidence snapshot", err)
		}
		defer rows.Close()
		var out []evidenceSnapshot
		for rows.Next() {
			var row evidenceSnapshot
			var body []byte
			if err = rows.Scan(&row.ID, &body, &row.Checksum, &row.Bytes, &row.Version, &row.Expires, &row.Created, &row.Updated); err != nil {
				t.Fatal(err)
			}
			row.ActualSHA = hash(body)
			out = append(out, row)
		}
		if rows.Err() != nil || len(out) < 6 {
			t.Fatal("original preparation/dispatch/result evidence is incomplete", rows.Err())
		}
		return out
	}
	before := snapshot()
	known, found, err := f.service.loadOriginalPublicationCaptureCertificate(ctx, claim, capture.Input.CaptureAttemptNo, capture)
	if err != nil || !found || !bytes.Equal(known.bytes, raw) || known.sha256 != sum {
		t.Fatal("current original query did not retain exact signed bytes", err)
	}
	duplicate, err := f.service.storeOriginalPublicationCaptureCertificate(ctx, prepared, bytes.Clone(raw))
	if err != nil || !bytes.Equal(duplicate.bytes, raw) || !duplicate.issued.Equal(known.issued) || !duplicate.expires.Equal(known.expires) {
		t.Fatal("original known-result duplicate recreated signed bytes/times", err)
	}
	resumed, resumedSHA, err := prepared.SignCommitted(ctx)
	if err != nil || !bytes.Equal(resumed, raw) || resumedSHA != sum || signs.Load() != 1 {
		t.Fatal("known result replay invoked signer or replaced bytes", err)
	}
	if _, err = f.service.prepareOriginalCaptureCertificate(ctx, claim, capture.Input.CaptureAttemptNo, capture, signers); !errors.Is(err, c.ErrExecutionCommitUnknown) || signs.Load() != 1 {
		t.Fatal("existing original signing input admitted a fresh preparation", err)
	}
	if after := snapshot(); !reflect.DeepEqual(before, after) {
		t.Fatal("query/idempotent replay changed original evidence bytes/version/expiry/timestamps")
	}
	// These are real SQL codec faults on the SAME original public bytes. Each
	// mutation stays in its own rolled-back admin transaction; it cannot leak
	// into current authority checks or be called a new capture/signing success.
	for _, mode := range []string{"missing-root", "missing-child", "unhealthy-root", "expired-root", "root-alias", "child-index", "child-length", "child-checksum"} {
		func() {
			tx, err := f.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			var query string
			var args []any
			switch mode {
			case "missing-root":
				query, args = `DELETE FROM system_backup_v2_evidence WHERE public_id=?`, []any{id}
			case "missing-child":
				query, args = `DELETE FROM system_backup_v2_evidence WHERE public_id=?`, []any{id + "_p0"}
			case "unhealthy-root":
				query, args = `UPDATE system_backup_v2_evidence SET observed_health='unknown' WHERE public_id=?`, []any{id}
			case "expired-root":
				query, args = `UPDATE system_backup_v2_evidence SET expires_at=UTC_TIMESTAMP(6) WHERE public_id=?`, []any{id}
			default:
				target := id + "_p0"
				if mode == "root-alias" {
					target = id
				}
				var body []byte
				if tx.QueryRowContext(ctx, `SELECT inline_payload FROM system_backup_v2_evidence WHERE public_id=?`, target).Scan(&body) != nil {
					t.Fatal("original evidence fault input unavailable", mode)
				}
				if mode == "root-alias" {
					body = bytes.Replace(body, []byte(`"Version"`), []byte(`"version"`), 1)
				} else {
					var chunk originalCaptureCertificateChunk
					if decodeProviderDeploymentJSON(body, &chunk) != nil {
						t.Fatal("original signed result chunk unavailable")
					}
					if mode == "child-index" {
						chunk.Index++
					} else {
						chunk.Data = chunk.Data[:len(chunk.Data)-1]
					}
					body, err = ce.Canonical(chunk)
					if err != nil {
						t.Fatal(err)
					}
				}
				checksum := hash(body)
				if mode == "child-checksum" {
					checksum = hash([]byte("explicit mismatched SQL checksum fault"))
				}
				query, args = `UPDATE system_backup_v2_evidence SET inline_payload=?,content_checksum=?,content_size_bytes=? WHERE public_id=?`, []any{body, checksum, len(body), target}
			}
			result, err := tx.ExecContext(ctx, query, args...)
			if err != nil {
				t.Fatal("same original codec fault", mode, err)
			}
			if n, err := result.RowsAffected(); err != nil || n != 1 {
				t.Fatal("same original codec fault did not affect one row", mode, err)
			}
			if _, err = readOriginalCaptureCertificateBytes(ctx, tx, capture); !errors.Is(err, c.ErrExecutionRecord) || errors.Is(err, sql.ErrNoRows) {
				t.Fatal("damaged existing signed evidence became absence/usable bytes", mode, err)
			}
			if err = originalCertificatePreparationAbsentTx(ctx, tx, capture); !errors.Is(err, c.ErrExecutionCommitUnknown) || signs.Load() != 1 {
				t.Fatal("damaged signing evidence permitted a new preparation", mode, err)
			}
		}()
	}
	if after := snapshot(); !reflect.DeepEqual(before, after) || signs.Load() != 1 {
		t.Fatal("rolled-back codec faults changed original bytes or invoked signer")
	}
	t.Log("same original certificate known-byte replay and rolled-back SQL codec faults", len(before), signs.Load())
}

// The connector first commits the actual native transaction, then withholds
// its ACK. Independent admin readback identifies which boundary committed.
func checkAOriginalCertificateCommitACK(t *testing.T, ctx context.Context, f *dOriginalSixPartTask, claim c.ClaimToken, capture publicationVerifiedCapture, prepared *preparedPublicationCaptureCertificate, mode string, raw []byte, sum string, resultErr error, fixture *aSameTaskCertificateMaterials) ([]byte, string) {
	t.Helper()
	wantedSigns := int64(0)
	if mode == "store-commit-ack-unknown" {
		wantedSigns = 1
	}
	if !errors.Is(resultErr, c.ErrExecutionCommitUnknown) || fixture.loseCommit.Load() || fixture.signs.Load() != wantedSigns || len(raw) != 0 || sum != "" {
		t.Fatal("actual original SQL ACK fault did not stop at intended boundary", mode, resultErr)
	}
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	id := originalCaptureCertificateID(capture.Input.InstallationID, capture.Input.TaskPublicID, capture.Input.CaptureAttemptNo)
	dispatchRaw, err := readOriginalCertificateEvidenceBytes(ctx, tx, capture, id+"_sent", "system-backup-original-publication-capture-certificate-dispatch-evidence.v1")
	var dispatch originalCaptureCertificateDispatch
	if err != nil || decodeProviderDeploymentJSON(dispatchRaw, &dispatch) != nil || dispatch.Installation != capture.Input.InstallationID || dispatch.Backup != f.publicID || dispatch.Attempt != capture.Input.CaptureAttemptNo || dispatch.CaptureSHA256 != capture.receipt.sha256 || dispatch.PayloadSHA256 != hash(prepared.payload) {
		t.Fatal("independent native commit readback lacks exact original send intent", mode, err)
	}
	storedRaw, storedErr := readOriginalCaptureCertificateBytes(ctx, tx, capture)
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if mode == "dispatch-commit-ack-unknown" {
		if !errors.Is(storedErr, sql.ErrNoRows) {
			t.Fatal("unknown dispatch commit unexpectedly produced a signed result", storedErr)
		}
		if _, _, err = prepared.SignCommitted(ctx); !errors.Is(err, c.ErrExecutionCommitUnknown) || fixture.signs.Load() != 0 {
			t.Fatal("unknown original dispatch ACK authorized a signer retry", err)
		}
		t.Log("same original dispatch native Commit ACK lost; query-only reentry and zero Sign", f.publicID)
		return nil, ""
	}
	if storedErr != nil || len(storedRaw) == 0 {
		t.Fatal("independent native commit readback lacks original signed bytes", storedErr)
	}
	known, found, err := f.service.loadOriginalPublicationCaptureCertificate(ctx, claim, capture.Input.CaptureAttemptNo, capture)
	if err != nil || !found || !bytes.Equal(known.bytes, storedRaw) {
		t.Fatal("current original query did not resolve actual committed signed bytes", err)
	}
	resumed, resumedSHA, err := prepared.SignCommitted(ctx)
	if err != nil || !bytes.Equal(resumed, storedRaw) || resumedSHA != known.sha256 || fixture.signs.Load() != 1 {
		t.Fatal("known signed-byte store ACK loss caused a second signer operation", err)
	}
	t.Log("same original signed-byte native Commit ACK lost; exact query readback and one Sign", f.publicID)
	return resumed, resumedSHA
}
