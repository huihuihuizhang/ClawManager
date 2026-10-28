package systembackupevidence

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupsecurity"
)

// Only the SQL transport is modeled here. These tests establish request/key
// ordering and rejection behavior, not InnoDB gap locking or current authority.
func TestDownloadAdmissionKeysExactScopeAndPrivateCapability(t *testing.T) {
	d, tx, _, f := downloadBindingFixture(t)
	queries := []string{}
	d.extraQuery = func(q string, args []driver.NamedValue) (driver.Rows, error) {
		queries = append(queries, q)
		if len(args) < 2 || args[0].Value != f.Intent.Installation {
			t.Fatal("wrong installation")
		}
		switch q {
		case downloadAdmissionKeySQL, downloadAdmissionTombstoneSQL:
			if len(args) != 3 || args[1].Value != "42" || args[2].Value != f.Proof.Request().IdempotencyKey() {
				t.Fatal("wrong exact key", args)
			}
			if q == downloadAdmissionKeySQL {
				return &admissionKeyRows{width: 2}, nil
			}
			return &admissionKeyRows{width: 1}, nil
		case downloadAdmissionReceiptKeySQL:
			if len(args) != 2 || args[1].Value != f.Intent.OperationID {
				t.Fatal("wrong receipt key")
			}
			return &admissionKeyRows{width: 1}, nil
		default:
			t.Fatal("unexpected SQL", q)
		}
		return nil, errors.New("unexpected SQL")
	}
	key, err := LockDownloadAdmissionKey(context.Background(), tx, f.Actor, f.Proof, f.Intent.OperationID)
	if err != nil || key == nil {
		t.Fatal(err)
	}
	if key.tx != tx || key.operationID != f.Intent.OperationID || key.request.RequestHash() != f.Proof.Request().RequestHash() || !sameDownloadAdmissionActor(key.actor, f.Actor) || !key.observedAt.Equal(d.now) {
		t.Fatal("key binding drift")
	}
	if strings.Join(queries, "\n") != strings.Join([]string{downloadAdmissionKeySQL, downloadAdmissionTombstoneSQL, downloadAdmissionReceiptKeySQL}, "\n") {
		t.Fatal("wrong order", queries)
	}
	if _, err := json.Marshal(key); err == nil || fmt.Sprintf("%v %#v", key, key) != "DownloadAdmissionKeyLock DownloadAdmissionKeyLock" {
		t.Fatal("key capability leaked")
	}
	if d.inserts != 1 || d.commits != 0 || d.rollbacks != 0 || d.begins != 1 {
		t.Fatal("changed caller transaction")
	}
}

// A tiny row transport is deliberately separate from the audit fixture, whose
// rows have a fixed six-column audit projection.
type admissionKeyRows struct {
	width  int
	values []driver.Value
	done   bool
}

func (r *admissionKeyRows) Columns() []string { return make([]string, r.width) }
func (*admissionKeyRows) Close() error        { return nil }
func (r *admissionKeyRows) Next(dest []driver.Value) error {
	if r.done || r.values == nil {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

func TestDownloadAdmissionKeysConflictExpiredAndUnavailable(t *testing.T) {
	for _, name := range []string{"same_hash", "different_hash", "expired_same_hash", "expired_different_hash", "operation_error", "tombstone_error", "receipt_error", "receipt_collision", "bad_operation_id", "bad_operation_hash", "bad_tombstone_hash", "wait_expired", "wait_clock_backwards"} {
		t.Run(name, func(t *testing.T) {
			d, tx, _, f := downloadBindingFixture(t)
			seen := []string{}
			d.extraQuery = func(q string, args []driver.NamedValue) (driver.Rows, error) {
				seen = append(seen, q)
				switch q {
				case downloadAdmissionKeySQL:
					switch name {
					case "same_hash":
						return &admissionKeyRows{width: 2, values: []driver.Value{int64(19), f.Intent.RequestHash}}, nil
					case "different_hash":
						return &admissionKeyRows{width: 2, values: []driver.Value{int64(19), strings.Repeat("f", 64)}}, nil
					case "bad_operation_id":
						return &admissionKeyRows{width: 2, values: []driver.Value{int64(0), f.Intent.RequestHash}}, nil
					case "bad_operation_hash":
						return &admissionKeyRows{width: 2, values: []driver.Value{int64(19), "bad"}}, nil
					case "operation_error":
						return nil, errors.New("PRIVATE operation SQL failure")
					}
					return &admissionKeyRows{width: 2}, nil
				case downloadAdmissionTombstoneSQL:
					switch name {
					case "expired_same_hash":
						return &admissionKeyRows{width: 1, values: []driver.Value{f.Intent.RequestHash}}, nil
					case "expired_different_hash":
						return &admissionKeyRows{width: 1, values: []driver.Value{strings.Repeat("f", 64)}}, nil
					case "bad_tombstone_hash":
						return &admissionKeyRows{width: 1, values: []driver.Value{"bad"}}, nil
					case "tombstone_error":
						return nil, errors.New("PRIVATE marker SQL failure")
					}
					return &admissionKeyRows{width: 1}, nil
				case downloadAdmissionReceiptKeySQL:
					switch name {
					case "receipt_collision":
						return &admissionKeyRows{width: 1, values: []driver.Value{int64(19)}}, nil
					case "receipt_error":
						return nil, errors.New("PRIVATE receipt SQL failure")
					case "wait_expired":
						d.now = d.now.Add(time.Hour)
					case "wait_clock_backwards":
						d.now = d.now.Add(-time.Microsecond)
					}
					return &admissionKeyRows{width: 1}, nil
				}
				t.Fatal("unexpected SQL", q)
				return nil, errors.New("unexpected SQL")
			}
			key, err := LockDownloadAdmissionKey(context.Background(), tx, f.Actor, f.Proof, f.Intent.OperationID)
			want := ErrDownloadAdmissionNotReady
			if name == "same_hash" || name == "different_hash" {
				want = ErrDownloadAdmissionKeyConflict
			}
			if name == "expired_same_hash" || name == "expired_different_hash" {
				want = ErrDownloadAdmissionKeyExpired
			}
			if key != nil || err != want {
				t.Fatal("wrong failure", err, want)
			}
			if (name == "same_hash" || name == "different_hash") && len(seen) != 1 {
				t.Fatal("conflict did not precede nonce/receipt lookups")
			}
			if d.inserts != 1 || d.commits != 0 {
				t.Fatal("key lookup wrote")
			}
		})
	}
}

func TestDownloadAdmissionKeysProofAndActorBeforeLedger(t *testing.T) {
	for _, name := range []string{"zero_proof", "actor_id", "subject", "session", "session_expired", "proof_expired", "operation_id", "canceled", "ended_tx"} {
		t.Run(name, func(t *testing.T) {
			d, tx, _, f := downloadBindingFixture(t)
			ctx := context.Background()
			d.extraQuery = func(string, []driver.NamedValue) (driver.Rows, error) {
				t.Fatal("ledger queried before actor/proof validation")
				return nil, nil
			}
			switch name {
			case "zero_proof":
				f.Proof = systembackupsecurity.SensitiveDownloadProofVerification{}
			case "actor_id":
				f.Actor.UserID++
			case "subject":
				f.Actor.Subject = "user:43"
			case "session":
				f.Actor.Session = strings.Repeat("f", 64)
			case "session_expired":
				f.Actor.SessionExpiresAt = d.now
			case "proof_expired":
				d.now = d.now.Add(61 * time.Second)
			case "operation_id":
				f.Intent.OperationID = "bad"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "ended_tx":
				tx.Rollback()
			}
			if key, err := LockDownloadAdmissionKey(ctx, tx, f.Actor, f.Proof, f.Intent.OperationID); key != nil || err == nil {
				t.Fatal("invalid authority returned key")
			}
		})
	}
}
