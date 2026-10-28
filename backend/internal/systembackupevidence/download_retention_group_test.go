package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

func retentionGroupFixture(t *testing.T, finished bool) (*admissionTxFixture, string) {
	t.Helper()
	f, _, c := committedFixture(t)
	if finished {
		if err := resultFixture(t, f).Finish(context.Background(), c, DownloadResultObservation{Outcome: "interrupted", BytesWritten: 3}); err != nil {
			t.Fatal(err)
		}
	}
	return f, c.operationID
}
func openRetentionGroup(t *testing.T, f *admissionTxFixture, id string) (*DownloadRetentionGroup, *sql.Tx, error) {
	t.Helper()
	tx, _, err := f.service.registry.begin(context.Background())
	if err != nil {
		return nil, nil, err
	}
	t.Cleanup(func() { tx.Rollback() })
	scope, err := sec.LockSensitiveDownloadNonceScope(context.Background(), tx, f.db.identity, f.initial.Manifest.Identity.Installation)
	if err != nil {
		return nil, tx, err
	}
	config, err := scope.LoadConfig(context.Background(), tx)
	if err != nil {
		return nil, tx, err
	}
	g, err := LockDownloadRetentionGroup(context.Background(), tx, f.db.identity, config, id)
	return g, tx, err
}
func verifyRetentionGroup(t *testing.T, f *admissionTxFixture, g *DownloadRetentionGroup, tx *sql.Tx) error {
	t.Helper()
	if err := f.env.LockOwnerReferences(context.Background(), tx); err != nil {
		return err
	}
	if err := g.LockNonce(context.Background(), tx); err != nil {
		return err
	}
	return g.VerifyAudits(context.Background(), tx)
}

func TestDownloadRetentionGroupReconstructsWithoutOriginalCapability(t *testing.T) {
	for _, mode := range []string{"completed", "pending_result", "revoked", "expired_original_authority", "expired_original_retention", "new_current_config"} {
		t.Run(mode, func(t *testing.T) {
			f, id := retentionGroupFixture(t, mode != "pending_result")
			if mode == "revoked" {
				f.db.sessionRevoked = true
				f.db.userActive = false
			}
			if mode == "expired_original_authority" {
				f.db.now = f.db.now.Add(time.Hour)
			}
			if mode == "expired_original_retention" {
				f.db.now = f.db.resultRetention[10].(time.Time).Add(time.Hour)
			}
			if mode == "new_current_config" {
				f.db.activeConfig = 2
			}
			commits, inserts, reserved := f.db.commits, f.db.resultInserts, f.db.reserved
			g, tx, err := openRetentionGroup(t, f, id)
			if err != nil || verifyRetentionGroup(t, f, g, tx) != nil {
				t.Fatal("cold group reconstruction failed", mode, err)
			}
			hash, complete := g.DetailRollingHash()
			if complete != (mode != "pending_result") || complete && !digestPattern.MatchString(hash) {
				t.Fatal("pending result became a complete cleanup hash")
			}
			if err = g.Recheck(context.Background(), tx); err != nil {
				t.Fatal(err)
			}
			again, ok := g.DetailRollingHash()
			if again != hash || ok != complete {
				t.Fatal("stable original group changed hash")
			}
			if f.db.commits != commits || f.db.resultInserts != inserts || f.db.reserved != reserved {
				t.Fatal("fact reader performed a write or commit")
			}
			for _, value := range []any{g, *g} {
				if _, err := json.Marshal(value); err == nil {
					t.Fatal("private group serialized")
				}
				if fmt.Sprintf("%v", value) != "DownloadRetentionGroup" || fmt.Sprintf("%#v", value) != "DownloadRetentionGroup" {
					t.Fatal("private group leaked through formatting")
				}
			}
		})
	}
}

func TestDownloadRetentionGroupL3ProjectionAndCanonicalBindings(t *testing.T) {
	for _, query := range []string{downloadRetentionOperationSQL, downloadRetentionReceiptSQL} {
		width := 11
		if query == downloadRetentionReceiptSQL {
			width = 16
		}
		for index := 0; index < width; index++ {
			t.Run(strconv.Itoa(width)+"_"+strconv.Itoa(index), func(t *testing.T) {
				f, id := retentionGroupFixture(t, true)
				f.db.groupMutate = func(q string, _ int, row []driver.Value) []driver.Value {
					if q != query {
						return row
					}
					switch v := row[index].(type) {
					case int64:
						row[index] = v + 1
					case string:
						row[index] = v + "changed"
					case []byte:
						row[index] = append(append([]byte(nil), v...), byte(' '))
					case time.Time:
						row[index] = v.Add(time.Microsecond)
					}
					return row
				}
				g, tx, err := openRetentionGroup(t, f, id)
				if err == nil {
					err = verifyRetentionGroup(t, f, g, tx)
				}
				if err == nil {
					t.Fatal("changed durable L3 projection accepted", index)
				}
			})
		}
	}
	for _, mode := range []string{"rehashed_claim", "private_oversize", "public_oversize", "sql_error"} {
		t.Run(mode, func(t *testing.T) {
			f, id := retentionGroupFixture(t, true)
			if mode == "sql_error" {
				f.db.groupFault = mode
			}
			f.db.groupMutate = func(q string, _ int, row []driver.Value) []driver.Value {
				if q != downloadRetentionReceiptSQL {
					return row
				}
				switch mode {
				case "rehashed_claim":
					r, err := DecodeCanonicalDownloadAdmissionReceipt(row[6].([]byte))
					if err != nil {
						t.Error(err)
						return nil
					}
					r.ClaimSHA256 = hash([]byte("another original claim"))
					body, err := CanonicalDownloadAdmissionReceipt(r)
					if err != nil {
						t.Error(err)
						return nil
					}
					row[6], row[7], row[8] = body, int64(len(body)), hash(body)
				case "private_oversize":
					row[6] = bytes.Repeat([]byte("x"), 8193)
				case "public_oversize":
					row[9] = bytes.Repeat([]byte("x"), 8193)
				}
				return row
			}
			g, tx, err := openRetentionGroup(t, f, id)
			if err == nil {
				err = verifyRetentionGroup(t, f, g, tx)
			}
			if err == nil {
				t.Fatal("untrusted canonical receipt authorized a group")
			}
		})
	}
}

func TestDownloadRetentionGroupNonceAssociationsAndAmbiguity(t *testing.T) {
	for index := 0; index < 19; index++ {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			f, id := retentionGroupFixture(t, true)
			g, tx, err := openRetentionGroup(t, f, id)
			if err != nil {
				t.Fatal(err)
			}
			bad := []driver.Value{int64(0), "installation_other", "invalid", hash([]byte("other subject")), hash([]byte("other session")), "invalid", "../bad", "otherEndpoint", hash([]byte("other request")), "other_idempotency_key", g.receipt.AdmittedAt.Add(time.Microsecond), g.receipt.AdmittedAt, g.receipt.AdmittedAt.Add(-time.Microsecond), int64(74), hash([]byte("response")), g.receipt.IntentAuditID + 1, g.retain.Add(time.Microsecond), f.db.consumed.Add(time.Microsecond), "system-backup-strong-auth-nonce.v2"}
			f.db.groupMutate = func(q string, _ int, row []driver.Value) []driver.Value {
				if q == downloadRetentionNonceSQL {
					row[index] = bad[index]
				}
				return row
			}
			if verifyRetentionGroup(t, f, g, tx) == nil {
				t.Fatal("foreign/invalid nonce projection accepted", index)
			}
		})
	}
	for _, fault := range []string{"nonce_missing", "nonce_duplicate"} {
		t.Run(fault, func(t *testing.T) {
			f, id := retentionGroupFixture(t, true)
			f.db.groupFault = fault
			g, tx, err := openRetentionGroup(t, f, id)
			if err != nil {
				t.Fatal(err)
			}
			if verifyRetentionGroup(t, f, g, tx) == nil {
				t.Fatal("ambiguous nonce group accepted")
			}
		})
	}
}

func TestDownloadRetentionGroupStrictAuditsAndOriginalResult(t *testing.T) {
	for _, target := range []string{"intent", "result"} {
		for _, fault := range []string{"actor", "action", "resource", "created", "unknown", "duplicate", "nested", "trailing", "null", "oversize", "fractional_integer", "range", "claim", "retain", "outcome"} {
			t.Run(target+"_"+fault, func(t *testing.T) {
				f, id := retentionGroupFixture(t, true)
				g, tx, err := openRetentionGroup(t, f, id)
				if err != nil {
					t.Fatal(err)
				}
				f.db.groupMutate = func(q string, _ int, row []driver.Value) []driver.Value {
					if q != downloadRetentionAuditSQL || (target == "intent") != (row[1] == "system_backup.evidence_download.intent") {
						return row
					}
					raw := append([]byte(nil), row[4].([]byte)...)
					switch fault {
					case "actor":
						row[0] = int64(43)
					case "action":
						row[1] = "another.action"
					case "resource":
						row[3] = int64(61)
					case "created":
						row[5] = row[5].(time.Time).Add(time.Second)
					case "duplicate":
						row[4] = append([]byte(`{"schema_version":"ignored",`), raw[1:]...)
					case "trailing":
						row[4] = append(raw, []byte(" {}")...)
					case "null":
						row[4] = []byte("null")
					case "oversize":
						row[4] = bytes.Repeat([]byte("x"), 8193)
					case "fractional_integer":
						start := strconv.FormatInt(g.receipt.Start, 10)
						row[4] = bytes.Replace(raw, []byte(`"range_start":`+start), []byte(`"range_start":`+start+`.0`), 1)
					default:
						d := json.NewDecoder(bytes.NewReader(raw))
						d.UseNumber()
						m := map[string]any{}
						if err := d.Decode(&m); err != nil {
							t.Error(err)
							return nil
						}
						switch fault {
						case "unknown":
							m["unknown"] = true
						case "nested":
							m["unknown"] = map[string]any{"nested": true}
						case "range":
							m["range_end"] = g.receipt.End + 1
						case "claim":
							m["claim_sha256"] = hash([]byte("other"))
						case "retain":
							m["retain_until"] = "2000-01-01T00:00:00.000000Z"
						case "outcome":
							m["outcome"] = "sent"
						}
						row[4] = canonical(m)
					}
					return row
				}
				if verifyRetentionGroup(t, f, g, tx) == nil {
					t.Fatal("untrusted audit accepted", target, fault)
				}
			})
		}
	}
}

func TestDownloadRetentionGroupFinalMismatchPoisonsValueCopies(t *testing.T) {
	for _, mode := range []string{"receipt", "nonce_id", "nonce_hmac", "nonce_issuer", "nonce_expiry", "intent", "database", "wrong_transaction", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f, id := retentionGroupFixture(t, true)
			g, tx, err := openRetentionGroup(t, f, id)
			if err != nil || verifyRetentionGroup(t, f, g, tx) != nil {
				t.Fatal(err)
			}
			copyGroup := *g
			originalDatabase := f.db.identity
			f.db.groupMutate = func(q string, _ int, row []driver.Value) []driver.Value {
				if mode == "receipt" && q == downloadRetentionReceiptSQL {
					row[15] = row[15].(time.Time).Add(time.Microsecond)
				}
				if q == downloadRetentionNonceSQL {
					switch mode {
					case "nonce_id":
						row[0] = int64(96)
					case "nonce_hmac":
						row[5] = hash([]byte("replaced HMAC"))
					case "nonce_issuer":
						row[2] = hash([]byte("replaced issuer"))
					case "nonce_expiry":
						row[11] = row[11].(time.Time).Add(time.Microsecond)
					}
				}
				if mode == "intent" && q == downloadRetentionAuditSQL {
					row[4] = []byte(`{"changed":true}`)
				}
				return row
			}
			ctx := context.Background()
			use := tx
			if mode == "wrong_transaction" {
				use = nil
			}
			if mode == "database" {
				f.db.identity.Database += "_other"
			}
			if mode == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if g.Recheck(ctx, use) == nil {
				t.Fatal("changed final group accepted")
			}
			f.db.groupMutate = nil
			f.db.identity = originalDatabase
			queries := len(f.db.queries)
			if copyGroup.Recheck(context.Background(), tx) == nil || len(f.db.queries) != queries {
				t.Fatal("restoration revived a failed group copy")
			}
			if _, ok := copyGroup.DetailRollingHash(); ok {
				t.Fatal("failed group returned a cleanup digest")
			}
		})
	}
}

func TestDownloadRetentionGroupIndependentResultFailureRollsBack(t *testing.T) {
	for _, fault := range []string{"operation", "receipt_final", "nonce_final", "intent_final", "result_final"} {
		t.Run(fault, func(t *testing.T) {
			f, _, c := committedFixture(t)
			result := resultFixture(t, f)
			before, reserved := f.db.record, f.db.reserved
			f.db.groupMutate = func(q string, n int, row []driver.Value) []driver.Value {
				if fault == "operation" && q == downloadRetentionOperationSQL {
					row[2] = "installation_other"
				}
				if fault == "receipt_final" && q == downloadRetentionReceiptSQL && n == 2 {
					row[15] = row[15].(time.Time).Add(time.Microsecond)
				}
				if fault == "nonce_final" && q == downloadRetentionNonceSQL && n == 2 {
					row[0] = int64(96)
				}
				if q == downloadRetentionAuditSQL && ((fault == "intent_final" && n == 2) || (fault == "result_final" && row[1] == "system_backup.evidence_download.result")) {
					row[4] = []byte(`{"changed":true}`)
				}
				return row
			}
			if result.Finish(context.Background(), c, DownloadResultObservation{Outcome: "interrupted", BytesWritten: 3}) == nil {
				t.Fatal("invalid persisted group committed result")
			}
			if !reflect.DeepEqual(before, f.db.record) || len(f.db.resultBody) != 0 || len(f.db.resultRetention) != 0 || f.db.reserved != reserved || f.db.commits != 1 {
				t.Fatal("partial result/release/group survived rollback")
			}
			queries := len(f.db.queries)
			if result.Finish(context.Background(), c, DownloadResultObservation{Outcome: "rejected"}) == nil || len(f.db.queries) != queries {
				t.Fatal("failed result retried")
			}
		})
	}
}

func TestDownloadRetentionGroupMissingInputsFailBeforeSQL(t *testing.T) {
	var zero DownloadRetentionGroup
	if zero.LockNonce(context.Background(), nil) == nil || zero.VerifyAudits(context.Background(), nil) == nil || zero.Recheck(context.Background(), nil) == nil {
		t.Fatal("zero group accepted")
	}
	if _, ok := zero.DetailRollingHash(); ok {
		t.Fatal("zero group has complete hash")
	}
	if g, err := LockDownloadRetentionGroup(context.Background(), nil, sec.DatabaseIdentity{}, nil, "invalid"); err == nil || g != nil {
		t.Fatal("unscoped group constructed")
	}
	if strings.Contains(fmt.Sprintf("%#v", zero), "receipt") {
		t.Fatal("zero group exposed its internal layout")
	}
}
