package systembackupevidence

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

func assertAdmissionRolledBack(t *testing.T, f *admissionTxFixture) {
	t.Helper()
	d := f.db
	if !reflect.DeepEqual(d.record, f.initial) || len(d.m.op) != 0 || len(d.m.receipt) != 0 || len(d.nonce) != 0 || len(d.body) != 0 || d.reserved != 0 || d.commitAttempts != 0 || d.rollbacks != 1 {
		t.Fatal("partial admission survived rollback", d.calls, d.commits, d.rollbacks)
	}
}

func TestDownloadAdmissionTransactionCommitsAllOriginalRowsOnce(t *testing.T) {
	f := newAdmissionTxFixture(t)
	out, err := f.service.Admit(f.request)
	if err != nil || out == nil {
		t.Fatal("admit", err, f.db.calls)
	}
	d := f.db
	if d.begins != 1 || d.commits != 1 || d.rollbacks != 0 || d.inserts != 1 || d.reserved != 65536 || len(d.m.op) != 14 || len(d.m.receipt) != 16 || len(d.nonce) != 16 || d.record.RowVersion != f.initial.RowVersion+1 {
		t.Fatal("missing/duplicate transaction effects", d.calls)
	}
	if out.OperationPublicID() != d.m.op[0] || out.record.Claim != d.record.Claim || out.intentAuditID != 1729 || d.nonce[10] != int64(73) || d.nonce[11] != int64(1729) || d.m.receipt[0] != int64(73) {
		t.Fatal("wrong row anchors")
	}
	if _, err = json.Marshal(out); err == nil || fmt.Sprintf("%v %#v", out, out) != "CommittedDownloadAdmission CommittedDownloadAdmission" {
		t.Fatal("committed metadata exposed private facts")
	}
	copied := out.Record()
	copied.Manifest.Chunks[0].CipherHash = strings.Repeat("f", 64)
	if out.Record().Manifest.Chunks[0].CipherHash != f.initial.Manifest.Chunks[0].CipherHash {
		t.Fatal("mutable committed snapshot")
	}
	first := func(stage string) int {
		for i, v := range d.calls {
			if v == stage {
				return i
			}
		}
		return -1
	}
	for _, pair := range [][2]string{{"L0", "L3"}, {"L3", "L4"}, {"L4", "L5"}, {"L5", "L6"}, {"L6", "audit"}, {"audit", "L9"}, {"L9", "claim"}, {"claim", "nonce"}, {"nonce", "commit"}} {
		if first(pair[0]) < 0 || first(pair[0]) >= first(pair[1]) {
			t.Fatal("wrong stage order", pair, d.calls)
		}
	}
	if f.env.guards != 2 || f.env.closes != 1 {
		t.Fatal("missing final authority checks or close")
	}
	if f.db.config.Enabled() {
		t.Fatal("this admission must also work with scheduling disabled")
	}
	if d.nonce[8] != d.proof.ProofAcceptedAt() || !d.nonce[9].(time.Time).Before(d.proof.ProofExpiresAt().Add(time.Microsecond)) {
		t.Fatal("nonce timestamps changed original proof bounds")
	}
	if d.m.receipt[15] != d.nonce[12] || !d.nonce[12].(time.Time).After(d.proof.ProofExpiresAt()) {
		t.Fatal("retention group split")
	}
}

func TestDownloadAdmissionTransactionClaimOwnershipAndVersion(t *testing.T) {
	for _, mode := range []string{"busy", "expired", "bad_old_owner", "unsafe_version"} {
		t.Run(mode, func(t *testing.T) {
			f := newAdmissionTxFixture(t)
			old := f.initial
			switch mode {
			case "busy":
				old.Claim = "aev_" + strings.Repeat("d", 32)
				old.ClaimUntil = f.db.now.Add(time.Minute)
			case "expired":
				old.Claim = "aev_" + strings.Repeat("d", 32)
				old.ClaimUntil = f.db.now.Add(-time.Microsecond)
			case "bad_old_owner":
				old.Claim = "invalid-claim"
				old.ClaimUntil = f.db.now.Add(-time.Microsecond)
			case "unsafe_version":
				old.RowVersion = 9007199254740991
			}
			f.initial, f.db.record, f.env.hint = old, old, old
			out, err := f.service.Admit(f.request)
			if mode == "expired" {
				if err != nil || out == nil || f.db.record.Claim == old.Claim || f.db.record.RowVersion != old.RowVersion+1 {
					t.Fatal("expired claim takeover", err)
				}
				return
			}
			if out != nil || err == nil {
				t.Fatal("invalid claim/version admitted", mode)
			}
			assertAdmissionRolledBack(t, f)
		})
	}
}

func TestDownloadAdmissionTransactionEveryFailureRollsBackWholeGroup(t *testing.T) {
	for _, fault := range []string{"canonical_missing", "materialized_drift", "legacy_installation", "claim_sql", "claim_cas", "nonce_insert", "nonce_zero", "nonce_read",
		"operation_insert", "operation_zero", "operation_id_error", "receipt_insert", "receipt_zero", "operation_read", "receipt_read", "receipt_rehashed", "public_rehashed",
		"prepare_denied", "owner_denied", "capacity_denied", "final_auth_denied", "final_capacity_denied", "late_password_change", "late_session_revoke", "late_role_change", "late_config_change", "late_claim_change", "late_nonce_change", "late_receipt_change", "claim_deadline_not_refreshed", "late_expiry", "late_clock_backwards"} {
		t.Run(fault, func(t *testing.T) {
			f := newAdmissionTxFixture(t)
			switch fault {
			case "operation_insert", "operation_zero", "operation_id_error", "receipt_insert", "receipt_zero", "operation_read", "receipt_read", "receipt_rehashed", "public_rehashed":
				f.db.m.fault = fault
			case "prepare_denied":
				f.env.denyPrepare = true
			case "owner_denied":
				f.env.denyOwner = true
			case "capacity_denied":
				f.env.denyReserve = true
			case "final_auth_denied":
				f.env.denyGuard = true
			case "final_capacity_denied":
				f.env.denyCapacity = true
			case "late_password_change":
				f.env.onGuard = func() { f.db.password = "changed-current-password" }
			case "late_session_revoke":
				f.env.onGuard = func() { f.db.sessionRevoked = true }
			case "late_role_change":
				f.env.onGuard = func() { f.db.role = "user" }
			case "late_config_change":
				f.env.onGuard = func() { f.db.activeConfig = 2 }
			case "late_claim_change":
				f.env.onGuard = func() { f.db.record.Claim = "aev_" + strings.Repeat("f", 32) }
			case "late_nonce_change":
				f.env.onGuard = func() { f.db.nonce[1] = strings.Repeat("f", 64) }
			case "late_receipt_change":
				f.env.onGuard = func() { f.db.m.receipt[8] = strings.Repeat("f", 64) }
			case "claim_deadline_not_refreshed":
				f.env.reservationUntil = f.db.now.Add(90 * time.Second)
				f.env.onOwner = func() { f.db.now = f.db.now.Add(31 * time.Second) }
			case "late_expiry":
				f.env.onGuard = func() { f.db.now = f.db.now.Add(time.Hour) }
			case "late_clock_backwards":
				f.env.onGuard = func() { f.db.now = f.db.now.Add(-time.Microsecond) }
			default:
				f.db.fault = fault
			}
			if out, err := f.service.Admit(f.request); out != nil || err == nil {
				t.Fatal("failed admission returned success", fault)
			}
			switch fault {
			case "canonical_missing", "materialized_drift", "legacy_installation", "claim_sql", "claim_cas", "nonce_insert", "nonce_zero", "nonce_read":
				if !f.db.faultSeen {
					t.Fatal("requested SQL fault was never reached", fault, f.db.calls)
				}
			case "prepare_denied":
				if f.env.prepares < 1 {
					t.Fatal("prepare fault not reached")
				}
			case "owner_denied":
				if f.env.owners < 1 {
					t.Fatal("owner fault not reached")
				}
			case "capacity_denied":
				if f.env.reserves < 1 {
					t.Fatal("capacity fault not reached")
				}
			case "final_capacity_denied":
				if f.env.capacityChecks < 1 {
					t.Fatal("final capacity fault not reached")
				}
			case "claim_deadline_not_refreshed":
				if f.env.reserves < 1 || !f.db.now.After(f.db.saved.record.CreatedAt.Add(time.Hour+30*time.Second)) {
					t.Fatal("claim wait not exercised")
				}
			case "operation_insert", "operation_zero", "operation_id_error":
				if f.db.m.writes < 1 {
					t.Fatal("operation fault not reached")
				}
			case "receipt_insert", "receipt_zero", "operation_read", "receipt_read", "receipt_rehashed", "public_rehashed":
				if f.db.m.writes < 2 {
					t.Fatal("receipt/readback fault not reached")
				}
			default:
				if f.env.guards < 1 {
					t.Fatal("final guard fault not reached", fault, f.db.calls)
				}
			}
			assertAdmissionRolledBack(t, f)
		})
	}
}

func TestDownloadAdmissionTransactionKeyAndNonceReplayOrdering(t *testing.T) {
	f := newAdmissionTxFixture(t)
	if _, err := f.service.Admit(f.request); err != nil {
		t.Fatal(err)
	}
	writes, body, nonce := f.db.m.writes, string(f.db.body), append([]driver.Value(nil), f.db.nonce...)
	if out, err := f.service.Admit(f.request); out != nil || err != ErrDownloadAdmissionKeyConflict {
		t.Fatal("same key reexecuted", err)
	}
	if f.db.m.writes != writes || string(f.db.body) != body || !reflect.DeepEqual(nonce, f.db.nonce) {
		t.Fatal("key conflict changed stored rows")
	}
	f.sign(t, "different_key_0123456789", f.db.now.Add(-time.Minute), f.db.now.Add(time.Minute))
	out, err := f.service.Admit(f.request)
	var ve *sec.VerificationError
	if out != nil || !errors.As(err, &ve) || ve.Code != sec.FailureReplayed {
		t.Fatal("new key consumed the same nonce", err)
	}
	if f.db.m.writes != writes || f.db.commitAttempts != 1 {
		t.Fatal("nonce replay executed work")
	}
	// Missing proof precedes existing key lookup; no old success can bypass MFA.
	f.request.Header.Del(sec.StrongAuthProofHeader)
	out, err = f.service.Admit(f.request)
	if out != nil || !errors.As(err, &ve) || ve.Code != sec.FailureRequired {
		t.Fatal("missing proof became a key/nonce result", err)
	}
}

func TestDownloadAdmissionTransactionUnknownOrLateCommitNeverReturnsCapability(t *testing.T) {
	for _, mode := range []string{"unknown", "late"} {
		t.Run(mode, func(t *testing.T) {
			f := newAdmissionTxFixture(t)
			want := ErrDownloadAdmissionCommitUnknown
			if mode == "unknown" {
				f.db.commitUnknown = true
			} else {
				f.db.commitLate = true
				f.env.reservationUntil = f.db.now.Add(10 * time.Millisecond)
				want = ErrDownloadAdmissionCommittedExpired
			}
			out, err := f.service.Admit(f.request)
			if out != nil || err != want || f.db.commitAttempts != 1 || len(f.db.nonce) != 16 || f.db.record.Claim == "" {
				t.Fatal("uncertain/late commit leaked a capability or auto-retried", err)
			}
			before := f.db.m.writes
			if out, err = f.service.Admit(f.request); out != nil || err != ErrDownloadAdmissionKeyConflict || f.db.m.writes != before || f.db.commitAttempts != 1 {
				t.Fatal("uncertain/late key was replayed", err)
			}
		})
	}
}

func TestDownloadAdmissionTransactionOriginalTransportSnapshotAndFutureAuth(t *testing.T) {
	t.Run("frozen_headers_and_hint", func(t *testing.T) {
		f := newAdmissionTxFixture(t)
		originalKey := f.request.Header.Get("Idempotency-Key")
		f.env.onPrepare = func() {
			f.request.Header.Set("Idempotency-Key", "replacement_key_0123456789")
			f.request.Header.Set(sec.StrongAuthProofHeader, "not-a-proof")
		}
		f.env.hint.Manifest.Chunks = append([]Chunk(nil), f.env.hint.Manifest.Chunks...)
		f.env.onOwner = func() { f.env.hint.Manifest.Chunks[0].CipherHash = strings.Repeat("f", 64) }
		if out, err := f.service.Admit(f.request); out == nil || err != nil || f.db.m.op[5] != originalKey {
			t.Fatal("caller mutation replaced original transport/hint", err)
		}
	})
	t.Run("signed_auth_time_ahead_of_acceptance", func(t *testing.T) {
		f := newAdmissionTxFixture(t)
		skew, err := strconv.ParseInt(f.db.configCells["strong_auth_clock_skew_seconds"].(string), 10, 64)
		if err != nil || skew < 1 {
			t.Fatal("fixture must allow positive skew")
		}
		auth := f.db.now.Add(time.Duration(skew) * time.Second)
		f.sign(t, f.request.Header.Get("Idempotency-Key"), auth, f.db.now.Add(time.Minute))
		if out, err := f.service.Admit(f.request); out == nil || err != nil {
			t.Fatal("valid future signed time rejected", err)
		}
		if !f.db.nonce[8].(time.Time).Equal(f.db.proof.ProofAcceptedAt()) || f.db.nonce[8].(time.Time).Equal(auth) {
			t.Fatal("nonce ledger used signed future auth_time")
		}
	})
}
