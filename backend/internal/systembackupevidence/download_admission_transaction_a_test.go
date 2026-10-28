package systembackupevidence

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// These A checks exercise the actual D transaction and real JWT/Ed25519 with
// D's scripted SQL transport. They do not establish InnoDB behavior, physical
// capacity, an actual MFA issuance source or production readiness.
func TestAAdmissionFinalCallbackCannotReplaceOriginalRows(t *testing.T) {
	attacks := []struct {
		name string
		edit func(*admissionTxFixture)
	}{
		{"nonce_acceptance", func(f *admissionTxFixture) { f.db.nonce[8] = f.db.now.Add(-time.Microsecond) }},
		{"nonce_consumption_and_creation", func(f *admissionTxFixture) { f.db.consumed = f.db.consumed.Add(time.Microsecond) }},
		{"nonce_subject", func(f *admissionTxFixture) { f.db.nonce[2] = strings.Repeat("f", 64) }},
		{"retained_historical_nonce", func(f *admissionTxFixture) { f.db.preConsumed = "v1" }},
		{"audit_original_time", func(f *admissionTxFixture) { f.db.created = f.db.created.Add(time.Microsecond) }},
		{"audit_original_fields", func(f *admissionTxFixture) {
			f.db.body = bytes.Replace(f.db.body, []byte(hash([]byte(f.db.record.Claim))), []byte(strings.Repeat("f", 64)), 1)
		}},
		{"claim_original_owner", func(f *admissionTxFixture) { f.db.record.Claim = "aev_" + strings.Repeat("f", 32) }},
		{"claim_original_version", func(f *admissionTxFixture) { f.db.record.RowVersion++ }},
		{"evidence_original_locator", func(f *admissionTxFixture) { f.db.record.Ref.RelativeKey += "-replacement" }},
		{"operation_original_key", func(f *admissionTxFixture) { f.db.m.op[5] = "replaced_operation_key_012345" }},
		{"operation_original_time", func(f *admissionTxFixture) { f.db.m.op[13] = f.db.now.Add(time.Microsecond) }},
		{"receipt_original_retention", func(f *admissionTxFixture) { f.db.m.receipt[15] = f.db.m.receipt[15].(time.Time).Add(time.Second) }},
		{"config_active_version", func(f *admissionTxFixture) { f.db.activeConfig++ }},
		{"config_materialized_cells", func(f *admissionTxFixture) { f.db.configCells["control_metadata_retention_seconds"] = "1" }},
	}
	for _, attack := range attacks {
		t.Run(attack.name, func(t *testing.T) {
			f := newAdmissionTxFixture(t)
			hit := false
			f.env.onGuard = func() {
				// The second guard follows capacity's own check. All original
				// SQL effects must already exist, before the independent reloads.
				if f.env.guards != 2 {
					return
				}
				if len(f.db.nonce) != 16 || len(f.db.m.op) != 14 || len(f.db.m.receipt) != 16 || len(f.db.body) == 0 || f.db.reserved == 0 || f.db.record.Claim == "" {
					t.Fatal("attack did not reach the fully staged transaction")
				}
				hit = true
				attack.edit(f)
			}
			out, err := f.service.Admit(f.request)
			if !hit || err == nil || out != nil || f.db.commitAttempts != 0 || f.db.commits != 0 || f.db.rollbacks != 1 || f.env.closes != 1 {
				t.Fatal("last callback substitution did not abort the original transaction", err)
			}
			if !reflect.DeepEqual(f.db.record, f.initial) || len(f.db.nonce) != 0 || len(f.db.m.op) != 0 || len(f.db.m.receipt) != 0 || len(f.db.body) != 0 || f.db.reserved != 0 {
				t.Fatal("a staged claim, nonce, audit, operation, receipt or reservation survived rollback")
			}
		})
	}
}

func TestAAdmissionFinalAuditJSONFormattingIsEquivalent(t *testing.T) {
	f := newAdmissionTxFixture(t)
	hit := false
	f.env.onGuard = func() {
		if f.env.guards == 2 {
			hit = true
			// MySQL may reformat JSON. Whitespace is not a fact replacement;
			// the closed parsed values and original time/ID must remain bound.
			f.db.body = append(append([]byte(" \n"), f.db.body...), '\n')
		}
	}
	out, err := f.service.Admit(f.request)
	if !hit || err != nil || out == nil || f.db.commitAttempts != 1 || f.db.commits != 1 || f.db.rollbacks != 0 {
		t.Fatal("equivalent SQL JSON representation was rejected", err)
	}
}

func TestAAdmissionRejectsTransportBeforeOpeningTransaction(t *testing.T) {
	for _, mode := range []string{"plain_http", "wrong_method", "query", "body", "ambiguous_authorization"} {
		t.Run(mode, func(t *testing.T) {
			f := newAdmissionTxFixture(t)
			switch mode {
			case "plain_http":
				f.request.TLS = nil
			case "wrong_method":
				f.request.Method = "POST"
			case "query":
				f.request.URL.RawQuery = "range=0-1"
			case "body":
				f.request.Body = io.NopCloser(strings.NewReader("ignored body"))
				t.Cleanup(func() { f.request.Body.Close() })
			case "ambiguous_authorization":
				f.request.Header["authorization"] = []string{f.request.Header.Get("Authorization")}
			}
			out, err := f.service.Admit(f.request)
			if out != nil || err == nil || f.db.begins != 0 || f.env.prepares != 0 || f.db.commitAttempts != 0 {
				t.Fatal("invalid transport reached transaction or deployment callbacks")
			}
		})
	}
}

func TestAAdmissionProofAndHistoryFailuresPrecedeKeyOrNonceEffects(t *testing.T) {
	for _, mode := range []string{"missing_proof", "duplicate_proof", "missing_history", "extra_history", "wrong_subject", "wrong_session"} {
		t.Run(mode, func(t *testing.T) {
			f := newAdmissionTxFixture(t)
			switch mode {
			case "missing_proof":
				f.request.Header.Del(sec.StrongAuthProofHeader)
			case "duplicate_proof":
				f.request.Header[strings.ToLower(sec.StrongAuthProofHeader)] = []string{f.request.Header.Get(sec.StrongAuthProofHeader)}
			case "missing_history":
				delete(f.env.cfg.NonceHMACKeys, "v1")
			case "extra_history":
				f.env.cfg.NonceHMACKeys["v3"] = bytes.Repeat([]byte{3}, 32)
			case "wrong_subject":
				f.env.cfg.ExpectedSubject = "user:7"
			case "wrong_session":
				f.env.cfg.ExpectedSession = strings.Repeat("f", 64)
			}
			out, err := f.service.Admit(f.request)
			if out != nil || err == nil || f.db.begins != 1 || f.db.rollbacks != 1 || f.db.commitAttempts != 0 || f.env.closes != 1 {
				t.Fatal("invalid proof/history did not fail in its original transaction")
			}
			for _, stage := range f.db.calls {
				if stage == "L3" || stage == "L4" || stage == "L5" || stage == "L6" || stage == "audit" || stage == "claim" || stage == "nonce" || stage == "commit" {
					t.Fatal("invalid proof/history reached a later admission stage", stage)
				}
			}
			if len(f.db.nonce) != 0 || len(f.db.body) != 0 || f.db.reserved != 0 || !reflect.DeepEqual(f.db.record, f.initial) {
				t.Fatal("invalid proof/history produced transaction effects")
			}
		})
	}
}
