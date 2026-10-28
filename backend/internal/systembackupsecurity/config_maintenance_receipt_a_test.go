package systembackupsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// SQL transport only, not proof of InnoDB locks or a runtime maintenance grant.
// All four replacements remain valid UTC microseconds and preserve
// intent <= result <= receipt. An order-only check therefore cannot detect
// replacing the original anchors inside the caller's own transaction.
func maintenanceAAuditTimeChange(s *maintenanceReceiptSQLState, name string) {
	switch name {
	case "intent-earlier":
		s.audits[11][5] = s.base.now.Add(-3 * time.Microsecond)
	case "intent-later":
		s.audits[11][5] = s.base.now.Add(-time.Microsecond)
	case "result-earlier":
		s.audits[12][5] = s.base.now.Add(-2 * time.Microsecond)
	case "result-later":
		s.audits[12][5] = s.base.now
	default:
		panic("unknown audit time attack")
	}
}

func TestConfigMaintenanceAAuditTimesStayBoundAcrossStageAndRecheck(t *testing.T) {
	for _, boundary := range []string{"stage-reload", "final-recheck"} {
		t.Run(boundary, func(t *testing.T) {
			for _, attack := range []string{"intent-earlier", "intent-later", "result-earlier", "result-later"} {
				t.Run(attack, func(t *testing.T) {
					_, tx, s, scope, original := maintenanceReceiptFixture(t)
					if boundary == "stage-reload" {
						s.callback = func(stage string) {
							if stage == "insert" {
								maintenanceAAuditTimeChange(s, attack)
							}
						}
						r, err := maintenanceReceiptStage(t, tx, s, scope, original, true)
						if !errors.Is(err, ErrRegistrationUnavailable) || r.tx != nil || r.raw != nil || r.id != "" {
							t.Fatal("Stage accepted replacement audit times with unchanged IDs, bodies and valid ordering", err)
						}
					} else {
						r, err := maintenanceReceiptStage(t, tx, s, scope, original, true)
						if err != nil {
							t.Fatal(err)
						}
						maintenanceAAuditTimeChange(s, attack)
						if !errors.Is(r.recheck(context.Background(), tx), ErrRegistrationUnavailable) {
							t.Fatal("Recheck accepted replacement audit times with unchanged IDs, bodies and valid ordering")
						}
					}
					if s.inserts != 1 || s.base.writes != 0 || s.base.commits != 0 || s.base.rollbacks != 0 {
						t.Fatal("audit guard changed caller transaction ownership or attempted another write")
					}
				})
			}
		})
	}
}

func TestConfigMaintenanceAAuditFormattingDoesNotReplaceFacts(t *testing.T) {
	_, tx, s, scope, original := maintenanceReceiptFixture(t)
	r, err := maintenanceReceiptStage(t, tx, s, scope, original, false)
	if err != nil {
		t.Fatal(err)
	}
	originalReceipt := r.bytes()
	for _, id := range []int64{11, 12} {
		var compact bytes.Buffer
		if err := json.Compact(&compact, s.audits[id][4].([]byte)); err != nil {
			t.Fatal(err)
		}
		s.audits[id][4] = append([]byte(nil), compact.Bytes()...)
		// Go location identity does not change the UTC SQL instant.
		s.audits[id][5] = s.audits[id][5].(time.Time).In(time.FixedZone("equivalent-utc", 0))
	}
	if err := r.recheck(context.Background(), tx); err != nil {
		t.Fatal("equivalent MySQL JSON formatting or UTC location rejected", err)
	}
	if !bytes.Equal(originalReceipt, r.bytes()) || s.inserts != 1 || s.base.writes != 0 || s.base.commits != 0 || s.base.rollbacks != 0 {
		t.Fatal("semantic audit recheck changed original receipt or caller transaction")
	}
}
