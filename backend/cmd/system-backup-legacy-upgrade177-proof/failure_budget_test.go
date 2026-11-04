package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"clawreef/internal/db"
)

func TestSafeFailureLegacy177TableBudgetCoordinates(t *testing.T) {
	err := &db.Legacy177RowProofBudgetError{Table: "audit_logs", Limit: "rows", Rows: 32000001, Bytes: 123, ExpectedRows: 32000001, MaxRows: 32000000, MaxBytes: 64 << 30, MaxRowBytes: 64 << 20, MaxScratch: 3 << 30}
	d := safeFailure("before", fmt.Errorf("SECRET PRIVATE ROW: %w", err))
	raw, e := json.Marshal(d)
	if e != nil || d.Reason != "rowproof_resource_budget_exceeded" || d.RowBudget == nil || d.RowBudget.Table != "audit_logs" || strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "PRIVATE") {
		t.Fatal("safe budget metadata lost or secret exposed")
	}
}
