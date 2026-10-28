package systembackupbusinessa

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
)

func fixtureCostGroup(rows int64) costCurrencyAggregate {
	return costCurrencyAggregate{Currency: "USD", Rows: rows, PromptTokens: "0", CompletionTokens: "0", TotalTokens: "0",
		InputUnitPrice: "0.00000000", OutputUnitPrice: "0.00000000", EstimatedCost: "0.00000000", ActualCost: "0.00000000", InternalCost: "0.00000000"}
}

func fixtureCostAggregateHash(t *testing.T, rows int64) string {
	t.Helper()
	var groups []costCurrencyAggregate
	if rows != 0 {
		groups = []costCurrencyAggregate{fixtureCostGroup(rows)}
	}
	hash, err := costAggregateHash(groups, rows)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func tFixtureCount(state *countState) int64 {
	if n, ok := state.counts["cost_records"]; ok {
		return n
	}
	return 2
}

func costSQLValues(g costCurrencyAggregate) []driver.Value {
	return []driver.Value{g.Currency, g.Rows, g.ActualCostCount, g.PromptTokens, g.CompletionTokens, g.TotalTokens,
		g.InputUnitPrice, g.OutputUnitPrice, g.EstimatedCost, g.ActualCost, g.InternalCost, int64(0)}
}

func costSQLRows(groups ...costCurrencyAggregate) *costTestRows {
	r := &costTestRows{}
	for _, g := range groups {
		r.values = append(r.values, costSQLValues(g))
	}
	return r
}

func fixtureCostSQLRows(rows int64) driver.Rows {
	if rows == 0 {
		return costSQLRows()
	}
	return costSQLRows(fixtureCostGroup(rows))
}

type costTestRows struct {
	values                [][]driver.Value
	nextError, closeError error
}

func (r *costTestRows) Columns() []string {
	return []string{"currency", "rows", "actual_count", "prompt", "completion", "total", "input", "output", "estimated", "actual", "internal", "violations"}
}
func (r *costTestRows) Close() error { return r.closeError }
func (r *costTestRows) Next(dest []driver.Value) error {
	if len(r.values) == 0 {
		if r.nextError != nil {
			return r.nextError
		}
		return io.EOF
	}
	copy(dest, r.values[0])
	r.values = r.values[1:]
	return nil
}

// Fixed vectors calculated from the documented v1 JSON bytes, independently
// of the SQL/source aggregation helpers. Currency case and NULL occupancy are
// deliberate parts of that vector; none of these amounts are public evidence.
func costGoldenSources() []CostRecordRestoreSource {
	zero, five := "0", "5"
	return []CostRecordRestoreSource{
		{Currency: "USD", PromptTokens: 10, CompletionTokens: 20, TotalTokens: 30, InputUnitPrice: "0.12345678", OutputUnitPrice: "0.00000001", EstimatedCost: "1.00000001", InternalCost: "0.01"},
		{Currency: "USD", PromptTokens: 1, CompletionTokens: 2, TotalTokens: 3, InputUnitPrice: "9999999999.99999999", OutputUnitPrice: "0", EstimatedCost: "2.12345678", ActualCost: &zero, InternalCost: "0.02"},
		{Currency: "usd", PromptTokens: 7, CompletionTokens: 8, TotalTokens: 15, InputUnitPrice: "2", OutputUnitPrice: "3", EstimatedCost: "4", ActualCost: &five, InternalCost: "6"},
	}
}

func costGoldenGroups() []costCurrencyAggregate {
	return []costCurrencyAggregate{
		{Currency: "USD", Rows: 2, ActualCostCount: 1, PromptTokens: "11", CompletionTokens: "22", TotalTokens: "33", InputUnitPrice: "10000000000.12345677", OutputUnitPrice: "0.00000001", EstimatedCost: "3.12345679", ActualCost: "0.00000000", InternalCost: "0.03000000"},
		{Currency: "usd", Rows: 1, ActualCostCount: 1, PromptTokens: "7", CompletionTokens: "8", TotalTokens: "15", InputUnitPrice: "2.00000000", OutputUnitPrice: "3.00000000", EstimatedCost: "4.00000000", ActualCost: "5.00000000", InternalCost: "6.00000000"},
	}
}

func TestCostAggregateIndependentGoldenVectors(t *testing.T) {
	const golden = "929ad8392fd0bbed5d19c2ed31777205a92e9b876e4dba7b548850afcb30999f"
	const empty = "74dea8c28b27f2c2409e900012cf2564c513b1bb79a03fe552e675e740a5b91f"
	for _, groups := range [][]costCurrencyAggregate{nil, {}} {
		if got, err := costAggregateHash(groups, 0); err != nil || got != empty {
			t.Fatal("empty golden mismatch", got, err)
		}
	}
	sources := costGoldenSources()
	for i := 0; i < len(sources); i++ {
		if got, err := costSourceAggregateHash(sources); err != nil || got != golden {
			t.Fatal("source golden mismatch", got, err)
		}
		sources = append(sources[1:], sources[0])
	}
	if got, err := costAggregateHash(costGoldenGroups(), 3); err != nil || got != golden {
		t.Fatal("SQL vector differs from source", got, err)
	}
	scope, _ := restoreFixture(t)
	state := &countState{counts: map[string]int64{"cost_records": 3}, costRows: func() driver.Rows { return costSQLRows(costGoldenGroups()...) }}
	snapshot, err := (SQLCountCollector{DB: countDB(t, state)}).CollectSnapshot(context.Background(), scope)
	if err != nil || snapshot.CostAggregateSHA256 != golden || state.commits != 1 {
		t.Fatal("collector did not bind SQL golden", err)
	}
	if state.queries[len(state.queries)-1] != costAggregateQuery || !state.begin.ReadOnly {
		t.Fatal("cost query escaped the same read-only transaction")
	}
}

func TestCostAggregateExactLargeTotalsAndBounds(t *testing.T) {
	g := fixtureCostGroup(5_000_000_000)
	g.PromptTokens, g.TotalTokens = "10737418235000000000", "10737418235000000000" // > MaxInt64
	g.EstimatedCost = "49999999999999999950.00000000"                              // exact DECIMAL sum, > MaxInt64 scaled
	if _, err := costAggregateHash([]costCurrencyAggregate{g}, g.Rows); err != nil {
		t.Fatal("valid wide sum rejected", err)
	}
	for name, edit := range map[string]func(*costCurrencyAggregate){
		"token upper bound":   func(g *costCurrencyAggregate) { g.TotalTokens = "10737418235000000001" },
		"decimal upper bound": func(g *costCurrencyAggregate) { g.EstimatedCost = "49999999999999999950.00000001" },
		"less total":          func(g *costCurrencyAggregate) { g.TotalTokens = "1" },
		"actual count":        func(g *costCurrencyAggregate) { g.ActualCostCount = g.Rows + 1 },
		"NULL amount":         func(g *costCurrencyAggregate) { g.ActualCost = "0.00000001" },
		"currency whitespace": func(g *costCurrencyAggregate) { g.Currency = " USD" },
		"currency control":    func(g *costCurrencyAggregate) { g.Currency = "US\x00D" },
		"zero rows":           func(g *costCurrencyAggregate) { g.Rows = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := g
			edit(&bad)
			if _, err := costAggregateHash([]costCurrencyAggregate{bad}, g.Rows); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatal("invalid group accepted", err)
			}
		})
	}
	for _, raw := range []string{"", "-1", "+1", "01", "1e2", "NaN", "1.000000000", "1.0", "1", " 1.00000000", strings.Repeat("9", 49)} {
		t.Run("decimal_"+raw, func(t *testing.T) {
			bad := fixtureCostGroup(1)
			bad.EstimatedCost = raw
			if _, err := costAggregateHash([]costCurrencyAggregate{bad}, 1); err == nil {
				t.Fatal("noncanonical decimal accepted")
			}
		})
	}
	a, b := fixtureCostGroup(math.MaxInt64), fixtureCostGroup(1)
	b.Currency = "usd"
	if _, err := costAggregateHash([]costCurrencyAggregate{a, b}, math.MaxInt64); err == nil {
		t.Fatal("row sum overflow accepted")
	}
	groups := []costCurrencyAggregate{fixtureCostGroup(1), fixtureCostGroup(1)}
	if _, err := costAggregateHash(groups, 2); err == nil {
		t.Fatal("duplicate currency accepted")
	}
	groups[0].Currency = "usd"
	if _, err := costAggregateHash(groups, 2); err == nil {
		t.Fatal("unsorted currencies accepted")
	}
	if _, err := costAggregateHash(nil, 1); err == nil {
		t.Fatal("missing summary rows accepted")
	}
	for _, bad := range []CostRecordRestoreSource{
		{Currency: "USD", PromptTokens: -1}, {Currency: "USD", TotalTokens: math.MaxInt32 + 1},
		{Currency: "USD", PromptTokens: 2, TotalTokens: 1}, {Currency: "USD", InputUnitPrice: "1e3"},
	} {
		if _, err := costSourceAggregateHash([]CostRecordRestoreSource{bad}); err == nil {
			t.Fatal("invalid source accepted")
		}
	}
}

func TestCostAggregateCurrencyBoundRejectsTruncation(t *testing.T) {
	var sources []CostRecordRestoreSource
	for i := 0; i <= maxCostAggregateCurrencies; i++ {
		sources = append(sources, CostRecordRestoreSource{Currency: fmt.Sprintf("C%03d", i), InputUnitPrice: "0", OutputUnitPrice: "0", EstimatedCost: "0", InternalCost: "0"})
	}
	if _, err := costSourceAggregateHash(sources[:256]); err != nil {
		t.Fatal("256 currencies rejected", err)
	}
	if _, err := costSourceAggregateHash(sources); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatal("257 currencies truncated", err)
	}
}

func TestCostAggregateSQLFailuresReturnNoPartialResult(t *testing.T) {
	cases := map[string]func() driver.Rows{
		"scan NULL":        func() driver.Rows { r := costSQLRows(fixtureCostGroup(2)); r.values[0][3] = nil; return r },
		"row violation":    func() driver.Rows { r := costSQLRows(fixtureCostGroup(2)); r.values[0][11] = int64(1); return r },
		"malformed amount": func() driver.Rows { r := costSQLRows(fixtureCostGroup(2)); r.values[0][8] = "1e2"; return r },
		"missing group":    func() driver.Rows { return costSQLRows() },
		"duplicate":        func() driver.Rows { return costSQLRows(fixtureCostGroup(1), fixtureCostGroup(1)) },
		"rows error": func() driver.Rows {
			r := costSQLRows(fixtureCostGroup(2))
			r.nextError = errors.New("injected rows failure")
			return r
		},
		"close error": func() driver.Rows {
			r := costSQLRows(fixtureCostGroup(2))
			r.closeError = errors.New("injected close failure")
			return r
		},
		"257 groups": func() driver.Rows {
			var groups []costCurrencyAggregate
			for i := 0; i < 257; i++ {
				g := fixtureCostGroup(1)
				g.Currency = fmt.Sprintf("C%03d", i)
				groups = append(groups, g)
			}
			return costSQLRows(groups...)
		},
		"query": nil,
	}
	for name, rows := range cases {
		t.Run(name, func(t *testing.T) {
			for _, restore := range []bool{false, true} {
				scope, expected := restoreFixture(t)
				state := &countState{costRows: rows}
				if name == "query" {
					state.failure = "cost-query"
				}
				db := countDB(t, state)
				if restore {
					proof := &restoreProofFixture{}
					checks, err := (SQLRestoreVerifier{DB: db, Proof: proof}).VerifyRestoreTarget(context.Background(), scope, expected, "sev_restored")
					if err == nil || !emptyCategoryChecks(checks) || proof.rechecks != 0 {
						t.Fatal("failed aggregate returned restore checks", err)
					}
				} else {
					snapshot, err := (SQLCountCollector{DB: db}).CollectSnapshot(context.Background(), scope)
					if err == nil || !reflect.DeepEqual(snapshot, SourceSnapshot{}) {
						t.Fatal("failed aggregate returned snapshot", err)
					}
				}
				if state.commits != 0 || state.rollbacks != 1 {
					t.Fatal("aggregate failure did not roll back", state)
				}
			}
		})
	}
}

func TestCostAggregateSameCountTargetDriftAndEmpty(t *testing.T) {
	for name, edit := range map[string]func(*costCurrencyAggregate){
		"input":         func(g *costCurrencyAggregate) { g.InputUnitPrice = "0.00000001" },
		"output":        func(g *costCurrencyAggregate) { g.OutputUnitPrice = "0.00000001" },
		"estimated":     func(g *costCurrencyAggregate) { g.EstimatedCost = "0.00000001" },
		"actual":        func(g *costCurrencyAggregate) { g.ActualCostCount = 1; g.ActualCost = "0.00000001" },
		"internal":      func(g *costCurrencyAggregate) { g.InternalCost = "0.00000001" },
		"prompt":        func(g *costCurrencyAggregate) { g.PromptTokens = "1"; g.TotalTokens = "1" },
		"completion":    func(g *costCurrencyAggregate) { g.CompletionTokens = "1"; g.TotalTokens = "1" },
		"total":         func(g *costCurrencyAggregate) { g.TotalTokens = "1" },
		"currency case": func(g *costCurrencyAggregate) { g.Currency = "usd" },
		"NULL to zero":  func(g *costCurrencyAggregate) { g.ActualCostCount = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			scope, expected := restoreFixture(t)
			g := fixtureCostGroup(2)
			edit(&g)
			state := &countState{costRows: func() driver.Rows { return costSQLRows(g) }}
			proof := &restoreProofFixture{}
			checks, err := (SQLRestoreVerifier{DB: countDB(t, state), Proof: proof}).VerifyRestoreTarget(context.Background(), scope, expected, "sev_restored")
			if !errors.Is(err, ErrRestoreNormalizationMismatch) || len(checks.AIGateway) != 14 || state.commits != 1 || proof.rechecks != 1 {
				t.Fatal("same-count drift accepted or checks lost", err)
			}
			for _, check := range allCategoryChecks(checks) {
				if check.ID == "ai_gateway.restore_cost_aggregates" {
					if check.Status != "failed" || check.FailureCategory != "normalization_failed" || check.CheckClassification == nil || *check.CheckClassification != "integrity" || len(check.Expected) != 1 || len(check.Actual) != 1 {
						t.Fatal("aggregate mismatch not closed", check)
					}
				} else if check.Status != "passed" {
					t.Fatal("same-count drift altered another check", check.ID)
				}
			}
		})
	}
	for _, n := range []int64{0, 3} {
		t.Run(fmt.Sprintf("actual_rows_%d", n), func(t *testing.T) {
			scope, expected := restoreFixture(t)
			state := &countState{counts: map[string]int64{"cost_records": n}}
			checks, err := (SQLRestoreVerifier{DB: countDB(t, state), Proof: &restoreProofFixture{}}).VerifyRestoreTarget(context.Background(), scope, expected, "sev_restored")
			if !errors.Is(err, ErrRestoreNormalizationMismatch) || len(checks.AIGateway) != 14 || state.commits != 1 {
				t.Fatal("row drift became an incomplete query failure", err)
			}
		})
	}
}

func TestCostAggregateBackupBindingAndRedaction(t *testing.T) {
	scope, _ := restoreFixture(t)
	source, dump := captureFixture(t)
	dump.Snapshot.CostAggregateSHA256 = strings.Repeat("f", 64)
	checks, err := VerifyBackupSnapshot(context.Background(), scope, source, dump, &proofFixture{})
	if !errors.Is(err, ErrSnapshotMismatch) || len(checks.AIGateway) != 12 {
		t.Fatal("same-count capture drift accepted", err)
	}
	last := checks.AIGateway[11]
	if last.ID != "ai_gateway.cost_aggregates" || last.Status != "failed" || last.FailureCategory != "validation_failed" {
		t.Fatal("wrong backup aggregate check", last)
	}
	metadata, err := VerifyBusinessMetadata(context.Background(), scope, source, dump, &proofFixture{})
	if err == nil || !reflect.DeepEqual(metadata, VerifiedBusinessMetadata{}) {
		t.Fatal("failed digest emitted metadata")
	}
	for _, bad := range []string{"", strings.Repeat("A", 64), "bad"} {
		s, d := captureFixture(t)
		d.Snapshot.CostAggregateSHA256 = bad
		proof := &proofFixture{}
		checks, err := VerifyBackupSnapshot(context.Background(), scope, s, d, proof)
		if !errors.Is(err, ErrInvalidSnapshot) || !emptyCategoryChecks(checks) || proof.calls != 0 {
			t.Fatal("unbound digest reached proof")
		}
	}
	raw, _ := json.Marshal(checks)
	for _, secret := range []string{"USD", "prompt_tokens", "actual_cost_count", "estimated_cost"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("raw cost aggregate leaked into checks", secret)
		}
	}
}

func TestCostAggregateNormalizedBatchBindsDump(t *testing.T) {
	for _, kind := range []string{"amount", "tokens", "currency", "NULL"} {
		t.Run(kind, func(t *testing.T) {
			scope, binding, input, proof := businessRestoreFixture(t)
			switch kind {
			case "amount":
				input.Gateway.CostSources[0].EstimatedCost = "2.00000001"
			case "tokens":
				input.Gateway.CostSources[0].TotalTokens++
			case "currency":
				input.Gateway.CostSources[0].Currency = "usd"
			case "NULL":
				input.Gateway.CostSources[0].ActualCost = nil
			}
			proof.wantInput = cloneBusinessRestoreInput(input) // independent proof still authenticates this projection
			rows, err := NormalizeBusinessForRestore(context.Background(), scope, binding, input, businessRestoreTestProofs(proof))
			if !errors.Is(err, ErrRestoreNormalizationMismatch) || !reflect.DeepEqual(rows, BusinessRestoreRows{}) {
				t.Fatal("projection disagrees with dump yet returned candidate rows", err)
			}
			for _, call := range proof.calls {
				if call == "final" {
					t.Fatal("cost mismatch reached final authority")
				}
			}
		})
	}
	scope, binding, input, proof := businessRestoreFixture(t)
	proof.onVerify = func(b BusinessRestoreBinding, i BusinessRestoreInput) {
		b.Dump.Snapshot.CostAggregateSHA256 = strings.Repeat("f", 64)
		i.Gateway.CostSources[0].EstimatedCost = "8"
		*i.Gateway.CostSources[0].ActualCost = "9"
		input.Gateway.CostSources[0].Currency = "usd"
	}
	rows, err := NormalizeBusinessForRestore(context.Background(), scope, binding, input, businessRestoreTestProofs(proof))
	if err != nil || len(rows.Gateway.Costs) != 1 {
		t.Fatal("proof mutation changed frozen aggregate", err)
	}
}

type costCaptureProof struct {
	verify func(context.Context, CaptureEvidence, CaptureEvidence) error
}

func (p costCaptureProof) VerifyCapture(ctx context.Context, source, dump CaptureEvidence) error {
	return p.verify(ctx, source, dump)
}

func TestCostAggregateCaptureProofMutationAndCancellation(t *testing.T) {
	scope, _ := restoreFixture(t)
	source, dump := captureFixture(t)
	proof := costCaptureProof{verify: func(_ context.Context, s, d CaptureEvidence) error {
		s.Snapshot.Tables[0].Rows = 999
		d.Snapshot.Tables[0].Rows = 999
		d.Snapshot.CostAggregateSHA256 = strings.Repeat("f", 64)
		dump.Snapshot.Tables[0].Rows = 999 // caller's input, after entry snapshot
		return nil
	}}
	metadata, err := VerifyBusinessMetadata(context.Background(), scope, source, dump, proof)
	if err != nil || metadata.Statistics[1].Rows != 18 || metadata.Checks.AIGateway[11].Status != "passed" {
		t.Fatal("proof/caller mutation changed captured metadata", err)
	}
	for _, reject := range []bool{false, true} {
		s, d := captureFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		sentinel := errors.New("B proof rejected aggregate binding")
		proof := costCaptureProof{verify: func(context.Context, CaptureEvidence, CaptureEvidence) error {
			if reject {
				return sentinel
			}
			cancel()
			return nil
		}}
		checks, err := VerifyBackupSnapshot(ctx, scope, s, d, proof)
		cancel()
		if !emptyCategoryChecks(checks) || err == nil {
			t.Fatal("unproven/canceled capture returned checks")
		}
		if reject && !errors.Is(err, sentinel) {
			t.Fatal("B proof error lost", err)
		}
		if !reject && !errors.Is(err, context.Canceled) {
			t.Fatal("capture proof cancellation lost", err)
		}
	}
}
