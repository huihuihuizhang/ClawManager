package systembackupbusinessa

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
)

// Cost summaries are grouped by exact currency bytes, never by the target's
// case-insensitive collation. The bound rejects excess groups, not a truncated
// successful summary. Only the digest is exposed in snapshots/checks.
const maxCostAggregateCurrencies = 256

const costAggregateQuery = `SELECT BINARY currency, COUNT(*), COUNT(actual_cost),
CAST(SUM(prompt_tokens) AS CHAR), CAST(SUM(completion_tokens) AS CHAR), CAST(SUM(total_tokens) AS CHAR),
CAST(SUM(input_unit_price) AS CHAR), CAST(SUM(output_unit_price) AS CHAR), CAST(SUM(estimated_cost) AS CHAR),
CAST(COALESCE(SUM(actual_cost),CAST(0 AS DECIMAL(18,8))) AS CHAR), CAST(SUM(internal_cost) AS CHAR),
SUM(prompt_tokens IS NULL OR prompt_tokens<0 OR prompt_tokens>2147483647 OR completion_tokens IS NULL OR completion_tokens<0 OR completion_tokens>2147483647 OR total_tokens IS NULL OR total_tokens>2147483647 OR total_tokens<prompt_tokens OR total_tokens<completion_tokens OR input_unit_price IS NULL OR input_unit_price<0 OR output_unit_price IS NULL OR output_unit_price<0 OR estimated_cost IS NULL OR estimated_cost<0 OR (actual_cost IS NOT NULL AND actual_cost<0) OR internal_cost IS NULL OR internal_cost<0)
FROM cost_records GROUP BY BINARY currency ORDER BY BINARY currency LIMIT 257`

type costCurrencyAggregate struct {
	Currency         string `json:"currency"`
	Rows             int64  `json:"rows"`
	ActualCostCount  int64  `json:"actual_cost_count"`
	PromptTokens     string `json:"prompt_tokens"`
	CompletionTokens string `json:"completion_tokens"`
	TotalTokens      string `json:"total_tokens"`
	InputUnitPrice   string `json:"input_unit_price"`
	OutputUnitPrice  string `json:"output_unit_price"`
	EstimatedCost    string `json:"estimated_cost"`
	ActualCost       string `json:"actual_cost"`
	InternalCost     string `json:"internal_cost"`
}

func costUnsigned(raw string, scale int) (*big.Int, bool) {
	if len(raw) > 48 {
		return nil, false
	}
	whole, fraction, dot := strings.Cut(raw, ".")
	if whole == "" || len(whole) > 1 && whole[0] == '0' || (scale == 0 && dot) || (scale > 0 && (!dot || len(fraction) != scale)) {
		return nil, false
	}
	for _, part := range []string{whole, fraction} {
		for _, r := range part {
			if r < '0' || r > '9' {
				return nil, false
			}
		}
	}
	n, ok := new(big.Int).SetString(whole+fraction, 10)
	return n, ok
}

func costFixed(n *big.Int) string {
	s := n.String()
	if len(s) <= 8 {
		s = strings.Repeat("0", 9-len(s)) + s
	}
	return s[:len(s)-8] + "." + s[len(s)-8:]
}

func costAggregateHash(groups []costCurrencyAggregate, expectedRows int64) (string, error) {
	if expectedRows < 0 || len(groups) > maxCostAggregateCurrencies {
		return "", ErrInvalidSnapshot
	}
	if groups == nil {
		groups = []costCurrencyAggregate{}
	}
	var rows int64
	previous := ""
	maxPrice, _ := new(big.Int).SetString("999999999999999999", 10)
	for i, g := range groups {
		if !validUserRestoreText(g.Currency, 16) || i > 0 && g.Currency <= previous || g.Rows <= 0 || g.Rows > math.MaxInt64-rows || g.ActualCostCount < 0 || g.ActualCostCount > g.Rows {
			return "", ErrInvalidSnapshot
		}
		previous = g.Currency
		rows += g.Rows
		var tokens [3]*big.Int
		for j, s := range []string{g.PromptTokens, g.CompletionTokens, g.TotalTokens} {
			n, ok := costUnsigned(s, 0)
			limit := new(big.Int).Mul(big.NewInt(g.Rows), big.NewInt(math.MaxInt32))
			if !ok || n.Cmp(limit) > 0 {
				return "", ErrInvalidSnapshot
			}
			tokens[j] = n
		}
		if tokens[2].Cmp(tokens[0]) < 0 || tokens[2].Cmp(tokens[1]) < 0 {
			return "", ErrInvalidSnapshot
		}
		for j, s := range []string{g.InputUnitPrice, g.OutputUnitPrice, g.EstimatedCost, g.ActualCost, g.InternalCost} {
			n, ok := costUnsigned(s, 8)
			count := g.Rows
			if j == 3 {
				count = g.ActualCostCount
			}
			limit := new(big.Int).Mul(big.NewInt(count), maxPrice)
			if !ok || n.Cmp(limit) > 0 {
				return "", ErrInvalidSnapshot
			}
		}
	}
	if rows != expectedRows {
		return "", ErrInvalidSnapshot
	}
	b, err := json.Marshal(groups)
	if err != nil {
		return "", ErrInvalidSnapshot
	}
	h := sha256.Sum256(append([]byte("cost-record-aggregate-v1\n"), b...))
	return hex.EncodeToString(h[:]), nil
}

func readCostAggregateHash(ctx context.Context, tx *sql.Tx, expectedRows int64) (string, error) {
	rows, err := tx.QueryContext(ctx, costAggregateQuery)
	if err != nil {
		return "", fmt.Errorf("query A cost aggregates: %w", err)
	}
	defer rows.Close()
	groups := make([]costCurrencyAggregate, 0)
	for rows.Next() {
		if len(groups) == maxCostAggregateCurrencies {
			return "", ErrInvalidSnapshot
		}
		var g costCurrencyAggregate
		var violations int64
		if err := rows.Scan(&g.Currency, &g.Rows, &g.ActualCostCount, &g.PromptTokens, &g.CompletionTokens, &g.TotalTokens, &g.InputUnitPrice, &g.OutputUnitPrice, &g.EstimatedCost, &g.ActualCost, &g.InternalCost, &violations); err != nil {
			return "", fmt.Errorf("scan A cost aggregates: %w", err)
		}
		if violations != 0 {
			return "", ErrInvalidSnapshot
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("read A cost aggregates: %w", err)
	}
	if err := rows.Close(); err != nil {
		return "", fmt.Errorf("close A cost aggregates: %w", err)
	}
	return costAggregateHash(groups, expectedRows)
}

// This projection contains no identity or mutable pointer shared with proofs.
// Source values and normalized rows must independently produce the same digest
// as the authenticated SQL snapshot. It does not authorize target writes.
func costSourceAggregateHash(sources []CostRecordRestoreSource) (string, error) {
	byCurrency := make(map[string]*costCurrencyAggregate)
	for _, s := range sources {
		if !validUserRestoreText(s.Currency, 16) || s.PromptTokens < 0 || s.CompletionTokens < 0 || s.TotalTokens < s.PromptTokens || s.TotalTokens < s.CompletionTokens || s.PromptTokens > math.MaxInt32 || s.CompletionTokens > math.MaxInt32 || s.TotalTokens > math.MaxInt32 {
			return "", ErrInvalidSnapshot
		}
		g := byCurrency[s.Currency]
		if g == nil {
			if len(byCurrency) == maxCostAggregateCurrencies {
				return "", ErrInvalidSnapshot
			}
			g = &costCurrencyAggregate{Currency: s.Currency, PromptTokens: "0", CompletionTokens: "0", TotalTokens: "0", InputUnitPrice: "0.00000000", OutputUnitPrice: "0.00000000", EstimatedCost: "0.00000000", ActualCost: "0.00000000", InternalCost: "0.00000000"}
			byCurrency[s.Currency] = g
		}
		g.Rows++
		for i, dst := range []*string{&g.PromptTokens, &g.CompletionTokens, &g.TotalTokens} {
			n, _ := costUnsigned(*dst, 0)
			n.Add(n, big.NewInt(int64([]int{s.PromptTokens, s.CompletionTokens, s.TotalTokens}[i])))
			*dst = n.String()
		}
		actual := "0"
		if s.ActualCost != nil {
			actual = *s.ActualCost
			g.ActualCostCount++
		}
		for i, dst := range []*string{&g.InputUnitPrice, &g.OutputUnitPrice, &g.EstimatedCost, &g.ActualCost, &g.InternalCost} {
			canonical, ok := canonicalLLMPrice([]string{s.InputUnitPrice, s.OutputUnitPrice, s.EstimatedCost, actual, s.InternalCost}[i])
			if !ok {
				return "", ErrInvalidSnapshot
			}
			n, _ := costUnsigned(*dst, 8)
			value, _ := costUnsigned(canonical, 8)
			n.Add(n, value)
			*dst = costFixed(n)
		}
	}
	groups := make([]costCurrencyAggregate, 0, len(byCurrency))
	for _, g := range byCurrency {
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Currency < groups[j].Currency })
	return costAggregateHash(groups, int64(len(sources)))
}

func normalizedCostAggregateHash(rows []NormalizedCostRecord) (string, error) {
	sources := make([]CostRecordRestoreSource, len(rows))
	for i, r := range rows {
		sources[i] = CostRecordRestoreSource{Currency: r.Currency, PromptTokens: r.PromptTokens, CompletionTokens: r.CompletionTokens, TotalTokens: r.TotalTokens, InputUnitPrice: r.InputUnitPrice, OutputUnitPrice: r.OutputUnitPrice, EstimatedCost: r.EstimatedCost, ActualCost: r.ActualCost, InternalCost: r.InternalCost}
	}
	return costSourceAggregateHash(sources)
}

func snapshotCostRows(snapshot SourceSnapshot) int64 {
	for _, t := range snapshot.Tables {
		if t.Table == "cost_records" {
			return t.Rows
		}
	}
	return -1
}

func cloneSourceSnapshot(snapshot SourceSnapshot) SourceSnapshot {
	snapshot.Tables = append([]TableCount(nil), snapshot.Tables...)
	return snapshot
}
