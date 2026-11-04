package main

import (
	"context"
	"errors"

	"clawreef/internal/db"

	"github.com/go-sql-driver/mysql"
)

// Stable coordinates only. SQL messages, row values and connection inputs
// must never be serialized, even for an unexpected driver/provider failure.
type failureDiagnostic struct {
	State     string                           `json:"state"`
	Phase     string                           `json:"phase"`
	Reason    string                           `json:"reason"`
	MySQLCode uint16                           `json:"mysql_code,omitempty"`
	RowBudget *db.Legacy177RowProofBudgetError `json:"row_budget,omitempty"`
}

func safeFailure(phase string, err error) failureDiagnostic {
	d := failureDiagnostic{State: "copy_proof_rejected", Phase: phase, Reason: "read_or_proof_rejected"}
	known := map[string]string{
		"legacy177 exact embedded catalog mismatch":                                           "embedded_catalog_mismatch",
		"legacy177 reviewed ledger union changed":                                             "expected_198_union_mismatch",
		"legacy source inventory identity mismatch":                                           "original_inventory_pin_mismatch",
		"legacy copy ledger differs from site source":                                         "copy_97_ledger_mismatch",
		"legacy copy schema differs from reviewed source/copy variants":                       "copy_schema_variant_unreviewed",
		"legacy preflight requires an isolated cm_import_<32hex> database":                    "isolated_copy_identity_rejected",
		"legacy row proof requires the observed server and an isolated copy":                  "rowproof_copy_identity_rejected",
		"legacy copy contains control history; reviewed empty-table conversion unavailable":   "legacy_control_history_not_empty",
		"backup source has unresolved work; preserve it and finish recovery before importing": "source_work_unresolved",
		"legacy row proof source schema or ledger changed":                                    "rowproof_schema_or_ledger_changed",
		"legacy row proof upgraded ledger incomplete":                                         "upgraded_198_ledger_incomplete",
		"legacy row proof original migration removed":                                         "original_ledger_record_missing",
		"legacy model existing protocol set changed":                                          "original_model_protocol_invalid",
		"legacy model full row proof unavailable":                                             "model_full_rowproof_unavailable",
		"legacy model group backfill differs from reviewed transformation":                    "model_group_backfill_mismatch",
		"backup import preservation budget exceeded":                                          "rowproof_budget_exceeded",
		"invalid import identifier":                                                           "source_identifier_invalid",
		"legacy preflight database configuration invalid":                                     "private_dsn_configuration_invalid",
		"legacy copy already has an import journal":                                           "copy_import_journal_present",
	}
	for current := err; current != nil; current = errors.Unwrap(current) {
		if reason, ok := known[current.Error()]; ok {
			d.Reason = reason
			break
		}
	}
	var sqlError *mysql.MySQLError
	var rowBudget *db.Legacy177RowProofBudgetError
	if errors.As(err, &rowBudget) {
		d.Reason = "rowproof_resource_budget_exceeded"
		d.RowBudget = rowBudget
	}
	if errors.As(err, &sqlError) {
		d.Reason = "mysql_read_rejected"
		d.MySQLCode = sqlError.Number
	}
	if errors.Is(err, context.DeadlineExceeded) {
		d.Reason = "proof_deadline_exceeded"
	}
	return d
}
