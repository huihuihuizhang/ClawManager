package systembackupresources

import (
	"context"
	"errors"
	"sort"
)

// Private composition of the five implemented tables. This is deliberately not
// a nine-table restore candidate: C's four scan tables are neither defaulted nor
// passed through. All target declarations still require B authentication.
type restoreFiveInput struct {
	Audit      restoreAuditInput
	Egress     restoreEgressInput
	Images     restoreImageInput
	Northbound restoreNorthboundInput
	Budget     restoreFieldBudget
}

type restoreFiveCandidate struct {
	Tables                    []restoreFieldTable
	AuditHistory              []restoreAuditHistory
	SourceAuditMaxID          *int64
	SourceNorthboundVersion   *int64
	ObservedNorthboundVersion *int64
}

// One combined input/output budget, and no partial result on any failure. This
// does not allocate target IDs, perform CAS or write SQL. The history stays
// protected with the same evidence boundary as the individual candidates.
func normalizeRestoreFive(ctx context.Context, input restoreFiveInput) (restoreFiveCandidate, error) {
	zero := restoreFiveCandidate{}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if input.Budget.Rows <= 0 || input.Budget.Bytes <= 0 {
		return zero, errors.New("resources five-table budget is required")
	}
	source := []restoreFieldTable{input.Audit.Audit, input.Audit.Northbound, input.Egress.Source, input.Images.Source, input.Northbound.Source}
	if err := validateRestoreFive(ctx, source, input.Budget); err != nil {
		return zero, err
	}
	// A typed source identity must mean the same target across every table.
	// Identical shared declarations are allowed; split/merged mappings are not.
	var union []restoreIDBinding
	seen := make(map[struct {
		kind   restoreIDKind
		source int64
	}]int64)
	for _, bindings := range [][]restoreIDBinding{input.Audit.Bindings, input.Egress.Bindings, input.Northbound.Bindings} {
		if _, err := newRestoreIDMap(bindings); err != nil {
			return zero, err
		}
		for _, binding := range bindings {
			key := struct {
				kind   restoreIDKind
				source int64
			}{binding.Kind, binding.Source}
			if target, exists := seen[key]; exists {
				if target != binding.Target {
					return zero, errors.New("resources five-table mapping differs")
				}
				continue
			}
			seen[key] = binding.Target
			union = append(union, binding)
		}
	}
	if _, err := newRestoreIDMap(union); err != nil {
		return zero, err
	}
	input.Audit.Budget, input.Egress.Budget, input.Images.Budget, input.Northbound.Budget = input.Budget, input.Budget, input.Budget, input.Budget
	audit, err := normalizeRestoreAudit(ctx, input.Audit)
	if err != nil {
		return zero, err
	}
	egress, err := normalizeRestoreEgress(ctx, input.Egress)
	if err != nil {
		return zero, err
	}
	images, err := normalizeRestoreImages(ctx, input.Images)
	if err != nil {
		return zero, err
	}
	northbound, err := normalizeRestoreNorthbound(ctx, input.Northbound)
	if err != nil {
		return zero, err
	}
	tables := []restoreFieldTable{audit.Audit, audit.Northbound, egress, images, northbound.Table}
	if err := validateRestoreFive(ctx, tables, input.Budget); err != nil {
		return zero, err
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Name < tables[j].Name })
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return restoreFiveCandidate{tables, audit.History, audit.SourceAuditMaxID, northbound.SourceVersion, northbound.ObservedTargetVersion}, nil
}

func validateRestoreFive(ctx context.Context, tables []restoreFieldTable, budget restoreFieldBudget) error {
	allowed := map[string]bool{"audit_logs": true, "northbound_settings_audit": true, "egress_private_exceptions": true, "system_image_settings": true, "northbound_admin_settings": true}
	if len(tables) != len(allowed) {
		return errors.New("resources five-table set is incomplete")
	}
	var shape []restoreFieldTable
	for _, table := range tables {
		if !allowed[table.Name] {
			return errors.New("resources five-table set differs")
		}
		delete(allowed, table.Name)
		shape = append(shape, table)
	}
	// Empty entries are shape-checking scaffolding only; they are never emitted
	// or certified as C's expected scan data.
	for name, columns := range restoreFieldColumns() {
		if name == "security_scan_configs" || name == "security_scan_jobs" || name == "security_scan_job_items" || name == "security_scan_reports" {
			shape = append(shape, restoreFieldTable{Name: name, Columns: columns})
		}
	}
	_, err := indexRestoreFields(ctx, shape, budget)
	return err
}
