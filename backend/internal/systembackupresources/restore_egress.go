package systembackupresources

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
)

// An offline input declaration, never a policy completeness/identity proof.
// B must authenticate the complete installation-specific control, metadata and
// provider exclusions, exact allowances, target references and startup gate.
type restoreEgressPolicy struct {
	Allowed []restoreNetworkAllowance
	Denied  []netip.Prefix
}
type restoreEgressInput struct {
	Source      restoreFieldTable
	Bindings    []restoreIDBinding
	OccupiedIDs []int64
	Policy      *restoreEgressPolicy
	Budget      restoreFieldBudget
}

// normalizeRestoreEgress returns a private disabled candidate, not an active
// exception or write authorization. Row IDs are preserved only if the supplied
// target occupancy permits them; B must repeat allocation checks under locks.
// This does not authenticate empty occupancy, empty tables or a supplied policy.
func normalizeRestoreEgress(ctx context.Context, input restoreEgressInput) (restoreFieldTable, error) {
	if err := ctx.Err(); err != nil {
		return restoreFieldTable{}, err
	}
	if input.Source.Name != "egress_private_exceptions" || input.Policy == nil || input.Budget.Rows <= 0 || input.Budget.Bytes <= 0 {
		return restoreFieldTable{}, errors.New("resources egress input and target policy are required")
	}
	var shape []restoreFieldTable
	for name, columns := range restoreFieldColumns() {
		entry := restoreFieldTable{Name: name, Columns: columns}
		if name == input.Source.Name {
			entry = input.Source
		}
		shape = append(shape, entry)
	}
	if _, err := indexRestoreFields(ctx, shape, input.Budget); err != nil {
		return restoreFieldTable{}, err
	}
	for _, rule := range input.Policy.Allowed {
		if !privateRestorePrefix(rule.Prefix) || rule.Port < 1 || rule.Port > 65535 {
			return restoreFieldTable{}, errors.New("resources egress target allowance is invalid")
		}
	}
	for _, block := range input.Policy.Denied {
		if !block.IsValid() || block != block.Masked() || block.Addr().Is4In6() || block.Addr().Zone() != "" {
			return restoreFieldTable{}, errors.New("resources egress target exclusion is invalid")
		}
	}
	occupied := make(map[int64]bool, len(input.OccupiedIDs))
	for _, id := range input.OccupiedIDs {
		if !validRestoreID(restoreInstanceID, id) || occupied[id] {
			return restoreFieldTable{}, errors.New("resources egress occupancy is invalid")
		}
		occupied[id] = true
	}
	mapping, err := newRestoreIDMap(input.Bindings)
	if err != nil {
		return restoreFieldTable{}, err
	}
	result := restoreFieldTable{Name: input.Source.Name, Columns: append([]string(nil), input.Source.Columns...)}
	for _, source := range input.Source.Rows {
		if err := ctx.Err(); err != nil {
			return restoreFieldTable{}, err
		}
		id, _ := strconv.ParseInt(*source["id"], 10, 64)
		if occupied[id] {
			return restoreFieldTable{}, errors.New("resources egress target ID is occupied")
		}
		kind, scope := source["scope_type"], source["scope_id"]
		if kind == nil || scope == nil {
			return restoreFieldTable{}, errors.New("resources egress scope is required")
		}
		var namespace restoreIDKind
		switch *kind {
		case "user":
			namespace = restoreUserID
		case "instance":
			namespace = restoreInstanceID
		default:
			return restoreFieldTable{}, errors.New("resources egress scope is unsupported")
		}
		sourceScope, err := parseRestoreAuditReference(scope, namespace)
		if err != nil {
			return restoreFieldTable{}, err
		}
		targetScope, err := mapping.nullable(namespace, sourceScope)
		if err != nil {
			return restoreFieldTable{}, err
		}
		creator, err := parseRestoreAuditReference(source["created_by"], restoreUserID)
		if err != nil {
			return restoreFieldTable{}, err
		}
		targetCreator, err := mapping.nullable(restoreUserID, creator)
		if err != nil {
			return restoreFieldTable{}, err
		}
		cidr, port, enabled := source["cidr"], source["port"], source["enabled"]
		if cidr == nil || len(*cidr) > 64 || port == nil || enabled == nil || (*enabled != "0" && *enabled != "1") {
			return restoreFieldTable{}, errors.New("resources egress row is invalid")
		}
		portValue, err := strconv.ParseInt(*port, 10, 32)
		if err != nil || strconv.FormatInt(portValue, 10) != *port {
			return restoreFieldTable{}, errors.New("resources egress port is invalid")
		}
		if err = validateRestoreNetwork(*cidr, int(portValue), input.Policy.Allowed, input.Policy.Denied); err != nil {
			return restoreFieldTable{}, err
		}
		for _, column := range []string{"created_at", "updated_at"} {
			if !validRestoreAuditTime(source[column], false) {
				return restoreFieldTable{}, errors.New("resources egress time is invalid")
			}
		}
		row := cloneRestoreAuditRow(source)
		row["scope_id"] = restoreAuditIDText(targetScope)
		row["created_by"] = restoreAuditIDText(targetCreator)
		prefix, _ := netip.ParsePrefix(*cidr)
		canonical := prefix.String()
		row["cidr"] = &canonical
		disabled := "0"
		row["enabled"] = &disabled
		row["description"] = redactRestoreText(source["description"])
		result.Rows = append(result.Rows, row)
	}
	for i := range shape {
		if shape[i].Name == result.Name {
			shape[i] = result
		}
	}
	if _, err := indexRestoreFields(ctx, shape, input.Budget); err != nil {
		return restoreFieldTable{}, err
	}
	if err := ctx.Err(); err != nil {
		return restoreFieldTable{}, err
	}
	return result, nil
}
