package systembackupsecurity

// sqlValuesWithCanonical prepares the candidate post-migration insert shape.
// Bootstrap uses this shape only when CanonicalSnapshot is explicitly enabled
// for the isolated candidate. The default still uses sqlValues until the
// canonical_config_json column and its migration/inventory are reviewed.
// Hash, size, flattened columns and source bytes all come from one validated
// BootstrapConfig; the returned byte slice does not alias its internal copy.
func (c BootstrapConfig) sqlValuesWithCanonical(installation, actor, reason string) ([]string, []any) {
	columns, args := c.sqlValues(installation, actor, reason)
	columns = append(columns, "canonical_config_json")
	args = append(args, c.CanonicalJSON())
	return columns, args
}
