package systembackupsecurity

import "time"

// DisabledInitializationPlan contains DATA only. It performs no I/O and grants
// no bootstrap, mutation, provider or task authority. The original installer
// must authenticate its genuine source handles and own the entire transaction.
type DisabledInitializationPlan struct {
	Columns                      []string
	Values                       []any
	OperationDeadline, Retention time.Duration
	CapacityBytes                int64
}

func (c BootstrapConfig) DisabledInitializationPlan(g OfflineBootstrapGrant) (DisabledInitializationPlan, error) {
	var zero DisabledInitializationPlan
	validated, err := DecodeBootstrapConfig(c.CanonicalJSON())
	if err != nil || !validBootstrapGrant(g) || validated.SHA256() != g.ConfigSHA256 || validated.SHA256() != c.SHA256() {
		return zero, ErrBootstrapConfig
	}
	columns, values := validated.sqlValuesWithCanonical(g.InstallationID, fieldsVersion(g.UserID), g.ChangeReason)
	return DisabledInitializationPlan{Columns: columns, Values: values,
		OperationDeadline: time.Duration(validated.numbers["operation_deadline_seconds"]) * time.Second,
		Retention:         time.Duration(validated.numbers["control_metadata_retention_seconds"]) * time.Second,
		CapacityBytes:     validated.numbers["control_metadata_capacity_bytes"]}, nil
}
