package systembackupsecurity

import "errors"

var ErrConfigMutation = errors.New("config_mutation_invalid")

// ConfigValues is an immutable, complete effective configuration. Decoding
// establishes structure and canonical identity, not authority or ref readiness.
// It cannot be passed as a disabled BootstrapConfig to BootstrapAdmission.
type ConfigValues struct{ snapshot BootstrapConfig }

func DecodeConfigValues(raw []byte) (ConfigValues, error) {
	c, err := decodeConfigValues(raw, true)
	if err != nil {
		return ConfigValues{}, ErrConfigMutation
	}
	return ConfigValues{snapshot: c}, nil
}

func (c ConfigValues) SHA256() string                     { return c.snapshot.SHA256() }
func (c ConfigValues) CanonicalJSON() []byte              { return c.snapshot.CanonicalJSON() }
func (c ConfigValues) Enabled() bool                      { return c.snapshot.values.Enabled }
func (c ConfigValues) Registries() []BootstrapRegistryRef { return c.snapshot.Registries() }
func (c ConfigValues) References() []BootstrapSecretRef   { return c.snapshot.References() }

// sqlValues prepares a NEW version only. Rollback writers must use the same
// validated object after current ref resolution and record copied_from_version.
// This helper does not execute SQL or authorize an update/backfill.
func (c ConfigValues) sqlValues(installation, actor, reason string, version int64) ([]string, []any, error) {
	if version < 1 || version > 9007199254740991 || len(c.snapshot.canonical) < 2 {
		return nil, nil, ErrConfigMutation
	}
	columns, args := c.snapshot.sqlValues(installation, actor, reason)
	args[1] = version
	args[4] = c.Enabled()
	columns = append(columns, "canonical_config_json")
	args = append(args, c.CanonicalJSON())
	return columns, args, nil
}
