package systembackupsecurity

import (
	"bytes"
	"encoding/json"
)

// ValidateEnableOnlyConfigMutation is a DATA constraint for native resource
// owners. It does not authorize a write, reconstruct a BootstrapConfig, mint an
// OfflineBootstrapGrant or convert a bootstrap check into mutation authority.
// JWT/session, strong auth, RBAC, nonce, capacity, complete native resources,
// independent deployment, KEK evidence/fence and SQL revocation stay mandatory.
func ValidateEnableOnlyConfigMutation(in ConfigMutationResourceInput) error {
	current, proposed := in.Configs()
	if current.Enabled() || !proposed.Enabled() || len(current.CanonicalJSON()) < 2 || len(proposed.CanonicalJSON()) < 2 {
		return ErrConfigMutation
	}
	// Compare complete typed snapshots after clearing only the proposed flag;
	// no registry/ref, retained reference, number or future field is waived.
	values := proposed.snapshot.values
	values.Enabled = false
	raw, e := json.Marshal(values)
	if e != nil {
		return ErrConfigMutation
	}
	normalized, e := DecodeConfigValues(raw)
	if e != nil || !bytes.Equal(normalized.CanonicalJSON(), current.CanonicalJSON()) {
		return ErrConfigMutation
	}
	return nil
}
