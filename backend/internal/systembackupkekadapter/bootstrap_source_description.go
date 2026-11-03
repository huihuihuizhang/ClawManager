package systembackupkekadapter

import (
	"encoding/json"

	sec "clawreef/internal/systembackupsecurity"
)

// OriginalConfiguration returns detached PUBLIC deployment pins only. It does
// not prepare admission, read SQL, contact a provider or confer any permission.
// The original concrete preparation remains the only source of its admission.
func (p *SQLBootstrapKEKPreparation) OriginalConfiguration() (SQLBootstrapKEKConfig, error) {
	var out SQLBootstrapKEKConfig
	if p == nil {
		return out, sec.ErrRegistrationUnavailable
	}
	raw, err := json.Marshal(p.cfg)
	if err != nil || json.Unmarshal(raw, &out) != nil {
		return SQLBootstrapKEKConfig{}, sec.ErrRegistrationUnavailable
	}
	if _, err := NewSQLBootstrapKEKPreparation(out); err != nil {
		return SQLBootstrapKEKConfig{}, sec.ErrRegistrationUnavailable
	}
	return out, nil
}
