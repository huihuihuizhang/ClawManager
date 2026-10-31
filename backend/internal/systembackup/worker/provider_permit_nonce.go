package worker

// PermitNonce comes only from the persisted original key-reserve response.
// It is independent of frozen materials and is never selected by a permit DTO.
func (a *OriginalKeyAuthority) PermitNonce() string {
	if a == nil {
		return ""
	}
	return a.lease.Nonce
}
