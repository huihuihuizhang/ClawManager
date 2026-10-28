package systembackupevidence

// ValidateTransitKeyRetention compares admitted snapshots against a complete,
// authenticated scan of retained evidence. A nil scan is unavailable, whereas
// an empty non-nil scan is complete. A nil previous or next snapshot is also
// unavailable; a known empty snapshot must be supplied as a non-nil slice.
// This local check does not authenticate the
// scan, provider permissions, key material, or authorize a configuration change;
// the owner must bind those facts and recheck them in its transaction.
func ValidateTransitKeyRetention(installation string, previous, next []TransitConfig, references []KeyRef) error {
	if !installationPattern.MatchString(installation) || previous == nil || next == nil || references == nil {
		return ErrKey
	}
	index := func(configs []TransitConfig) (map[KeyRef]TransitConfig, error) {
		m := make(map[KeyRef]TransitConfig, len(configs))
		for _, c := range configs {
			if c.Installation != installation || !c.Key.valid() || c.KeyVersion == 0 || c.Endpoint == "" || c.KeyName == "" {
				return nil, ErrKey
			}
			if _, exists := m[c.Key]; exists {
				return nil, ErrKey
			}
			m[c.Key] = c
		}
		return m, nil
	}
	old, err := index(previous)
	if err != nil {
		return err
	}
	current, err := index(next)
	if err != nil {
		return err
	}
	// Never silently rebind an existing reference, even when the scan is empty.
	for ref, before := range old {
		if after, ok := current[ref]; ok && (before.Endpoint != after.Endpoint || before.KeyName != after.KeyName || before.KeyVersion != after.KeyVersion) {
			return ErrKey
		}
	}
	for _, ref := range references {
		if !ref.valid() {
			return ErrKey
		}
		before, ok := old[ref]
		if !ok {
			return ErrKey
		}
		after, ok := current[ref]
		if !ok || before.Endpoint != after.Endpoint || before.KeyName != after.KeyName || before.KeyVersion != after.KeyVersion {
			return ErrKey
		}
	}
	return nil
}
