package systembackupevidence

import "context"

// TransitKeyring is an immutable routing snapshot for one installation. Readers
// use the full KeyRef recorded in the envelope; writers use only writeKey.
// No default/latest key, provider fallback or automatic key removal is allowed.
// A new snapshot does not revoke old snapshots: authoritative admission and
// provider grants must reject new writes through a superseded configuration.
type TransitKeyring struct {
	keys     map[KeyRef]*TransitKeys
	writeKey KeyRef
	writable bool
}

var _ Keys = (*TransitKeyring)(nil)

// NewTransitKeyring consumes admission-validated, historical registry mappings.
// All mappings must belong to installation, including inactive refs still needed
// for retained evidence. A nil writeKey creates a read-only snapshot. Credentials
// are resolved live on every call; neither credentials nor DEKs are cached here.
// The owner must close a replaced snapshot after its in-flight users finish.
func NewTransitKeyring(installation string, configs []TransitConfig, writeKey *KeyRef, credentials TransitCredentials) (*TransitKeyring, error) {
	if !installationPattern.MatchString(installation) || len(configs) == 0 || credentials == nil || writeKey != nil && !writeKey.valid() {
		return nil, ErrKey
	}
	r := &TransitKeyring{keys: make(map[KeyRef]*TransitKeys, len(configs))}
	if writeKey != nil {
		r.writeKey, r.writable = *writeKey, true
	}
	fail := func() (*TransitKeyring, error) { r.Close(); return nil, ErrKey }
	for _, c := range configs {
		if c.Installation != installation || r.keys[c.Key] != nil {
			return fail()
		}
		k, err := NewTransitKeys(c, credentials)
		if err != nil {
			return fail()
		}
		r.keys[c.Key] = k
	}
	if r.writable && r.keys[r.writeKey] == nil {
		return fail()
	}
	return r, nil
}

func (r *TransitKeyring) Wrap(ctx context.Context, ref KeyRef, dek []byte) ([]byte, error) {
	if r == nil || ctx.Err() != nil || !r.writable || ref != r.writeKey || r.keys[ref] == nil {
		return nil, ErrKey
	}
	return r.keys[ref].Wrap(ctx, ref, dek)
}

func (r *TransitKeyring) Unwrap(ctx context.Context, ref KeyRef, wrapped []byte) ([]byte, error) {
	if r == nil || ctx.Err() != nil || r.keys[ref] == nil {
		return nil, ErrKey
	}
	return r.keys[ref].Unwrap(ctx, ref, wrapped)
}

// Close releases idle HTTP connections. It does not revoke grants or delete
// historical keys. Key retirement remains a separate, reference-aware action.
func (r *TransitKeyring) Close() {
	if r != nil {
		for _, k := range r.keys {
			k.Close()
		}
	}
}
