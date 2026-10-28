package systembackupevidence

import (
	"context"
	"io"
	"reflect"
	"time"
)

// PrepareSystemCapability prepares external capability evidence, including
// bodies below the inline threshold, without padding or changing their bytes.
// Authority and keys must be supplied by trusted, authenticated producer
// adapters. This function neither implements those adapters nor grants SQL,
// Wrap, STS or publication authority. No runtime currently wires this entry.
// The producer binding hash must include all C1 fixed snapshot versions. A
// renewal/replacement invalidates this call, even if the new lease is longer.
func PrepareSystemCapability(ctx context.Context, i Identity, key KeyRef, source Source, authority ContentAuthority, keys Keys, dst io.Writer) (Prepared, error) {
	if ctx == nil || !i.validExternal() || i.OwnerType != "system" || i.Type != "capability_snapshot" || i.Media != "application/json" || i.ContentSize > MaxCapabilityContent ||
		!key.valid() || source == nil || nilSystemAdapter(dst) || nilSystemAdapter(authority) || nilSystemAdapter(keys) || ctx.Err() != nil {
		return Prepared{}, ErrInvalid
	}
	baseline, err := authority.AuthorizeContent(ctx, i)
	if err != nil {
		return Prepared{}, ErrDenied
	}
	_, policyHash, err := contentValidator(baseline, i)
	if err != nil {
		return Prepared{}, ErrDenied
	}
	// Retain values, never the adapter's mutable policy pointer. The original
	// deadline bounds every read, encryption step and the final live check.
	call := &systemContentCall{authority, i, baseline.ProducerIdentityHash, policyHash, baseline.ValidUntil}
	ctx, cancel := context.WithDeadline(ctx, baseline.ValidUntil)
	defer cancel()
	dispatcher, err := NewContentDispatcher(call)
	if err != nil {
		return Prepared{}, err
	}
	prepared, err := prepareExternal(ctx, i, key, source, dispatcher, keys, dst)
	if err != nil {
		return Prepared{}, err
	}
	if _, err := call.AuthorizeContent(ctx, i); err != nil {
		return Prepared{}, ErrDenied
	}
	return prepared, nil
}

func nilSystemAdapter(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}

type systemContentCall struct {
	authority ContentAuthority
	identity  Identity
	producer  string
	policy    string
	until     time.Time
}

func (c *systemContentCall) AuthorizeContent(ctx context.Context, i Identity) (ContentAuthorization, error) {
	if i != c.identity || ctx.Err() != nil || !time.Now().Before(c.until) {
		return ContentAuthorization{}, ErrDenied
	}
	a, err := c.authority.AuthorizeContent(ctx, i)
	if err != nil {
		return ContentAuthorization{}, ErrDenied
	}
	_, policy, err := contentValidator(a, i)
	if err != nil || policy != c.policy || a.ProducerIdentityHash != c.producer || !a.ValidUntil.Equal(c.until) || ctx.Err() != nil || !time.Now().Before(c.until) {
		return ContentAuthorization{}, ErrDenied
	}
	return a, nil
}
