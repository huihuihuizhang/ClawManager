package systembackup

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// Boundary fixtures only; no native identity/gate success is claimed.
func TestMinIOBuiltinIdentityNeedsCurrentBoundedAuthority(t *testing.T) {
	identity := MinIOBuiltinIdentity{Kind: "minio-builtin-static-identity.v1", AccessKey: "fixture-reader", SecretKey: []byte("fixture-secret-not-authority"), Version: "original-version"}
	if _, e := resolveMinIOBuiltinIdentity(context.Background(), identity, nil); e == nil {
		t.Fatal("nil owner accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e := resolveMinIOBuiltinIdentity(ctx, identity, func(context.Context) error { return ErrMinIOReadGate }); e == nil {
		t.Fatal("denied original current owner accepted")
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, e := resolveMinIOBuiltinIdentity(expired, identity, func(context.Context) error { return nil }); e == nil {
		t.Fatal("expired current invocation accepted")
	}
	if e := json.Unmarshal([]byte(`{"Kind":"minio-builtin-static-identity.v1","AccessKey":"x","SecretKey":"eA==","Version":"v"}`), &identity); e != nil {
		t.Fatal(e)
	}
	if _, e := resolveMinIOBuiltinIdentity(ctx, identity, func(context.Context) error { return nil }); e == nil {
		t.Fatal("invalid static key bypassed native credential validation")
	}
	if ObserveOriginalMinIOBuiltinIdentityMaterial(ctx, nil, "", "", nil) == nil {
		t.Fatal("empty setup became native identity observation")
	}
}
