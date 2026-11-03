package systembackupcatrust

import (
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"os"
	"testing"
	"time"
)

// Actual loopback TLS/private local files; no installed deployment authority
// or config mutation permission is created by this native component test.
func TestEnableOnlyCAUsesActualTLSAndPinsOriginalConfig(t *testing.T) {
	f := newFixture(t, false)
	current, e := sec.DecodeConfigValues(f.config.CanonicalJSON())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o, e := f.v.observeEnableOnlyCurrent(ctx, current)
	if e != nil || o == nil || f.handshakes.Load() != 1 {
		t.Fatal("real TLS observation", e)
	}
	deadline, _ := ctx.Deadline()
	if o.ValidUntil().After(deadline) || !o.ValidUntil().After(time.Now()) {
		t.Fatal("deadline was extended")
	}
	if o.Recheck(ctx, nil, time.Now().UTC()) == nil || !o.ValidUntil().IsZero() {
		t.Fatal("invalid transaction did not poison observation")
	}
	if _, e := f.v.ObserveEnableOnly(ctx, sec.ConfigMutationResourceInput{}); e == nil {
		t.Fatal("missing actual mutation snapshots accepted")
	}
}
func TestEnableOnlyCARejectsChangedAndUntrustedNativeInputs(t *testing.T) {
	for _, which := range []string{"leaf", "config", "ca_file"} {
		t.Run(which, func(t *testing.T) {
			f := newFixture(t, which == "leaf")
			current, e := sec.DecodeConfigValues(f.config.CanonicalJSON())
			if e != nil {
				t.Fatal(e)
			}
			if which == "config" {
				f.v.binding.ConfigSHA256 = ""
			}
			if which == "ca_file" {
				if e := os.WriteFile(f.v.binding.CAFile, []byte("changed"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := f.v.observeEnableOnlyCurrent(context.Background(), current); e == nil {
				t.Fatal("changed/untrusted CA accepted")
			}
		})
	}
}
