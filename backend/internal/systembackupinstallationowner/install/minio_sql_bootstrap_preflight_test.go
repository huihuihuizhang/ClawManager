package install

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// Actual original Installer/auth/signatures/current reader with the existing
// explicit SQL/Kubernetes transport model. No native qualification is claimed.
func TestOriginalMinIOSQLBootstrapPreflightAuthenticatesAbsentAndExactActive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newMinioSQLLifecycleFixture(t)
	raw := f.issue(t, ctx)
	before := cloneMinioSQLData(f.model.data)
	execs := f.model.execs
	if e := f.base.i.AuthorizeMinIOSQLInstallation(ctx, f.base.password, f.base.enrollment, f.intent.Pin, raw, hash(raw)); e != nil {
		t.Fatal("original absent-domain authorization", e)
	}
	if f.model.execs != execs || !reflect.DeepEqual(before, f.model.data) || f.model.open.Load() != 0 {
		t.Fatal("preflight mutated original SQL")
	}
	importMinioSQLFixture(t, ctx, f, raw)
	before = cloneMinioSQLData(f.model.data)
	execs = f.model.execs
	if e := f.base.i.AuthorizeMinIOSQLInstallation(ctx, f.base.password, f.base.enrollment, f.intent.Pin, raw, hash(raw)); e != nil {
		t.Fatal("same original active-domain authorization", e)
	}
	if f.model.execs != execs || !reflect.DeepEqual(before, f.model.data) || f.model.open.Load() != 0 {
		t.Fatal("active preflight changed seven rows")
	}
}

func TestOriginalMinIOSQLBootstrapPreflightRejectsForeignAndRevoked(t *testing.T) {
	for _, scenario := range []string{"password", "issuer", "tuple", "revoked", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			f := newMinioSQLLifecycleFixture(t)
			raw := f.issue(t, ctx)
			password := f.base.password
			pin := f.intent.Pin
			switch scenario {
			case "password":
				password = []byte("foreign-original-operator-password")
			case "issuer":
				pin.IssuerPublic = append([]byte(nil), pin.IssuerPublic...)
				pin.IssuerPublic[0] ^= 1
			case "tuple":
				pin.GrantSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			case "revoked":
				importMinioSQLFixture(t, ctx, f, raw)
				revoke, e := f.base.i.IssueMinIOSQLRevocation(ctx, f.base.password, f.base.enrollment, pin, f.base.key)
				if e != nil {
					t.Fatal(e)
				}
				importMinioSQLFixture(t, ctx, f, revoke)
			case "expired":
				f.model.clock = f.intent.Grant.Until.Add(time.Microsecond)
			}
			before := cloneMinioSQLData(f.model.data)
			execs := f.model.execs
			if e := f.base.i.AuthorizeMinIOSQLInstallation(ctx, password, f.base.enrollment, pin, raw, hash(raw)); e == nil {
				t.Fatal("foreign/revoked/expired scope authorized before native probes")
			}
			if f.model.execs != execs || !reflect.DeepEqual(before, f.model.data) || f.model.open.Load() != 0 {
				t.Fatal("refused preflight mutated original SQL")
			}
		})
	}
}
