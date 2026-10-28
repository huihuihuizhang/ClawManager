package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql/driver"
	"strings"
	"testing"
	"time"
)

func TestPublicDownloadConcreteOwnerHTTPReleasesAfterRevocationAndCancel(t *testing.T) {
	for _, mode := range []string{"public", "internal", "revoked", "canceled", "release_failure"} {
		t.Run(mode, func(t *testing.T) {
			classification := mode
			if classification != "internal" {
				classification = "public"
			}
			x := newAdmittedHTTPFixture(t, classification)
			s, err := NewSQLTaskDownloadOwners(SQLTaskDownloadOwnersConfig{Registry: x.f.service.registry, Sessions: x.f.env.sessions, RegistryDirectory: x.a.c.RegistryDirectory})
			if err != nil {
				t.Fatal(err)
			}
			model := newSQLTaskOwnerModel(t, x.f, "backup")
			// Real SQL time advances across provider checks. Keep the original
			// claim/session/config limits fixed; only sample observations afresh.
			x.f.db.ownerQuery = func(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, bool, error) {
				if strings.Contains(q, "UTC_TIMESTAMP(6)") {
					x.f.db.now = time.Now().UTC().Truncate(time.Microsecond)
				}
				return model.query(ctx, q, args)
			}
			r := s.Registry()
			x.f.service.registry, x.a.c.Registry = r, r
			x.h.service.Registry, x.h.public.Service.Registry = r, r
			x.h.results.c.Registry, x.h.results.c.Owners = r, s
			w := admittedWriter()
			if mode == "revoked" {
				w.onHeader = func() { x.f.db.sessionRevoked, x.f.db.userActive = true, false }
			}
			if mode == "canceled" {
				ctx, cancel := context.WithCancel(x.f.request.Context())
				defer cancel()
				x.f.request = x.f.request.WithContext(ctx)
				w.onHeader = cancel
			}
			if mode == "release_failure" {
				x.f.db.fault = "release_sql"
				x.h.public.Service.Failure = func(ctx context.Context, id, code string) {
					x.failures++
					if ctx.Err() != nil || id != x.f.initial.Manifest.Identity.ID || code != "download_audit_or_release_failed" {
						t.Error("public failure lost independent budget", ctx.Err(), code)
					}
				}
			}
			x.h.ServeHTTP(w, x.f.request)
			wantFailures, wantVersion := 0, x.f.initial.RowVersion+2
			if mode == "release_failure" {
				wantFailures, wantVersion = 1, x.f.initial.RowVersion+1
			}
			if w.Code != 206 || !bytes.Equal(w.Body.Bytes(), x.plain[:21]) || x.failures != wantFailures || (x.f.db.record.Claim == "") != (mode != "release_failure") || x.f.db.record.RowVersion != wantVersion {
				t.Fatal("public response/independent release", mode, w.Code, x.failures, x.f.db.record.Claim, x.f.db.record.RowVersion)
			}
			if x.f.db.inserts != 0 || x.f.db.resultInserts != 0 || len(x.f.db.nonce) != 0 || len(x.f.db.m.op) != 0 || len(x.f.db.m.receipt) != 0 {
				t.Fatal("public cleanup created private admission/audit authority")
			}
		})
	}
}

func TestPublicDownloadReleaseIsExactClaimAndIndependentOfUserSession(t *testing.T) {
	for _, mode := range []string{"revoked", "expired_claim", "other_claim", "changed_version", "private", "foreign_origin", "version_ceiling", "owner_changed", "unknown_commit"} {
		t.Run(mode, func(t *testing.T) {
			f, _, owners, m := sqlTaskOwnerFixture(t, "backup")
			r := f.initial
			r.Manifest.Identity.Classification = "public"
			r.Claim = "aev_" + strings.Repeat("8", 32)
			r.ClaimUntil = f.db.now.Add(30 * time.Second)
			r.RowVersion++
			f.db.record, f.db.m.f.Record = r, r
			f.db.sessionRevoked, f.db.userActive = true, false
			switch mode {
			case "expired_claim":
				r.ClaimUntil = f.db.now.Add(-time.Minute)
				f.db.record, f.db.m.f.Record = r, r
			case "other_claim":
				f.db.record.Claim = "aev_" + strings.Repeat("9", 32)
			case "changed_version":
				f.db.record.RowVersion++
			case "private":
				r.Manifest.Identity.Classification = "sensitive"
			case "foreign_origin":
				origin := "installation_other"
				f.db.committedOrigin = &origin
			case "version_ceiling":
				r.RowVersion = 9007199254740991
				f.db.record.RowVersion = r.RowVersion
			case "owner_changed":
				m.deadline = m.deadline.Add(-time.Microsecond)
			case "unknown_commit":
				f.db.commitUnknown = true
			}
			handled, err := owners.Registry().finishPublicDownload(context.Background(), r)
			wantSuccess := mode == "revoked" || mode == "expired_claim"
			if !handled || (err == nil) != wantSuccess {
				t.Fatal("public release scope", mode, handled, err)
			}
			if mode == "unknown_commit" {
				if err != ErrDownloadResultCommitUnknown || f.db.commitAttempts != 1 {
					t.Fatal("unknown public commit was retried", err)
				}
				return
			}
			if wantSuccess && (f.db.record.Claim != "" || f.db.record.RowVersion != r.RowVersion+1) {
				t.Fatal("own public claim not released")
			}
			if !wantSuccess && f.db.record.Claim == "" {
				t.Fatal("different/private claim was released")
			}
			if f.db.inserts != 0 || f.db.resultInserts != 0 || f.db.reserved != 0 || len(f.db.nonce) != 0 {
				t.Fatal("public release acquired write/audit reservation")
			}
		})
	}
}
