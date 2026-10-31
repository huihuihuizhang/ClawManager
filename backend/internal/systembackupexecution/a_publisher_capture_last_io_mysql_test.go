package systembackupexecution

import (
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	s "clawreef/internal/systembackupsecurity"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestAPublisherCaptureAuthorityRejectsChangesDuringLastWorkloadIO(t *testing.T) {
	for _, entry := range []string{"constructor", "check"} {
		for _, mode := range []string{"actual-renew", "business-revoke", "fixed-window-expired"} {
			t.Run(entry+"/"+mode, func(t *testing.T) {
				x := newAPublisherCaptureAuthorityFixture(t)
				if mode == "fixed-window-expired" {
					x.grant.Until = time.Now().UTC().Add(750 * time.Millisecond)
					x.writeGrant(t, true)
				}
				var authority *s.SQLPublisherCaptureAuthority
				if entry == "check" {
					authority = x.authority(t)
				}
				calls, changed := 0, false
				var fresh c.ClaimToken
				x.f.x.client.PrependReactor("get", "serviceaccounts", func(ktesting.Action) (bool, kruntime.Object, error) {
					calls++
					if calls == 2 {
						if x.f.db.Stats().InUse != 0 {
							t.Fatal("last workload read held original SQL connection")
						}
						switch mode {
						case "actual-renew":
							var err error
							fresh, err = c.RenewClaimInInstallation(x.f.ctx, x.f.db, x.f.installation, x.token, x.f.policy)
							if err != nil || fresh.RowVersion != x.token.RowVersion+1 {
								t.Fatal("actual Renew did not change current claim", err)
							}
						case "business-revoke":
							x.grant.Revoked = true
							x.writeGrant(t, false)
						case "fixed-window-expired":
							if delay := time.Until(x.grant.Until) + 25*time.Millisecond; delay > 0 {
								time.Sleep(delay)
							}
						}
						changed = true
					}
					return false, nil, nil
				})
				var err error
				if entry == "constructor" {
					authority, err = s.NewSQLPublisherCaptureAuthority(x.f.ctx, x.cfg, x.scope)
					if authority != nil {
						t.Fatal("constructor returned authority after final I/O drift")
					}
				} else {
					err = authority.Check(x.f.ctx)
				}
				if !changed || calls != 2 || err == nil {
					t.Fatal("last workload I/O drift accepted", mode, calls, err)
				}
				if mode == "actual-renew" {
					if _, err = s.NewSQLPublisherCaptureAuthority(x.f.ctx, x.cfg, x.scope); err == nil {
						t.Fatal("old claim accepted after failed I/O check")
					}
					x.scope.Claim.RowVersion = fresh.RowVersion
					current := x.authority(t)
					if err = current.Check(x.f.ctx); err != nil {
						t.Fatal("fresh token not accepted through full new authority", err)
					}
					if current.Scope().Claim.RowVersion != fresh.RowVersion {
						t.Fatal("fresh authority did not retain actual new token")
					}
				}
				if x.f.x.logins.Load() != 0 || x.f.x.signs.Load() != 0 {
					t.Fatal("read proof race reached provider")
				}
			})
		}
	}
}

func TestAPublisherCaptureWorkloadRechecksGrantAfterLastGET(t *testing.T) {
	x := newAPublisherCaptureAuthorityFixture(t)
	authority := x.authority(t)
	changed := false
	x.f.x.client.PrependReactor("get", "serviceaccounts", func(ktesting.Action) (bool, kruntime.Object, error) {
		x.grant.Revoked = true
		x.writeGrant(t, false)
		changed = true
		return false, nil, nil
	})
	if authority.CheckWorkload(x.f.ctx) == nil || !changed {
		t.Fatal("workload returned success using grant read before final GET")
	}
}
