package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	s "clawreef/internal/systembackupsecurity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type aPublisherCaptureAuthorityFixture struct {
	f      *aPublicationClaims
	token  c.ClaimToken
	cfg    s.PublisherCaptureAuthorityConfig
	scope  s.PublisherCaptureScope
	grant  s.PublisherCaptureGrant
	issuer ed25519.PrivateKey
}

type aUncomparablePublisherContext struct {
	context.Context
	data []byte
}

func newAPublisherCaptureAuthorityFixture(t *testing.T) *aPublisherCaptureAuthorityFixture {
	t.Helper()
	f := newAPublicationClaims(t)
	token := f.acquire(t, f.x.service.PublisherOwner, 7)
	g := f.x.service.Forward.DeploymentBinding()
	w := f.x.service.publicationRuntime
	x := &aPublisherCaptureAuthorityFixture{f: f, token: token}
	x.cfg = s.PublisherCaptureAuthorityConfig{DB: f.db, Kubernetes: f.x.client, Deployment: s.PublisherCaptureDeployment{InstallationID: g.InstallationID, ServerUUID: g.ServerUUID, Database: g.Database, DatabaseAccount: g.DatabaseAccount, ControllerOwner: g.ControllerOwner, ConfigVersion: g.ConfigVersion, ConfigSHA256: g.ConfigSHA256, ProfileSHA256: g.ProfileSHA256, DeploymentConfigSHA256: g.DeploymentConfigSHA256, CaptureGrantSHA256: f.x.service.Forward.GrantSHA256(), NotBefore: g.NotBefore, Until: g.ExpiresAt}, Workload: s.PublisherCaptureWorkload{Namespace: w.Namespace, NamespaceUID: w.NamespaceUID, PodName: w.PodName, PodUID: w.PodUID, ServiceAccountName: w.ServiceAccountName, ServiceAccountUID: w.ServiceAccountUID, PublisherOwner: w.PublisherOwner}}
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	x.issuer = private
	t.Cleanup(func() { clear(private) })
	x.cfg.GrantMount = s.PublisherCaptureGrantMount{File: filepath.Join(t.TempDir(), "independent-publisher-verifier-grant.json"), Issuer: pub}
	x.grant = s.PublisherCaptureGrant{Version: s.PublisherCaptureGrantVersion, Deployment: x.cfg.Deployment, Workload: x.cfg.Workload, NotBefore: time.Now().UTC().Add(-time.Minute), Until: time.Now().UTC().Add(time.Minute)}
	x.writeGrant(t, true)
	x.scope = s.PublisherCaptureScope{BackupPublicID: token.Target.PublicID, Claim: s.SQLSigningClaim{ControllerOwner: token.Owner, RowVersion: token.RowVersion}, CaptureAttemptNo: 1, Part: "users_instances_database"}
	f.x.client.PrependReactor("*", "*", func(ktesting.Action) (bool, kruntime.Object, error) {
		if f.db.Stats().InUse != 0 {
			t.Error("publisher authority used Kubernetes while original SQL transaction held")
		}
		return false, nil, nil
	})
	return x
}

func (x *aPublisherCaptureAuthorityFixture) writeGrant(t *testing.T, repin bool) {
	t.Helper()
	record, err := json.Marshal(x.grant)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(s.SignedPublisherCaptureGrant{Record: record, Signature: ed25519.Sign(x.issuer, append([]byte(s.PublisherCaptureGrantDomain), record...))})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(x.cfg.GrantMount.File, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if repin {
		x.cfg.GrantMount.SHA256 = hash(raw)
		x.cfg.Workload.GrantSHA256 = hash(raw)
	}
}

func (x *aPublisherCaptureAuthorityFixture) authority(t *testing.T) *s.SQLPublisherCaptureAuthority {
	t.Helper()
	a, err := s.NewSQLPublisherCaptureAuthority(x.f.ctx, x.cfg, x.scope)
	if err != nil {
		t.Fatal("concrete independent publisher capture authority", err)
	}
	return a
}

func TestAPublisherCaptureAuthorityCurrentSQLAndWorkload(t *testing.T) {
	for _, status := range []string{"validating", "publishing", "finalization_unknown"} {
		t.Run(status, func(t *testing.T) {
			x := newAPublisherCaptureAuthorityFixture(t)
			f := x.f
			if _, err := f.owner.ExecContext(f.ctx, `UPDATE system_backup_v2_backups SET status=? WHERE public_id=?`, status, f.target.PublicID); err != nil {
				t.Fatal(err)
			}
			a := x.authority(t)
			if a.Scope() != x.scope || a.Deployment() != x.cfg.Deployment || a.ValidUntil().IsZero() {
				t.Fatal("authority did not freeze original scope/deployment")
			}
			if err := a.Check(f.ctx); err != nil {
				t.Fatal(err)
			}
			tx, err := f.db.BeginTx(f.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			calls := len(f.x.client.Actions())
			guard, err := a.Bind(f.ctx, tx)
			if err != nil {
				t.Fatal(err)
			}
			facts := guard.Facts()
			if facts.Status != status || facts.RequestID != "original-claim-api-publication" || facts.CaptureAttemptNo != 1 || facts.CaptureEpoch != 17 || facts.BackupPublicID != f.target.PublicID || !guard.ValidUntil().Equal(a.ValidUntil()) {
				t.Fatal("original publisher SQL fact/shortest window mismatch")
			}
			if err = guard.RecheckTx(f.ctx, tx); err != nil {
				t.Fatal(err)
			}
			if len(f.x.client.Actions()) != calls {
				t.Fatal("Bind/RecheckTx contacted Kubernetes")
			}
			uncomparable := aUncomparablePublisherContext{Context: f.ctx, data: []byte{1}}
			if _, err = a.Bind(uncomparable, tx); err == nil {
				t.Fatal("uncomparable context admitted to publisher guard")
			}
			if guard.RecheckTx(uncomparable, tx) == nil {
				t.Fatal("uncomparable context admitted to guard recheck")
			}
			var nilContext *aUncomparablePublisherContext
			if _, err = a.Bind(nilContext, tx); err == nil {
				t.Fatal("typed nil context admitted")
			}
			derived, cancel := context.WithCancel(f.ctx)
			defer cancel()
			if guard.RecheckTx(derived, tx) == nil {
				t.Fatal("foreign context used original guard")
			}
			if _, err = tx.ExecContext(f.ctx, `UPDATE system_backup_v2_backups SET row_version=row_version+1 WHERE public_id=?`, f.target.PublicID); err != nil {
				t.Fatal(err)
			}
			if guard.RecheckTx(f.ctx, tx) == nil {
				t.Fatal("same original transaction drift escaped guard")
			}
			tx.Rollback()
			if f.x.logins.Load() != 0 || f.x.signs.Load() != 0 {
				t.Fatal("read authority contacted signing provider")
			}
		})
	}
}

func TestAPublisherCaptureAuthorityRejectsRenewRevokeAndScope(t *testing.T) {
	t.Run("actual renewed old token", func(t *testing.T) {
		x := newAPublisherCaptureAuthorityFixture(t)
		a := x.authority(t)
		renewed, err := c.RenewClaimInInstallation(x.f.ctx, x.f.db, x.f.installation, x.token, x.f.policy)
		if err != nil {
			t.Fatal(err)
		}
		if a.Check(x.f.ctx) == nil {
			t.Fatal("renewed claim adopted by old authority")
		}
		x.scope.Claim.RowVersion = renewed.RowVersion
		x.authority(t)
	})
	t.Run("business revoke", func(t *testing.T) {
		x := newAPublisherCaptureAuthorityFixture(t)
		a := x.authority(t)
		x.grant.Revoked = true
		x.writeGrant(t, false)
		if a.Check(x.f.ctx) == nil {
			t.Fatal("replaced independent business grant ignored")
		}
		x.writeGrant(t, true)
		if _, err := s.NewSQLPublisherCaptureAuthority(x.f.ctx, x.cfg, x.scope); err == nil {
			t.Fatal("validly signed explicit business revoke accepted")
		}
	})
	t.Run("workload replaced", func(t *testing.T) {
		x := newAPublisherCaptureAuthorityFixture(t)
		a := x.authority(t)
		sa, err := x.f.x.client.CoreV1().ServiceAccounts(x.cfg.Workload.Namespace).Get(x.f.ctx, x.cfg.Workload.ServiceAccountName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		sa.UID = "replaced"
		if _, err = x.f.x.client.CoreV1().ServiceAccounts(sa.Namespace).Update(x.f.ctx, sa, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if a.Check(x.f.ctx) == nil {
			t.Fatal("replaced actual SA ignored")
		}
	})
	for _, fault := range []string{"capture owner", "old version", "other backup", "other attempt", "unsealed", "capturing", "canceled", "expired task", "source not resumed", "capture result drift", "wrong peer"} {
		t.Run(fault, func(t *testing.T) {
			x := newAPublisherCaptureAuthorityFixture(t)
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := x.f.owner.ExecContext(x.f.ctx, q, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "capture owner":
				x.scope.Claim.ControllerOwner = x.cfg.Deployment.ControllerOwner
			case "old version":
				x.scope.Claim.RowVersion--
			case "other backup":
				x.scope.BackupPublicID = "sbk_22222222-2222-4333-8444-555555555555"
			case "other attempt":
				x.scope.CaptureAttemptNo++
			case "unsealed":
				exec(`UPDATE system_backup_v2_attempts SET status='running'`)
			case "capturing":
				exec(`UPDATE system_backup_v2_backups SET status='capturing'`)
			case "canceled":
				exec(`INSERT INTO system_backup_v2_operations(origin_installation_id,target_type,target_public_id,operation_type,status) VALUES (?,'backup',?,'cancel','pending')`, x.f.installation, x.f.target.PublicID)
			case "expired task":
				exec(`UPDATE system_backup_v2_backups SET deadline_at=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6))`)
			case "source not resumed":
				exec(`UPDATE system_backup_v2_runtime_captures SET source_resumed_at=NULL`)
			case "capture result drift":
				exec(`UPDATE system_backup_v2_execution_records SET payload_sha256='invalid'`)
			case "wrong peer":
				x.cfg.Deployment.Database = "different"
				x.grant.Deployment = x.cfg.Deployment
				x.writeGrant(t, true)
			}
			if _, err := s.NewSQLPublisherCaptureAuthority(x.f.ctx, x.cfg, x.scope); err == nil {
				t.Fatal("unavailable original publisher facts admitted")
			}
			if x.f.x.logins.Load() != 0 || x.f.x.signs.Load() != 0 {
				t.Fatal("invalid lookup reached provider")
			}
		})
	}
}

func TestAPublisherCaptureAuthorityBoundsBusinessAndSQLWindow(t *testing.T) {
	x := newAPublisherCaptureAuthorityFixture(t)
	x.grant.Until = time.Now().UTC().Add(700 * time.Millisecond)
	x.writeGrant(t, true)
	a := x.authority(t)
	if !a.ValidUntil().Equal(x.grant.Until) {
		t.Fatal("independent business deadline not shortest")
	}
	x.f.waitDB(t, `SELECT UTC_TIMESTAMP(6)>=?`, x.grant.Until)
	if a.Check(x.f.ctx) == nil {
		t.Fatal("expired publisher business authorization accepted")
	}
}

func TestAPublisherCaptureAuthoritySignedGrantAndPinBoundaries(t *testing.T) {
	x := newAPublisherCaptureAuthorityFixture(t)
	baseGrant, baseCfg := x.grant, x.cfg
	for _, fault := range []string{"future", "expired", "too long", "wrong version", "deployment drift", "workload drift", "wrong issuer", "wrong pin", "wrong domain", "missing part", "nil client"} {
		t.Run(fault, func(t *testing.T) {
			x.grant, x.cfg = baseGrant, baseCfg
			scope := x.scope
			switch fault {
			case "future":
				x.grant.NotBefore = time.Now().UTC().Add(time.Minute)
				x.grant.Until = x.grant.NotBefore.Add(time.Hour)
			case "expired":
				x.grant.NotBefore = time.Now().UTC().Add(-2 * time.Hour)
				x.grant.Until = time.Now().UTC().Add(-time.Hour)
			case "too long":
				x.grant.Until = x.grant.NotBefore.Add(25 * time.Hour)
			case "wrong version":
				x.grant.Version = "other"
			case "deployment drift":
				x.grant.Deployment.ConfigVersion++
			case "workload drift":
				x.grant.Workload.PublisherOwner = "public:other-pod"
			case "missing part":
				scope.Part = ""
			case "nil client":
				var client *fake.Clientset
				x.cfg.Kubernetes = client
			}
			x.writeGrant(t, true)
			switch fault {
			case "wrong issuer":
				x.cfg.GrantMount.Issuer = make([]byte, 32)
			case "wrong pin":
				x.cfg.GrantMount.SHA256 = hash([]byte("different"))
				x.cfg.Workload.GrantSHA256 = x.cfg.GrantMount.SHA256
			case "wrong domain":
				raw, err := os.ReadFile(x.cfg.GrantMount.File)
				if err != nil {
					t.Fatal(err)
				}
				var envelope s.SignedPublisherCaptureGrant
				if json.Unmarshal(raw, &envelope) != nil {
					t.Fatal("fixture")
				}
				envelope.Signature = ed25519.Sign(x.issuer, append([]byte(s.InstallationSigningDomain), envelope.Record...))
				raw, _ = json.Marshal(envelope)
				if err = os.WriteFile(x.cfg.GrantMount.File, raw, 0600); err != nil {
					t.Fatal(err)
				}
				x.cfg.GrantMount.SHA256 = hash(raw)
				x.cfg.Workload.GrantSHA256 = hash(raw)
			}
			if _, err := s.NewSQLPublisherCaptureAuthority(x.f.ctx, x.cfg, scope); err == nil {
				t.Fatal("invalid independent original grant/pin admitted")
			}
		})
	}
}
