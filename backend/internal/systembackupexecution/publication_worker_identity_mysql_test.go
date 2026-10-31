package systembackupexecution

import (
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackup/control"
	c "clawreef/internal/systembackupcontroller"
)

type aPublicationIssuerEffect struct {
	crypto.Signer
	after func()
}

func (s aPublicationIssuerEffect) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := s.Signer.Sign(random, digest, opts)
	if err == nil {
		s.after()
	}
	return signature, err
}

// Actual signed deployment issue_worker action and independent current
// publisher SQL claim. The software CA is a named local fixture, and this is
// an mTLS identity stage, not artifact signing or a complete publish Job.
func TestPublicationWorkerIdentityUsesCurrentPublisherAndExplicitIssuerActionMySQL(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" {
		t.Skip("requires owned local MySQL")
	}
	for _, mode := range []string{"current", "missing-issue-action", "issuer-pin-changed", "release-during-sign"} {
		t.Run(mode, func(t *testing.T) {
			var issuer control.IdentityIssuer
			originalMTLSControlServer(t, http.NotFoundHandler(), func(value control.IdentityIssuer) { issuer = value })
			options := aPublisherVerifierFixtureOptions{FullService: true, WorkerIssuer: &issuer}
			if mode == "missing-issue-action" {
				// A well-formed read/capture deployment omits BOTH issuing action
				// and issuer authorization pin. NewPinnedExecutionIdentity already
				// rejects a pinned issuer without its mandatory issuing action.
				options.ConfigureExecutionGrant = func(g *c.ExecutionGrant) { g.Actions = []string{"prepare", "capture"}; g.WorkerIssuerSHA256 = "" }
			}
			x := newAPublisherVerifierFixtureOptions(t, options)
			aStartPublisherVerifierSamePod(t, x)
			h, ctx := x.history, context.Background()
			h.owner.Issuer = issuer
			h.service.Runtime = &PublicCapture{Owner: h.owner}
			if mode == "missing-issue-action" {
				for _, action := range h.service.Forward.DeploymentBinding().Actions {
					if action == "issue_worker" {
						t.Fatal("missing-action fault was not present in actual signed grant")
					}
				}
			}
			requestSHA := hash([]byte("original publication request DATA"))
			var signed, entered, applied atomic.Bool
			h.owner.Issuer.Signer = aPublicationIssuerEffect{Signer: issuer.Signer, after: func() {
				signed.Store(true)
				if mode != "release-during-sign" || !entered.CompareAndSwap(false, true) {
					return
				}
				fault, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				var owner sql.NullString
				var version uint64
				if h.admin.QueryRowContext(fault, "SELECT controller_owner,row_version FROM system_backup_v2_backups WHERE public_id=?", h.original.TaskPublicID).Scan(&owner, &version) != nil || !owner.Valid || owner.String != h.token.Owner || version != h.token.RowVersion {
					t.Error("claim not live before signing effect")
					return
				}
				if _, e := (c.ClaimCoordinator{Executor: h.admin, InstallationID: h.original.InstallationID}).Release(fault, h.token, time.Second); e != nil {
					t.Error("actual Release blocked during CA signing", e)
					return
				}
				if h.admin.QueryRowContext(fault, "SELECT controller_owner,row_version FROM system_backup_v2_backups WHERE public_id=?", h.original.TaskPublicID).Scan(&owner, &version) != nil || owner.Valid || version <= h.token.RowVersion {
					t.Error("CA signing effect did not actually withdraw original claim")
					return
				}
				applied.Store(true)
			}}
			if mode == "issuer-pin-changed" {
				changed := *issuer.Certificate
				changed.Raw = append([]byte(nil), issuer.Certificate.Raw...)
				changed.Raw[0] ^= 1
				h.owner.Issuer.Certificate = &changed
			}
			identity, err := h.service.issuePublicationWorkerIdentity(ctx, h.token, h.original.AttemptNo, requestSHA)
			defer identity.Clear()
			if mode != "current" {
				if err == nil || len(identity.Data) != 0 {
					t.Fatal("unauthorized worker identity escaped", mode, err)
				}
				if mode == "release-during-sign" {
					if !signed.Load() || !applied.Load() {
						t.Fatal("actual signing/release effect not reached")
					}
				} else if signed.Load() {
					t.Fatal("denied action/pin reached CA signing")
				}
				return
			}
			if err != nil || !signed.Load() || len(identity.Data) != 3 {
				t.Fatal("actual current publication worker identity", err)
			}
			block, _ := pem.Decode(identity.Data["tls.crt"])
			if block == nil {
				t.Fatal("issued certificate")
			}
			certificate, e := x509.ParseCertificate(block.Bytes)
			if e != nil {
				t.Fatal(e)
			}
			if len(certificate.URIs) != 1 || !strings.HasSuffix(certificate.URIs[0].String(), "/backup/"+h.original.TaskPublicID+"/"+requestSHA) || certificate.NotAfter.After(h.original.DeadlineAt) || certificate.NotAfter.After(issuer.Certificate.NotAfter) {
				t.Fatal("publication identity subject/window")
			}
		})
	}
}
