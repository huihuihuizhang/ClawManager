package systembackupexecution

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"clawreef/internal/systembackup/staging"
	c "clawreef/internal/systembackupcontroller"
)

// Real original SQL/receipt/history, current publisher, private observed C
// copies, TLS Unwrap and a full inert portable-workspace read. This does not
// prove all six domains or artifact/terminal acceptance. Runtime stop/resume
// remain named fixtures.
func TestAPublicationConsumesOnlyOriginalPrivateObservedCFiles(t *testing.T) {
	for _, mode := range []string{"private-only", "missing-private-cipher", "changed-private-cipher", "changed-private-envelope", "renew-old-object"} {
		t.Run(mode, func(t *testing.T) {
			x, _, _ := newAOriginalPublicationService(t)
			h, ctx := x.history, context.Background()
			h.service.staging = h.owner.Staging
			if mode == "private-only" {
				worker, err := h.owner.Staging.OpenRoot(h.original.TaskPublicID)
				if err != nil {
					t.Fatal(err)
				}
				if worker.Remove(h.candidate.Ciphertext.Name) != nil || worker.Remove(h.candidate.Envelope.Name) != nil {
					t.Fatal("named worker outputs not removed")
				}
				worker.Close()
			} else if mode != "renew-old-object" {
				custody, err := staging.OpenSealCustody(h.owner.Staging)
				if err != nil {
					t.Fatal(err)
				}
				v, err := h.service.PublisherVerifierForPart(ctx, h.token, h.original.AttemptNo, "workspace")
				if err != nil {
					t.Fatal(err)
				}
				record, err := v.CapturedRecord(ctx)
				v.Close()
				if err != nil {
					t.Fatal(err)
				}
				files, _, err := staging.OpenFormalObserved(ctx, custody, record.SealScope, h.candidate.Ciphertext, h.candidate.Envelope)
				custody.Close()
				if err != nil {
					t.Fatal(err)
				}
				name := files.Ciphertext.Name()
				if mode == "changed-private-envelope" {
					name = files.Envelope.Name()
				}
				files.Close()
				if mode == "missing-private-cipher" {
					if os.Remove(name) != nil {
						t.Fatal("named private file removal")
					}
				} else {
					// Custody deliberately seals files read-only. Only this owned
					// adversarial test fixture changes its local mode before tampering.
					if os.Chmod(name, 0600) != nil {
						t.Fatal("owned tamper fixture mode")
					}
					file, err := os.OpenFile(name, os.O_WRONLY, 0)
					if err != nil {
						t.Fatal(err)
					}
					_, err = file.WriteAt([]byte{0}, 0)
					file.Close()
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			part, err := h.service.openPublicationCaptureFiles(ctx, h.token, h.original.AttemptNo, "workspace")
			valid := mode == "private-only" || mode == "renew-old-object"
			if !valid {
				if err == nil || part != nil {
					if part != nil {
						part.Close()
					}
					t.Fatal("bad private copy accepted or worker fallback used", err)
				}
				if x.logins.Load() != 0 || x.decrypts.Load() != 0 {
					t.Fatal("bad private copy reached provider")
				}
				return
			}
			if err != nil || part == nil {
				t.Fatal("actual private publisher intake", err)
			}
			defer part.Close()
			if !part.domainVerified || len(part.controlPlain) != 0 {
				t.Fatal("publisher omitted inert domain read")
			}
			if part.candidate != h.candidate || part.stream.CiphertextSHA256() != h.candidate.Ciphertext.SHA256 || part.stream.CiphertextBytes() != h.candidate.Ciphertext.Size || x.logins.Load() != 1 || x.decrypts.Load() != 1 || part.check(ctx) != nil {
				t.Fatal("original bytes/current claim lost")
			}
			if mode == "renew-old-object" {
				fresh, err := (c.ClaimCoordinator{Executor: h.db, InstallationID: h.original.InstallationID}).Renew(ctx, h.token, c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second})
				if err != nil || fresh.RowVersion == h.token.RowVersion {
					t.Fatal("actual Renew", err)
				}
				if part.check(ctx) == nil {
					t.Fatal("old authenticated files adopted renewed claim")
				}
				return
			}
			// Same retained private descriptor, rewound at byte zero, reaches EOF.
			raw, err := io.ReadAll(part.files.Ciphertext)
			if err != nil || int64(len(raw)) != h.candidate.Ciphertext.Size || hash(raw) != h.candidate.Ciphertext.SHA256 {
				t.Fatal("private ciphertext descriptor replaced")
			}
			envelope, err := io.ReadAll(part.files.Envelope)
			if err != nil || hash(envelope) != h.candidate.Envelope.SHA256 {
				t.Fatal("private envelope descriptor replaced")
			}
			part.Close()
			if part.check(ctx) == nil {
				t.Fatal("closed publisher files retained authority")
			}
		})
	}
}
