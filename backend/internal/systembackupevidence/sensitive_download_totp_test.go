package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

func prepareDownloadProofTarget(t *testing.T, p *admissionPinnedFixture, rawRange string) (sec.SensitiveDownloadProofTarget, *sql.Tx) {
	t.Helper()
	fields := map[string]string{"evidence_id": p.initial.Manifest.Identity.ID}
	if rawRange != "" {
		fields["range"] = rawRange
		p.request.Header.Set("Range", rawRange)
	}
	p.sign(t, p.request.Header.Get("Idempotency-Key"), p.db.now.Add(-time.Minute), p.db.now.Add(time.Minute))
	raw, _ := json.Marshal(fields)
	selector, err := sec.DecodeSensitiveDownloadProofSelector(raw)
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewPinnedSensitiveDownloadProofTargets(p.service.registry, p.environment)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := p.service.registry.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	target, err := source.Prepare(context.Background(), tx, p.env.actor, selector, p.request.Header.Get("Idempotency-Key"))
	if err != nil {
		t.Fatal("proof target preparation", err, p.db.queries)
	}
	t.Cleanup(target.Close)
	return target, tx
}

func TestPinnedDownloadMFAUsesIdenticalGETBindingWithoutAdmissionEffects(t *testing.T) {
	for _, rawRange := range []string{"", "bytes=2-5", "bytes=2-", "bytes=-2", "bytes=0-999"} {
		t.Run(map[bool]string{true: "full", false: rawRange}[rawRange == ""], func(t *testing.T) {
			p := newAdmissionPinnedFixture(t)
			target, tx := prepareDownloadProofTarget(t, p, rawRange)
			bound, err := BindSensitiveDownloadRequest(p.env.actor, p.initial.Manifest, p.request.Header)
			if err != nil || target.Request() != bound || !target.ValidUntil().Equal(p.configuration.MaterialsUntil) {
				t.Fatal("issuance and GET differ", err)
			}
			if target.Recheck(context.Background(), tx, p.env.actor) == nil {
				t.Fatal("unverified proof target rechecked")
			}
			if err = target.ValidateProof(context.Background(), tx, p.env.actor, p.proof, p.db.now); err != nil {
				t.Fatal("trusted proof", err)
			}
			if err = target.Recheck(context.Background(), tx, p.env.actor); err != nil {
				t.Fatal("fresh original authority", err, p.db.queries)
			}
			if p.owners.previews != 2 || p.owners.locks != 0 || p.owners.guards != 0 || p.db.opKeyLocked || p.db.ownerLocked || p.db.evidenceLocked || p.db.reserved != 0 || p.db.commitAttempts != 0 || p.db.inserts != 0 || len(p.db.nonce) != 0 || len(p.db.m.op) != 0 || len(p.db.m.receipt) != 0 || len(p.db.body) != 0 {
				t.Fatal("MFA performed admission effects", p.db.calls)
			}
			target.Close()
			if target.Recheck(context.Background(), tx, p.env.actor) == nil || target.ValidateProof(context.Background(), tx, p.env.actor, p.proof, p.db.now) == nil {
				t.Fatal("closed target reused")
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			assertAdmissionRolledBack(t, p.admissionTxFixture)
		})
	}
}

func TestPinnedDownloadMFARereadsOriginalAuthorityAndMaterial(t *testing.T) {
	for _, name := range []string{"revoked", "password", "rbac", "historic-key", "active-key", "manifest", "locator", "expiry", "config-active", "config-cell", "wrong-actor", "wrong-proof", "future-issued-at", "wrong-transaction"} {
		t.Run(name, func(t *testing.T) {
			p := newAdmissionPinnedFixture(t)
			target, tx := prepareDownloadProofTarget(t, p, "")
			actor, proof, issuedAt := p.env.actor, p.proof, p.db.now
			validateFirst := name != "wrong-proof" && name != "future-issued-at" && name != "wrong-transaction"
			if validateFirst {
				if err := target.ValidateProof(context.Background(), tx, actor, proof, issuedAt); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "revoked":
				p.db.sessionRevoked = true
			case "password":
				p.db.password = "different-password-hash"
			case "rbac":
				writeAdmissionPinnedFile(t, p.rbacPath, []byte("{}"))
			case "historic-key":
				writeAdmissionPinnedFile(t, p.noncePaths["v1"], bytes.Repeat([]byte{0x44}, 32))
			case "active-key":
				writeAdmissionPinnedFile(t, p.noncePaths["v2"], bytes.Repeat([]byte{0x55}, 32))
			case "manifest":
				p.db.record.Manifest.Chunks[0].CipherHash = strings.Repeat("b", 64)
			case "locator":
				p.db.record.Ref.RelativeKey = "different-object"
			case "expiry":
				p.db.now = target.ValidUntil()
			case "config-active":
				p.db.activeConfig++
			case "config-cell":
				p.db.configCells["enabled"] = true
			case "wrong-actor":
				actor.Session = strings.Repeat("b", 64)
			case "wrong-proof":
				proof.Payload.RequestHash = strings.Repeat("b", 64)
			case "future-issued-at":
				issuedAt = p.db.now.Add(time.Microsecond)
			case "wrong-transaction":
				tx = nil
			}
			var err error
			if validateFirst {
				err = target.Recheck(context.Background(), tx, actor)
			} else {
				err = target.ValidateProof(context.Background(), tx, actor, proof, issuedAt)
			}
			if err == nil {
				t.Fatal("changed source accepted")
			}
			if p.db.commitAttempts != 0 || p.db.reserved != 0 || p.owners.locks != 0 || p.db.opKeyLocked || len(p.db.nonce) != 0 || len(p.db.m.op) != 0 || len(p.db.body) != 0 {
				t.Fatal("failed MFA target changed admission")
			}
		})
	}
}
