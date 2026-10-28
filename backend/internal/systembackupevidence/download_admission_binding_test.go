package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupsecurity"
)

func downloadBindingFixture(t *testing.T, maxAge ...time.Duration) (*downloadAuditDB, *sql.Tx, DownloadIntentAuditAnchor, DownloadAdmissionContentFacts) {
	t.Helper()
	d, _, tx, intent := downloadAuditFixture(t)
	m, h := sensitiveDownloadManifestFixture(t)
	h.Set("Range", "bytes=1-9")
	a := sensitiveDownloadActor()
	a.SessionIssuedAt, a.SessionExpiresAt = d.now.Add(-time.Hour), d.now.Add(90*time.Second)
	r, err := BindSensitiveDownloadRequest(a, m, h)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.ProofBinding("issuer-binding")
	if err != nil {
		t.Fatal(err)
	}
	proof := systembackupsecurity.Proof{SchemaVersion: systembackupsecurity.ProofSchemaVersion, Payload: systembackupsecurity.ProofPayload{
		Issuer: b.Issuer, Audience: b.Audience, Subject: b.Subject, Session: b.Session, Endpoint: b.Endpoint, RequestHash: b.RequestHash, IdempotencyKey: b.IdempotencyKey,
		AuthTime: d.now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: d.now.Add(60*time.Second + 789*time.Nanosecond).Format(time.RFC3339Nano), Method: "totp", AMR: []string{"pwd", "otp"}, Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)),
	}}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	verifier := systembackupsecurity.Ed25519JWSVerifier{PublicKey: key.Public().(ed25519.PublicKey), KeyID: "key-binding", KeyVersion: "v1", Purpose: "strong_auth_issuer"}
	protected := `{"alg":"EdDSA","key_version":"v1","kid":"key-binding","purpose":"strong_auth_issuer","typ":"` + systembackupsecurity.DomainSeparator + `"}`
	proof.Signature = systembackupsecurity.ProofSignature{Format: "jws", Algorithm: "EdDSA", KeyID: verifier.KeyID, KeyVersion: verifier.KeyVersion, DomainSeparator: systembackupsecurity.DomainSeparator, ProtectedHeader: base64.RawURLEncoding.EncodeToString([]byte(protected))}
	payload, err := systembackupsecurity.CanonicalPayload(proof.Payload)
	if err != nil {
		t.Fatal(err)
	}
	proof.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(proof.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
	cfg := systembackupsecurity.VerifyConfig{Now: d.now, MaxAge: 5 * time.Minute, ExpectedAudience: b.Audience, ExpectedSubject: b.Subject, ExpectedSession: b.Session,
		TrustedSigners: map[string]map[string]systembackupsecurity.SignatureVerifier{b.Issuer: {"v1": verifier}}, TrustedIssuerPolicies: map[string]systembackupsecurity.IssuerPolicy{b.Issuer: {Methods: []string{"totp"}, AMR: []string{"pwd", "otp"}}},
		NonceHMACKeys: map[string][]byte{"v1": bytes.Repeat([]byte{0x11}, 32), "v2": bytes.Repeat([]byte{0x22}, 32)}, RequiredNonceHMACKeyVersions: []string{"v1", "v2"}, ActiveNonceHMACKeyVersion: "v2"}
	if len(maxAge) > 0 {
		cfg.MaxAge = maxAge[0]
	}
	v, err := r.VerifyProof(proof, b.Issuer, cfg)
	if err != nil {
		t.Fatal(err)
	}
	intent.Installation, intent.EvidenceID = m.Identity.Installation, m.Identity.ID
	intent.ManifestSHA256, intent.RequestHash = r.ManifestSHA256(), r.RequestHash()
	audit, err := (SQLDownloadAdmissionAudits{}).StageIntent(context.Background(), tx, intent)
	if err != nil {
		t.Fatal(err)
	}
	f := DownloadAdmissionContentFacts{Actor: a, Intent: intent, Proof: v, AuthorityUntil: d.now.Add(40 * time.Second),
		Record: Record{Manifest: m, State: "ready", Failure: "none", RowVersion: intent.EvidenceRowVersion, Claim: intent.Claim, ClaimUntil: d.now.Add(30 * time.Second)}}
	return d, tx, audit, f
}

func TestDownloadAdmissionBindingOriginalTransactionAndProjection(t *testing.T) {
	d, tx, a, f := downloadBindingFixture(t)
	b, err := BindDownloadAdmissionContent(context.Background(), tx, a, f)
	if err != nil || b == nil {
		t.Fatal(err)
	}
	r, err := DecodeCanonicalDownloadAdmissionReceipt(b.ReceiptJSON())
	if err != nil || r.IntentAuditID != d.id || r.EvidenceRowVersion != f.Record.RowVersion || r.ClaimSHA256 != hash([]byte(f.Record.Claim)) || r.SubjectSHA256 != hash([]byte(f.Actor.Subject)) || r.SessionSHA256 != hash([]byte(f.Actor.Session)) {
		t.Fatal("independent bindings", err)
	}
	if !b.DeadlineAt().Equal(f.Record.ClaimUntil) || !r.AdmittedAt.Equal(d.now) {
		t.Fatal("original deadline/time")
	}
	for _, raw := range [][]byte{b.ReceiptJSON(), b.OperationJSON()} {
		if bytes.Contains(raw, []byte(f.Record.Claim)) || bytes.Contains(raw, []byte(f.Actor.Session)) {
			t.Fatal("transient data serialized")
		}
	}
	for _, v := range []any{f, b} {
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("whole capability serialized")
		}
	}
	if fmt.Sprintf("%v %#v", b, b) != "DownloadAdmissionContentBinding DownloadAdmissionContentBinding" {
		t.Fatal("capability formatted")
	}
	private, public := b.ReceiptJSON(), b.OperationJSON()
	private[0] = '!'
	public[0] = '!'
	if b.ReceiptJSON()[0] != '{' || b.OperationJSON()[0] != '{' {
		t.Fatal("mutable content alias")
	}
	d.now = d.now.Add(time.Second)
	if err := b.Recheck(context.Background(), tx, f.Actor, f.Record); err != nil {
		t.Fatal(err)
	}
	if d.inserts != 1 || d.begins != 1 || d.commits != 0 || d.rollbacks != 0 {
		t.Fatal("binding wrote or owned transaction")
	}
}

func TestDownloadAdmissionBindingRejectsSubstitution(t *testing.T) {
	for name, change := range map[string]func(*DownloadAdmissionContentFacts){
		"zero_proof": func(f *DownloadAdmissionContentFacts) {
			f.Proof = systembackupsecurity.SensitiveDownloadProofVerification{}
		},
		"subject":         func(f *DownloadAdmissionContentFacts) { f.Actor.Subject = "user:43" },
		"session":         func(f *DownloadAdmissionContentFacts) { f.Actor.Session = strings.Repeat("b", 64) },
		"future_session":  func(f *DownloadAdmissionContentFacts) { f.Actor.SessionIssuedAt = f.Record.ClaimUntil },
		"expired_session": func(f *DownloadAdmissionContentFacts) { f.Actor.SessionExpiresAt = f.Actor.SessionIssuedAt },
		"manifest":        func(f *DownloadAdmissionContentFacts) { f.Record.Manifest.ObjectHash = strings.Repeat("f", 64) },
		"classification":  func(f *DownloadAdmissionContentFacts) { f.Record.Manifest.Identity.Classification = "internal" },
		"row_version":     func(f *DownloadAdmissionContentFacts) { f.Record.RowVersion++ },
		"claim":           func(f *DownloadAdmissionContentFacts) { f.Record.Claim = "aev_" + strings.Repeat("e", 32) },
		"state":           func(f *DownloadAdmissionContentFacts) { f.Record.State = "deleted" },
		"failure":         func(f *DownloadAdmissionContentFacts) { f.Record.Failure = "internal_error" },
		"installation":    func(f *DownloadAdmissionContentFacts) { f.Intent.Installation = "installation_other" },
		"operation": func(f *DownloadAdmissionContentFacts) {
			f.Intent.OperationID = "sop_99999999-1111-4111-8111-111111111111"
		},
		"audit_request":     func(f *DownloadAdmissionContentFacts) { f.Intent.RequestHash = strings.Repeat("e", 64) },
		"range":             func(f *DownloadAdmissionContentFacts) { f.Intent.Start++ },
		"authority_missing": func(f *DownloadAdmissionContentFacts) { f.AuthorityUntil = time.Time{} },
		"authority_expired": func(f *DownloadAdmissionContentFacts) { f.AuthorityUntil = f.Actor.SessionIssuedAt },
	} {
		t.Run(name, func(t *testing.T) {
			_, tx, a, f := downloadBindingFixture(t)
			change(&f)
			if name == "manifest" && f.Record.Manifest.ObjectHash == strings.Repeat("e", 64) {
				t.Fatal("manifest counterexample did not change the original hash")
			}
			if b, err := BindDownloadAdmissionContent(context.Background(), tx, a, f); err == nil || b != nil {
				t.Fatal("substitution yielded binding")
			}
		})
	}
	t.Run("cross_transaction", func(t *testing.T) {
		_, _, a, f := downloadBindingFixture(t)
		_, other, _, _ := downloadBindingFixture(t)
		if b, err := BindDownloadAdmissionContent(context.Background(), other, a, f); err == nil || b != nil {
			t.Fatal("cross transaction")
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		_, tx, a, f := downloadBindingFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if b, err := BindDownloadAdmissionContent(ctx, tx, a, f); err == nil || b != nil {
			t.Fatal("cancelled")
		}
	})
}

func TestDownloadAdmissionBindingFrozenLimitsAndFinalClock(t *testing.T) {
	t.Run("maximum_auth_age", func(t *testing.T) {
		d, tx, a, f := downloadBindingFixture(t, 70*time.Second)
		b, err := BindDownloadAdmissionContent(context.Background(), tx, a, f)
		if err != nil || !b.DeadlineAt().Equal(d.now.Add(10*time.Second)) {
			t.Fatal("auth-age deadline lost", err)
		}
		d.now = b.DeadlineAt()
		if b.Recheck(context.Background(), tx, f.Actor, f.Record) == nil {
			t.Fatal("max-age limit extended")
		}
	})
	t.Run("zero_verification_deadline", func(t *testing.T) {
		var v systembackupsecurity.SensitiveDownloadProofVerification
		if until, err := v.AdmissionDeadlineAt(); err == nil || !until.IsZero() {
			t.Fatal("zero verification has a deadline")
		}
	})
	for _, name := range []string{"claim", "authority", "session", "proof_floor"} {
		t.Run(name, func(t *testing.T) {
			d, tx, a, f := downloadBindingFixture(t)
			want := f.Record.ClaimUntil
			switch name {
			case "authority":
				f.AuthorityUntil = d.now.Add(10 * time.Second)
				want = f.AuthorityUntil
			case "session":
				f.Actor.SessionExpiresAt = d.now.Add(15 * time.Second)
				want = f.Actor.SessionExpiresAt
			case "proof_floor":
				f.AuthorityUntil = d.now.Add(90 * time.Second)
				f.Record.ClaimUntil = f.AuthorityUntil
				want = f.Proof.ProofExpiresAt().Truncate(time.Microsecond)
			}
			b, err := BindDownloadAdmissionContent(context.Background(), tx, a, f)
			if err != nil || !b.DeadlineAt().Equal(want) {
				t.Fatal("minimum original deadline", err)
			}
			if b.DeadlineAt().After(f.Proof.ProofExpiresAt()) {
				t.Fatal("proof rounded up")
			}
			d.now = want
			if b.Recheck(context.Background(), tx, f.Actor, f.Record) == nil {
				t.Fatal("expired binding")
			}
		})
	}
	t.Run("clock_after_audit_read", func(t *testing.T) {
		d, tx, a, f := downloadBindingFixture(t)
		d.mutate = func(d *downloadAuditDB) { d.now = f.Record.ClaimUntil }
		if b, err := BindDownloadAdmissionContent(context.Background(), tx, a, f); err == nil || b != nil {
			t.Fatal("stale pre-read clock")
		}
	})
	t.Run("regressed_clock", func(t *testing.T) {
		d, tx, a, f := downloadBindingFixture(t)
		b, err := BindDownloadAdmissionContent(context.Background(), tx, a, f)
		if err != nil {
			t.Fatal(err)
		}
		d.now = d.now.Add(5 * time.Second)
		if b.Recheck(context.Background(), tx, f.Actor, f.Record) != nil {
			t.Fatal("valid first recheck")
		}
		d.now = d.now.Add(-time.Second)
		if b.Recheck(context.Background(), tx, f.Actor, f.Record) == nil {
			t.Fatal("clock regressed")
		}
		d.now = d.now.Add(2 * time.Second)
		if b.Recheck(context.Background(), tx, f.Actor, f.Record) == nil {
			t.Fatal("failed binding revived")
		}
	})
	t.Run("non_UTC", func(t *testing.T) {
		d, tx, a, f := downloadBindingFixture(t)
		d.fail = "non_utc"
		if b, err := BindDownloadAdmissionContent(context.Background(), tx, a, f); err == nil || b != nil {
			t.Fatal("non UTC")
		}
	})
}

func TestDownloadAdmissionBindingRechecksOriginalFacts(t *testing.T) {
	for _, name := range []string{"actor", "session_deadline", "claim", "claim_deadline", "manifest", "row_version", "audit_body", "audit_id", "audit_action", "read_failure", "post_read_expiry", "post_read_clock_regression", "cross_transaction", "committed_transaction"} {
		t.Run(name, func(t *testing.T) {
			d, tx, a, f := downloadBindingFixture(t)
			b, err := BindDownloadAdmissionContent(context.Background(), tx, a, f)
			if err != nil {
				t.Fatal(err)
			}
			actor, current := f.Actor, f.Record
			candidateTX := tx
			switch name {
			case "actor":
				actor.UserID++
			case "session_deadline":
				actor.SessionExpiresAt = actor.SessionExpiresAt.Add(time.Second)
			case "claim":
				current.Claim = "aev_" + strings.Repeat("e", 32)
			case "claim_deadline":
				current.ClaimUntil = current.ClaimUntil.Add(time.Second)
			case "manifest":
				current.Manifest.ObjectHash = strings.Repeat("f", 64)
			case "row_version":
				current.RowVersion++
			case "audit_body":
				d.body = bytes.Replace(d.body, []byte(f.Intent.RequestHash), []byte(strings.Repeat("e", 64)), 1)
			case "audit_id":
				b.audit.id++
			case "audit_action":
				d.action = "system_backup.other.intent"
			case "read_failure":
				d.fail = "read"
			case "post_read_expiry":
				d.mutate = func(d *downloadAuditDB) { d.now = f.Record.ClaimUntil }
			case "post_read_clock_regression":
				d.mutate = func(d *downloadAuditDB) { d.now = d.now.Add(-time.Microsecond) }
			case "cross_transaction":
				_, candidateTX, _, _ = downloadBindingFixture(t)
			case "committed_transaction":
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			if b.Recheck(context.Background(), candidateTX, actor, current) == nil {
				t.Fatal("changed original facts accepted")
			}
			if b.Recheck(context.Background(), tx, f.Actor, f.Record) == nil {
				t.Fatal("failed binding reused")
			}
		})
	}
}
