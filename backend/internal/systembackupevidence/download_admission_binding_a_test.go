package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"testing"
	"time"

	"clawreef/internal/systembackupsecurity"
)

// These cases deliberately fail after a binding has been constructed. Restoring
// the input or SQL transport must not make that failed capability usable again.
func TestADownloadBindingAbortIsPermanent(t *testing.T) {
	for _, name := range []string{"nil_context", "cancelled_context", "cancel_during_audit", "nil_transaction", "rolled_back_transaction", "clock_failure", "clock_offset", "missing_audit", "session_issued_changed", "session_expired", "proof_expired", "authority_expired"} {
		t.Run(name, func(t *testing.T) {
			d, tx, anchor, facts := downloadBindingFixture(t)
			if name == "session_expired" {
				facts.Actor.SessionExpiresAt = d.now.Add(time.Second)
			}
			if name == "proof_expired" {
				facts.Record.ClaimUntil = d.now.Add(80 * time.Second)
				facts.AuthorityUntil = facts.Record.ClaimUntil
			}
			if name == "authority_expired" {
				facts.AuthorityUntil = d.now.Add(time.Second)
			}
			binding, err := BindDownloadAdmissionContent(context.Background(), tx, anchor, facts)
			if err != nil {
				t.Fatal("positive binding control", err)
			}
			originalNow := d.now
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checkTX, actor := tx, facts.Actor
			switch name {
			case "nil_context":
				ctx = nil
			case "cancelled_context":
				cancel()
			case "cancel_during_audit":
				d.mutate = func(*downloadAuditDB) { cancel() }
			case "nil_transaction":
				checkTX = nil
			case "rolled_back_transaction":
				if err := tx.Rollback(); err != nil {
					t.Fatal(err)
				}
			case "clock_failure":
				d.fail = "clock"
			case "clock_offset":
				d.fail = "non_utc"
			case "missing_audit":
				d.fail = "missing"
			case "session_issued_changed":
				actor.SessionIssuedAt = actor.SessionIssuedAt.Add(time.Microsecond)
			case "session_expired":
				d.now = actor.SessionExpiresAt
			case "proof_expired":
				d.now = facts.Proof.ProofExpiresAt().Add(time.Microsecond)
			case "authority_expired":
				d.now = facts.AuthorityUntil
			}
			if err := binding.Recheck(ctx, checkTX, actor, facts.Record); err == nil {
				t.Fatal("invalid final state accepted")
			}
			d.now, d.fail, d.mutate = originalNow, "", nil
			if err := binding.Recheck(context.Background(), tx, facts.Actor, facts.Record); err == nil {
				t.Fatal("failed capability revived after restoring facts")
			}
			if d.inserts != 1 || d.begins != 1 || d.commits != 0 {
				t.Fatal("helper added writes or owned transaction")
			}
		})
	}
}

// A separate signed log request exercises retention independently of the
// ordinary evidence fixture. SQL is scripted; this is not a lock/FK test.
func aDownloadLogBindingFixture(t *testing.T) (*downloadAuditDB, *sql.Tx, DownloadIntentAuditAnchor, DownloadAdmissionContentFacts) {
	t.Helper()
	d, _, tx, intent := downloadAuditFixture(t)
	m, headers := sensitiveDownloadManifestFixture(t)
	m.Identity.Type = "job_log_chunk"
	headers.Set("Range", "bytes=1-9")
	actor := sensitiveDownloadActor()
	actor.SessionIssuedAt, actor.SessionExpiresAt = d.now.Add(-time.Hour), d.now.Add(time.Minute)
	request, err := BindSensitiveDownloadRequest(actor, m, headers)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := request.ProofBinding("issuer-a-log")
	if err != nil {
		t.Fatal(err)
	}
	proof := systembackupsecurity.Proof{SchemaVersion: systembackupsecurity.ProofSchemaVersion,
		Payload: systembackupsecurity.ProofPayload{Issuer: binding.Issuer, Audience: binding.Audience, Subject: binding.Subject, Session: binding.Session,
			Endpoint: binding.Endpoint, RequestHash: binding.RequestHash, IdempotencyKey: binding.IdempotencyKey,
			AuthTime: d.now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: d.now.Add(time.Minute).Format(time.RFC3339Nano),
			Method: "totp", AMR: []string{"pwd", "otp"}, Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	verifier := systembackupsecurity.Ed25519JWSVerifier{PublicKey: key.Public().(ed25519.PublicKey), KeyID: "key-a-log", KeyVersion: "v1", Purpose: "strong_auth_issuer"}
	header := `{"alg":"EdDSA","key_version":"v1","kid":"key-a-log","purpose":"strong_auth_issuer","typ":"` + systembackupsecurity.DomainSeparator + `"}`
	proof.Signature = systembackupsecurity.ProofSignature{Format: "jws", Algorithm: "EdDSA", KeyID: verifier.KeyID, KeyVersion: verifier.KeyVersion,
		DomainSeparator: systembackupsecurity.DomainSeparator, ProtectedHeader: base64.RawURLEncoding.EncodeToString([]byte(header))}
	payload, err := systembackupsecurity.CanonicalPayload(proof.Payload)
	if err != nil {
		t.Fatal(err)
	}
	proof.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(proof.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
	verified, err := request.VerifyProof(proof, binding.Issuer, systembackupsecurity.VerifyConfig{
		Now: d.now, MaxAge: 5 * time.Minute, ExpectedAudience: binding.Audience, ExpectedSubject: binding.Subject, ExpectedSession: binding.Session,
		TrustedSigners:        map[string]map[string]systembackupsecurity.SignatureVerifier{binding.Issuer: {"v1": verifier}},
		TrustedIssuerPolicies: map[string]systembackupsecurity.IssuerPolicy{binding.Issuer: {Methods: []string{"totp"}, AMR: []string{"pwd", "otp"}}},
		NonceHMACKeys:         map[string][]byte{"v1": bytes.Repeat([]byte{5}, 32)}, RequiredNonceHMACKeyVersions: []string{"v1"}, ActiveNonceHMACKeyVersion: "v1",
	})
	if err != nil {
		t.Fatal("positive signature control", err)
	}
	intent.Installation, intent.EvidenceID, intent.ManifestSHA256, intent.RequestHash = m.Identity.Installation, m.Identity.ID, request.ManifestSHA256(), request.RequestHash()
	anchor, err := (SQLDownloadAdmissionAudits{}).StageIntent(context.Background(), tx, intent)
	if err != nil {
		t.Fatal(err)
	}
	return d, tx, anchor, DownloadAdmissionContentFacts{Actor: actor, Intent: intent, Proof: verified, AuthorityUntil: d.now.Add(40 * time.Second),
		Record: Record{Manifest: m, State: "ready", Failure: "none", RowVersion: intent.EvidenceRowVersion, Claim: intent.Claim,
			ClaimUntil: d.now.Add(30 * time.Second), ExpiresAt: d.now.Add(10 * time.Second)}}
}

func TestADownloadBindingLogRetention(t *testing.T) {
	for _, name := range []string{"original_limit", "extended_expiry", "shortened_expiry", "missing_expiry", "expired_at_bind", "submicrosecond_expiry", "non_UTC_expiry"} {
		t.Run(name, func(t *testing.T) {
			d, tx, anchor, facts := aDownloadLogBindingFixture(t)
			originalExpiry := facts.Record.ExpiresAt
			switch name {
			case "missing_expiry":
				facts.Record.ExpiresAt = time.Time{}
			case "expired_at_bind":
				facts.Record.ExpiresAt = d.now
			case "submicrosecond_expiry":
				facts.Record.ExpiresAt = originalExpiry.Add(time.Nanosecond)
			case "non_UTC_expiry":
				facts.Record.ExpiresAt = originalExpiry.In(time.FixedZone("offset", 3600))
			}
			b, err := BindDownloadAdmissionContent(context.Background(), tx, anchor, facts)
			if name == "missing_expiry" || name == "expired_at_bind" || name == "submicrosecond_expiry" || name == "non_UTC_expiry" {
				if err == nil || b != nil {
					t.Fatal("invalid retention yielded binding")
				}
				return
			}
			if err != nil || b == nil || !b.DeadlineAt().Equal(originalExpiry) {
				t.Fatal("original log retention lost", err)
			}
			d.now = d.now.Add(time.Second)
			if b.Recheck(context.Background(), tx, facts.Actor, facts.Record) != nil {
				t.Fatal("valid log binding failed")
			}
			switch name {
			case "extended_expiry":
				facts.Record.ExpiresAt = originalExpiry.Add(time.Minute)
				d.now = originalExpiry
			case "shortened_expiry":
				facts.Record.ExpiresAt = d.now.Add(time.Second)
				d.now = facts.Record.ExpiresAt
			default:
				d.now = originalExpiry
			}
			if b.Recheck(context.Background(), tx, facts.Actor, facts.Record) == nil {
				t.Fatal("log expired but final recheck passed")
			}
		})
	}
}

func TestADownloadBindingSamplesClockAfterAudit(t *testing.T) {
	for _, phase := range []string{"bind", "recheck"} {
		t.Run(phase, func(t *testing.T) {
			d, tx, anchor, facts := downloadBindingFixture(t)
			facts.AuthorityUntil = d.now.Add(time.Second)
			if phase == "bind" {
				d.mutate = func(d *downloadAuditDB) { d.now = facts.AuthorityUntil }
				if b, err := BindDownloadAdmissionContent(context.Background(), tx, anchor, facts); err == nil || b != nil {
					t.Fatal("authority expired during audit read but construction succeeded")
				}
				return
			}
			b, err := BindDownloadAdmissionContent(context.Background(), tx, anchor, facts)
			if err != nil {
				t.Fatal(err)
			}
			d.mutate = func(d *downloadAuditDB) { d.now = facts.AuthorityUntil }
			if b.Recheck(context.Background(), tx, facts.Actor, facts.Record) == nil {
				t.Fatal("authority expired during final audit read but recheck succeeded")
			}
		})
	}
}
