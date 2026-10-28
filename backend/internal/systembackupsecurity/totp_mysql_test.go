//go:build systembackup_mysql

package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"golang.org/x/crypto/bcrypt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type testProofSigner struct{ key ed25519.PrivateKey }

func (s testProofSigner) Sign(_ context.Context, b []byte) ([]byte, error) {
	return ed25519.Sign(s.key, b), nil
}

func testTOTPMySQL(t *testing.T, db *sql.DB, ctx context.Context) {
	_, err := db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN password_hash VARCHAR(255) NOT NULL DEFAULT ''")
	mysqlMust(t, err)
	password := "isolated-test-password-only"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO users(id,role,is_active,password_hash) VALUES (43,'admin',TRUE,?)", string(hash))
	mysqlMust(t, err)
	var now time.Time
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	box, err := NewTOTPSecretBox(bytes.Repeat([]byte{5}, 32))
	mysqlMust(t, err)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	mysqlMust(t, err)
	service := SQLTOTPService{DB: db, InstallationID: "installation_d_totp_probe", Box: box, Issuer: StrongAuthProofIssuer{Key: StrongAuthRegistryKey{Issuer: "test-strong-auth", KeyID: "test-strong-auth-key", KeyVersion: "1", Purpose: "strong_auth_issuer", PublicKey: pub, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, Audience: "test-audience", Signer: testProofSigner{key}, Lifetime: time.Minute}}
	service.Authorize = func(_ context.Context, _ *sql.Tx, a RegistrationActor) error {
		if a.UserID != 43 || a.Subject != "user:43" {
			return ErrRegistrationPermission
		}
		return nil
	} // Explicit isolated-test grant.
	actor := RegistrationActor{UserID: 43, Subject: "user:43", Session: strings.Repeat("a", 64), SessionExpiresAt: now.Add(time.Hour), SessionIssuedAt: now.Add(-time.Minute)}
	uri, err := service.BeginEnrollment(ctx, actor, password)
	mysqlMust(t, err)
	parsed, err := url.Parse(uri)
	mysqlMust(t, err)
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(parsed.Query().Get("secret"))
	mysqlMust(t, err)
	defer wipeSecret(seed)
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	// Adjacent past step permits enrollment and a distinct current code without
	// sleeping; both are explicitly synthetic RFC algorithm inputs.
	_, err = service.VerifyAndIssue(ctx, actor, password, totpCode(seed, now.Unix()/30-1, 6), nil)
	mysqlMust(t, err)
	request, _, _ := providerSignedFixture(t)
	code := totpCode(seed, now.Unix()/30, 6)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, e := service.VerifyAndIssue(ctx, actor, password, code, &request)
			if e == nil && p.Payload.Subject != "user:43" {
				e = ErrTOTPRejected
			}
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("TOTP code did not have one atomic issuance", successes)
	}
	for i := 0; i < 5; i++ {
		_, err = service.VerifyAndIssue(ctx, actor, "incorrect password", code, &request)
		if err == nil {
			t.Fatal("wrong password accepted")
		}
	}
	_, err = service.VerifyAndIssue(ctx, actor, password, code, &request)
	if err != ErrTOTPRateLimited {
		t.Fatal("persisted throttle missing")
	}
	mysqlMust(t, service.RevokeUserSessions(ctx, 43))
	tx, err := db.BeginTx(ctx, nil)
	mysqlMust(t, err)
	if CheckRegistrationSession(ctx, tx, service.InstallationID, actor) == nil {
		tx.Rollback()
		t.Fatal("revoked session accepted")
	}
	tx.Rollback()
	var seedStored []byte
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT encrypted_seed FROM system_backup_v2_totp_credentials WHERE user_id=43").Scan(&seedStored))
	if bytes.Contains(seedStored, seed) {
		t.Fatal("seed stored in plaintext")
	}
}
