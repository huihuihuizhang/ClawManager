package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// Advance the model's database clock during real boundary callbacks, without
// sleeps. The callbacks still return valid material for the time they received.
// A commit guard must use time AFTER those callbacks have returned.
type mutationAContractAuthority struct {
	ConfigMutationAuthority
	s              *mutationTestState
	afterAuthorize func()
	afterStrong    func(*VerifyConfig)
	strongCalls    int
}

func (a *mutationAContractAuthority) Authorize(ctx context.Context, tx *sql.Tx, actor RegistrationActor, installation string, old, proposed ConfigValues, risk ConfigMutationRisk, now time.Time) error {
	err := a.ConfigMutationAuthority.Authorize(ctx, tx, actor, installation, old, proposed, risk, now)
	if err == nil && a.afterAuthorize != nil {
		a.afterAuthorize()
	}
	return err
}

func (a *mutationAContractAuthority) StrongAuth(ctx context.Context, tx *sql.Tx, actor RegistrationActor, installation string, values ConfigValues, versions []string, now time.Time) (VerifyConfig, error) {
	sc, err := a.ConfigMutationAuthority.StrongAuth(ctx, tx, actor, installation, values, versions, now)
	a.strongCalls++
	if err == nil && a.strongCalls == 2 && a.afterStrong != nil {
		a.afterStrong(&sc)
	}
	return sc, err
}

func mutationARequireRollback(t *testing.T, s *mutationTestState, result ConfigMutationResult, err error) {
	t.Helper()
	if err == nil || result.HTTPStatus != 0 || s.activeTx || s.data.active != 1 || len(s.data.rows) != 1 || s.data.receipt != nil || len(s.data.writes) != 0 {
		t.Fatalf("rejected final facts committed configuration/nonce/audit: err=%v status=%d rows=%d writes=%v", err, result.HTTPStatus, len(s.data.rows), s.data.writes)
	}
}

func TestConfigMutationACommitClockAfterFinalBoundaries(t *testing.T) {
	for _, name := range []string{"operation-deadline", "session-expiry", "still-valid"} {
		t.Run(name, func(t *testing.T) {
			svc, actor, raw, state, _ := mutationTransactionFixture(t)
			deadline := state.now.Add(time.Duration(state.data.rows[1].snapshot.numbers["operation_deadline_seconds"]) * time.Second)
			actor.SessionExpiresAt = deadline.Add(time.Hour)
			if name == "session-expiry" {
				actor.SessionExpiresAt = state.now.Add(time.Minute)
			}
			authority := &mutationAContractAuthority{ConfigMutationAuthority: svc.Authority, s: state}
			authority.afterAuthorize = func() {
				if len(state.working.writes) == 0 {
					return
				}
				switch name {
				case "operation-deadline":
					state.now = deadline
				case "session-expiry":
					state.now = actor.SessionExpiresAt
				case "still-valid":
					state.now = deadline.Add(-time.Microsecond)
				}
			}
			svc.Authority = authority
			result, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "a-clock", raw, nil)
			if name == "still-valid" {
				if err != nil || result.Version != 2 || state.data.active != 2 {
					t.Fatal("valid delayed operation rejected", err)
				}
				return
			}
			mutationARequireRollback(t, state, result, err)
			if name == "operation-deadline" && err != ErrRegistrationUnavailable || name == "session-expiry" && err != ErrRegistrationPermission {
				t.Fatal("incorrect final failure category", err)
			}
		})
	}
}

func TestConfigMutationAStrongAuthFinalFacts(t *testing.T) {
	for _, name := range []string{"proof-expiry", "mfa-age", "active-nonce-key-drift", "historical-nonce-key-drift", "still-valid"} {
		t.Run(name, func(t *testing.T) {
			svc, actor, raw, state, sc := mutationTransactionFixture(t)
			raw = bytes.Replace(raw, []byte(`"retention_seconds":2592000`), []byte(`"retention_seconds":86400`), 1)
			raw = bytes.Replace(raw, []byte(`"change_reason":null`), []byte(`"change_reason":"A final-boundary fixture"`), 1)
			r, err := DecodeConfigMutationRequest(ConfigUpdateEndpoint, raw)
			if err != nil {
				t.Fatal(err)
			}
			proof := mutationTransactionProof(t, r, actor, state.now, &sc)
			// Make proof expiry later than the MFA-age boundary in the age case.
			if name == "mfa-age" {
				proof.Payload.ExpiresAt = state.now.Add(20 * time.Minute).Format(time.RFC3339Nano)
				payload, err := CanonicalPayload(proof.Payload)
				if err != nil {
					t.Fatal(err)
				}
				signer := ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", 32)))
				proof.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, []byte(proof.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
			}
			authAt, expiresAt, err := parseTimes(proof.Payload)
			if err != nil {
				t.Fatal(err)
			}
			authority := &mutationAContractAuthority{ConfigMutationAuthority: mutationTestAuthority{state, sc}, s: state}
			authority.afterStrong = func(cfg *VerifyConfig) {
				switch name {
				case "proof-expiry":
					state.now = expiresAt
				case "mfa-age":
					c := state.data.rows[1].snapshot.numbers
					state.now = authAt.Add(time.Duration(c["strong_auth_max_age_seconds"]+c["strong_auth_clock_skew_seconds"])*time.Second + time.Microsecond)
				case "active-nonce-key-drift", "historical-nonce-key-drift":
					keys := make(map[string][]byte, len(cfg.NonceHMACKeys))
					for version, material := range cfg.NonceHMACKeys {
						keys[version] = append([]byte(nil), material...)
					}
					version := cfg.ActiveNonceHMACKeyVersion
					if name == "historical-nonce-key-drift" {
						version = "old"
					}
					keys[version] = bytes.Repeat([]byte{0x55}, 32)
					cfg.NonceHMACKeys = keys
				case "still-valid":
					state.now = expiresAt.Add(-time.Microsecond)
				}
			}
			svc.Authority = authority
			result, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "a-proof", raw, &proof)
			if name == "still-valid" {
				if err != nil || result.Version != 2 || state.data.active != 2 || authority.strongCalls != 2 {
					t.Fatal("valid delayed proof rejected", err)
				}
				return
			}
			mutationARequireRollback(t, state, result, err)
			if name == "proof-expiry" || name == "mfa-age" {
				var failure *VerificationError
				if !errors.As(err, &failure) || failure.Code != FailureExpired {
					t.Fatal("expiry did not use existing strong-auth category", err)
				}
			}
		})
	}
}

func TestConfigMutationAReplaySessionExpiresDuringFinalAuthority(t *testing.T) {
	svc, actor, raw, state, _ := mutationTransactionFixture(t)
	result, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "a-original", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	writes := len(state.data.writes)
	afterRead := 0
	authority := &mutationAContractAuthority{ConfigMutationAuthority: svc.Authority, s: state}
	authority.afterAuthorize = func() {
		if state.reads > 0 {
			afterRead++
			if afterRead == 2 {
				state.now = actor.SessionExpiresAt
			}
		}
	}
	svc.Authority = authority
	replayed, err := svc.ObserveCommitted(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "a-replay", raw)
	if err != ErrRegistrationPermission || replayed.HTTPStatus != 0 || len(state.data.writes) != writes || state.data.active != result.Version || state.activeTx {
		t.Fatal("expired replay returned response or changed committed operation", err, replayed.HTTPStatus, state.data.writes)
	}
}

func TestConfigMutationARollbackRequiresFreshProof(t *testing.T) {
	for _, name := range []string{"missing", "expires-during-final-load"} {
		t.Run(name, func(t *testing.T) {
			svc, actor, _, state, sc := mutationTransactionFixture(t)
			current := state.data.rows[1]
			previous, err := DecodeConfigValues(bytes.Replace(current.CanonicalJSON(), []byte(`"retention_seconds":2592000`), []byte(`"retention_seconds":86400`), 1))
			if err != nil {
				t.Fatal(err)
			}
			state.data.rows[1], state.data.rows[2] = previous, current
			state.data.active, state.data.stateVersion = 2, 2
			raw := []byte(`{"expected_version":2,"rollback_from_version":1,"change_reason":"A rollback fixture"}`)
			r, err := DecodeConfigMutationRequest(ConfigRollbackEndpoint, raw)
			if err != nil {
				t.Fatal(err)
			}
			var proof *Proof
			if name != "missing" {
				p := mutationTransactionProof(t, r, actor, state.now, &sc)
				proof = &p
			}
			authority := &mutationAContractAuthority{ConfigMutationAuthority: mutationTestAuthority{state, sc}, s: state}
			authority.afterStrong = func(*VerifyConfig) {
				_, expiresAt, err := parseTimes(proof.Payload)
				if err != nil {
					t.Fatal(err)
				}
				state.now = expiresAt
			}
			svc.Authority = authority
			result, err := svc.Mutate(context.Background(), actor, ConfigRollbackEndpoint, "mutation_key_0123456789", "a-rollback", raw, proof)
			if err == nil || result.HTTPStatus != 0 || state.activeTx || state.data.active != 2 || len(state.data.rows) != 2 || state.data.receipt != nil || len(state.data.writes) != 0 || state.data.rows[1].SHA256() != previous.SHA256() || state.data.rows[2].SHA256() != current.SHA256() {
				t.Fatal("rollback bypassed fresh auth or rewrote history", err, result.HTTPStatus, state.data.writes)
			}
			if name != "missing" {
				var failure *VerificationError
				if !errors.As(err, &failure) || failure.Code != FailureExpired {
					t.Fatal("rollback expiry category", err)
				}
			}
		})
	}
}

func TestConfigMutationANonceBindingAllowsNewVersion(t *testing.T) {
	consumed := VerificationResult{NonceHMAC: strings.Repeat("a", 64), NonceHMACKeyVersion: "current", NonceHMACCandidates: []NonceHMACCandidate{{KeyVersion: "current", HMAC: strings.Repeat("a", 64)}, {KeyVersion: "historical", HMAC: strings.Repeat("b", 64)}}}
	final := consumed
	final.NonceHMACCandidates = append(append([]NonceHMACCandidate(nil), consumed.NonceHMACCandidates...), NonceHMACCandidate{KeyVersion: "new-config-version", HMAC: strings.Repeat("c", 64)})
	if !configMutationNonceBindingStable(consumed, final) {
		t.Fatal("new config legitimately adds a version to the global retained-key union")
	}
}
