package systembackupsecurity

import (
	"context"
	"database/sql"
	"strconv"
	"time"
)

// VerifyConfigMutationAndIssue authenticates a fresh TOTP step and binds it to
// the strict effective request, installation and authenticated actor. A proof
// is not a write grant: the mutation service independently authorizes the
// current/proposed resources and consumes its nonce in the write transaction.
func (s SQLTOTPService) VerifyConfigMutationAndIssue(ctx context.Context, actor RegistrationActor, password, code string, request ConfigMutationRequest, idempotencyKey string) (Proof, error) {
	if ctx == nil || ctx.Err() != nil || s.DatabaseIdentity == nil || !s.DatabaseIdentity.valid() || !configMutationInstallation.MatchString(s.InstallationID) {
		return Proof{}, ErrRegistrationUnavailable
	}
	if actor.UserID < 1 || !validIdempotencyKey(idempotencyKey) {
		return Proof{}, ErrConfigMutation
	}
	// Re-decode the immutable business input; never sign a submitted digest,
	// installation, actor, session or caller-supplied MFA assertion.
	decoded, err := DecodeConfigMutationRequest(request.Endpoint(), request.CanonicalJSON())
	if err != nil {
		return Proof{}, err
	}
	digest, err := decoded.RequestHash(s.InstallationID, "admin", strconv.FormatInt(actor.UserID, 10))
	if err != nil {
		return Proof{}, err
	}
	binding := RequestBinding{Endpoint: decoded.Endpoint(), RequestHash: digest, IdempotencyKey: idempotencyKey}
	return s.verifyAndIssue(ctx, actor, password, code, &binding, true)
}

func (s SQLTOTPService) checkConfigProofSession(ctx context.Context, tx *sql.Tx, actor RegistrationActor, notBefore time.Time) error {
	if s.DatabaseIdentity == nil {
		return ErrRegistrationUnavailable
	}
	sessions := SQLLoginSessions{db: s.DB, identity: *s.DatabaseIdentity, installation: s.InstallationID}
	return sessions.CheckConfigMutationSession(ctx, tx, s.InstallationID, actor, notBefore)
}

func (s SQLTOTPService) finalConfigProofCheck(ctx context.Context, tx *sql.Tx, actor RegistrationActor, issuedAt time.Time) error {
	_, err := s.finalConfigProofClock(ctx, tx, actor, issuedAt)
	return err
}

func (s SQLTOTPService) finalConfigProofClock(ctx context.Context, tx *sql.Tx, actor RegistrationActor, issuedAt time.Time) (totpProofClock, error) {
	if err := s.Authorize(ctx, tx, actor); err != nil {
		return totpProofClock{}, registrationBoundaryError(err)
	}
	if err := s.checkConfigProofSession(ctx, tx, actor, issuedAt); err != nil {
		return totpProofClock{}, err
	}
	// The signer or final callbacks may have taken time. Observe fresh database
	// UTC after them; no callback follows this temporal check before commit.
	started := time.Now()
	now, err := configMutationClock(ctx, tx)
	if err != nil || now.Before(issuedAt) || !configMutationSessionAt(actor, now) || !now.Before(issuedAt.Add(s.Issuer.Lifetime)) || now.Before(s.Issuer.Key.NotBefore) || !now.Before(s.Issuer.Key.NotAfter) {
		return totpProofClock{}, ErrRegistrationUnavailable
	}
	return totpProofClock{now: now, started: started}, nil
}
