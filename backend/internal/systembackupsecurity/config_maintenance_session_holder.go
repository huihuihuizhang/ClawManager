package systembackupsecurity

import (
	"context"
	"crypto/tls"
	"database/sql"
	"net/http"
	"time"
)

// This private adapter proves possession of an existing application session.
// It is not a grant issuer or a production maintenance endpoint. The logical
// issuer is deployment configuration and must remain stable across JWT-key
// rotation. A deployment must separately review its principal-ID lifecycle.
type configMaintenanceSessionHolder struct {
	sessions          *SQLLoginSessions
	issuer, principal string
	digest            string
	actor             RegistrationActor
	request           context.Context
	bound             context.Context
}

type configMaintenanceHolderContextKey struct{}

func newConfigMaintenanceSessionHolder(sessions *SQLLoginSessions, issuer string, request *http.Request) (*configMaintenanceSessionHolder, error) {
	if sessions == nil || sessions.db == nil || !sessions.identity.valid() || !configMutationInstallation.MatchString(sessions.installation) || len(sessions.secret) < 32 || request == nil || request.Context().Err() != nil || request.TLS == nil || request.TLS.Version < tls.VersionTLS12 {
		return nil, ErrRegistrationPermission
	}
	actor, err := (JWTRegistrationAuthenticator{Secret: sessions.secret}).Authenticate(request)
	if err != nil {
		return nil, ErrRegistrationPermission
	}
	digest, err := ConfigMaintenanceActorSHA256(issuer, actor.Subject)
	if err != nil {
		return nil, ErrRegistrationPermission
	}
	h := &configMaintenanceSessionHolder{sessions: sessions, issuer: issuer, principal: actor.Subject, digest: digest, actor: actor, request: request.Context()}
	// The supplied request and its descendants own this proof. Another request
	// or a detached context cannot reuse it, even with an identical bearer.
	h.bound = context.WithValue(request.Context(), configMaintenanceHolderContextKey{}, h)
	return h, nil
}

func (*configMaintenanceSessionHolder) MarshalJSON() ([]byte, error) {
	return nil, ErrConfigMutation
}

func (h *configMaintenanceSessionHolder) check(ctx context.Context, tx *sql.Tx, scope configMaintenanceScope, now time.Time) error {
	if h == nil || h.sessions == nil || ctx == nil || ctx.Err() != nil || tx == nil || h.request == nil || h.request.Err() != nil || ctx.Value(configMaintenanceHolderContextKey{}) != h || !scope.valid() || scope.database != h.sessions.identity || scope.identity.Installation != h.sessions.installation || scope.identity.Actor != h.digest {
		return ErrRegistrationPermission
	}
	// This locks the current user/credential, session and revocation rows in
	// the caller's original transaction and samples fresh SQL UTC after locks.
	// It never records/refreshes a session, writes audit or commits a result.
	if err := h.sessions.CheckConfigMutationSession(ctx, tx, h.sessions.installation, h.actor, now); err != nil {
		return registrationBoundaryError(err)
	}
	if h.request.Err() != nil || ctx.Err() != nil {
		return ErrRegistrationPermission
	}
	return nil
}

type configMaintenanceGrantVerifier func(context.Context, *sql.Tx, configMaintenanceScope, time.Time) (configMaintenanceGrantFacts, error)

// withGrantVerifier checks the independent holder on BOTH sides of a real
// grant verifier. It compares, rather than fills, the verifier's principal.
// The outer pinned authority still verifies purpose, immutable grant bytes,
// full tuple, revocation and the original expiry. No default grant exists.
func (h *configMaintenanceSessionHolder) withGrantVerifier(verify configMaintenanceGrantVerifier) (configMaintenanceGrantVerifier, error) {
	if h == nil || h.sessions == nil || h.bound == nil || verify == nil {
		return nil, ErrRegistrationUnavailable
	}
	return func(ctx context.Context, tx *sql.Tx, scope configMaintenanceScope, now time.Time) (configMaintenanceGrantFacts, error) {
		zero := configMaintenanceGrantFacts{}
		if err := h.check(ctx, tx, scope, now); err != nil {
			return zero, err
		}
		facts, err := verify(ctx, tx, cloneConfigMaintenanceScope(scope), now)
		if err != nil {
			return zero, registrationBoundaryError(err)
		}
		if facts.actorIssuer != h.issuer || facts.principal != h.principal {
			return zero, ErrRegistrationPermission
		}
		if err := h.check(ctx, tx, scope, now); err != nil {
			return zero, err
		}
		return facts, nil
	}, nil
}
