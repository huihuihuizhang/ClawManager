package systembackupsecurity

import (
	"time"
	"unicode/utf8"
)

// These are authenticated SQL receipt facts, not an HTTP request or a grant.
// Current session/RBAC admission and exact receipt lookup precede construction;
// the response reader needs independent live read authority as well.
type ConfigMutationResponseReplayFacts struct {
	Database                                         DatabaseIdentity
	Installation                                     string
	Actor                                            RegistrationActor
	Operation, Endpoint, IdempotencyKey, RequestHash string
	EvidenceID                                       int64
	ResponseHash                                     string
	Version                                          int64
	AuthorizedAt, ValidUntil                         time.Time
}

type ConfigMutationResponseReplayPreparation struct {
	facts ConfigMutationResponseReplayFacts
}

func NewConfigMutationResponseReplayPreparation(f ConfigMutationResponseReplayFacts) (ConfigMutationResponseReplayPreparation, error) {
	if !f.Database.valid() || !configMutationInstallation.MatchString(f.Installation) || !configMutationOperationID.MatchString(f.Operation) ||
		(f.Endpoint != ConfigUpdateEndpoint && f.Endpoint != ConfigRollbackEndpoint) || !validIdempotencyKey(f.IdempotencyKey) ||
		!providerHashPattern.MatchString(f.RequestHash) || !providerHashPattern.MatchString(f.ResponseHash) || f.EvidenceID < 1 || f.Version < 2 || f.Version > 9007199254740991 ||
		f.Actor.UserID < 1 || f.Actor.Subject == "" || len(f.Actor.Subject) > 256 || !utf8.ValidString(f.Actor.Subject) || f.Actor.Session == "" || len(f.Actor.Session) > 256 || !utf8.ValidString(f.Actor.Session) ||
		!configMutationSessionAt(f.Actor, f.AuthorizedAt) || !f.AuthorizedAt.Before(f.ValidUntil) || f.ValidUntil.After(f.Actor.SessionExpiresAt) {
		return ConfigMutationResponseReplayPreparation{}, ErrRegistrationUnavailable
	}
	return ConfigMutationResponseReplayPreparation{facts: f}, nil
}
func (p ConfigMutationResponseReplayPreparation) Facts() ConfigMutationResponseReplayFacts {
	return p.facts
}
func (ConfigMutationResponseReplayPreparation) MarshalJSON() ([]byte, error) {
	return nil, ErrConfigMutation
}
