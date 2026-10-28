package systembackupsecurity

import (
	"time"
	"unicode/utf8"
)

// ConfigMutationResponsePreparation contains only independently established
// writer facts. It is not JSON input, an MFA assertion or a write capability.
// Its payload is constructed by A's canonical builder rather than parsed to
// manufacture its own content-authorization policy.
type ConfigMutationResponsePreparation struct {
	database      DatabaseIdentity
	actor         RegistrationActor
	current       ConfigValues
	policy        ConfigMutationResponseContentPolicy
	payload       []byte
	retain, until time.Time
	binding       *ConfigMutationResponseRequestBinding
}

func NewConfigMutationResponsePreparation(database DatabaseIdentity, actor RegistrationActor, current ConfigValues, policy ConfigMutationResponseContentPolicy, retain time.Time) (ConfigMutationResponsePreparation, error) {
	fail := func() (ConfigMutationResponsePreparation, error) {
		return ConfigMutationResponsePreparation{}, ErrRegistrationUnavailable
	}
	if !database.valid() || actor.UserID != policy.CreatedBy || actor.Subject == "" || len(actor.Subject) > 256 || !utf8.ValidString(actor.Subject) || actor.Session == "" || len(actor.Session) > 256 || !utf8.ValidString(actor.Session) || !configMutationSessionAt(actor, policy.CreatedAt) || len(current.CanonicalJSON()) < 2 {
		return fail()
	}
	if policy.RedactedReason != nil {
		copy := *policy.RedactedReason
		policy.RedactedReason = &copy
	}
	raw, err := CanonicalConfigMutationResponse(policy)
	if err != nil {
		return fail()
	}
	retention := current.snapshot.numbers["control_metadata_retention_seconds"]
	if policy.Config.snapshot.numbers["control_metadata_retention_seconds"] > retention {
		retention = policy.Config.snapshot.numbers["control_metadata_retention_seconds"]
	}
	if retain.Before(policy.CreatedAt.Add(time.Duration(retention) * time.Second)) {
		return fail()
	}
	until := policy.CreatedAt.Add(time.Duration(current.snapshot.numbers["operation_deadline_seconds"]) * time.Second)
	if actor.SessionExpiresAt.Before(until) {
		until = actor.SessionExpiresAt
	}
	return ConfigMutationResponsePreparation{database: database, actor: actor, current: current, policy: policy, payload: raw, retain: retain, until: until}, nil
}
func (p ConfigMutationResponsePreparation) Database() DatabaseIdentity  { return p.database }
func (p ConfigMutationResponsePreparation) Actor() RegistrationActor    { return p.actor }
func (p ConfigMutationResponsePreparation) CurrentConfig() ConfigValues { return p.current }
func (p ConfigMutationResponsePreparation) ContentPolicy() ConfigMutationResponseContentPolicy {
	policy := p.policy
	if policy.RedactedReason != nil {
		copy := *policy.RedactedReason
		policy.RedactedReason = &copy
	}
	return policy
}
func (p ConfigMutationResponsePreparation) Bytes() []byte              { return append([]byte(nil), p.payload...) }
func (p ConfigMutationResponsePreparation) RetainUntil() time.Time     { return p.retain }
func (p ConfigMutationResponsePreparation) ValidUntil() time.Time      { return p.until }
func (ConfigMutationResponsePreparation) MarshalJSON() ([]byte, error) { return nil, ErrConfigMutation }
