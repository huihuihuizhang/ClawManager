package systembackupsecurity

import (
	"bytes"
	"strconv"
	"time"
)

// Locked business facts only. A terminal response does not exist yet: finish
// and update times are sampled AFTER the config/CAS in the final transaction.
// This object is neither a completed Operation nor a provider/write grant.
type ConfigMutationOperationPreparation struct {
	database                                     DatabaseIdentity
	actor                                        RegistrationActor
	installation, operation, endpoint, key, hash string
	version                                      int64
	created, deadline, until                     time.Time
	retentionSeconds                             int64
}

func newConfigMutationOperationPreparation(database DatabaseIdentity, actor RegistrationActor, installation, operation string, request ConfigMutationRequest, key string, current, proposed ConfigValues, highest int64, created time.Time) (ConfigMutationOperationPreparation, error) {
	fail := func() (ConfigMutationOperationPreparation, error) {
		return ConfigMutationOperationPreparation{}, ErrRegistrationUnavailable
	}
	if !database.valid() || !configMutationInstallation.MatchString(installation) || !configMutationOperationID.MatchString(operation) || !validIdempotencyKey(key) || actor.UserID < 1 || actor.Subject == "" || actor.Session == "" || !configMutationSessionAt(actor, created) || !configOperationResponseTime(created) || len(current.CanonicalJSON()) < 2 || len(proposed.CanonicalJSON()) < 2 || highest < request.ExpectedVersion() || highest >= 9007199254740991 {
		return fail()
	}
	r, err := DecodeConfigMutationRequest(request.Endpoint(), request.CanonicalJSON())
	if err != nil {
		return fail()
	}
	if r.Endpoint() == ConfigUpdateEndpoint && !bytes.Equal(r.Config().CanonicalJSON(), proposed.CanonicalJSON()) {
		return fail()
	}
	hash, err := r.RequestHash(installation, "admin", strconv.FormatInt(actor.UserID, 10))
	if err != nil {
		return fail()
	}
	retention := current.snapshot.numbers["control_metadata_retention_seconds"]
	if proposed.snapshot.numbers["control_metadata_retention_seconds"] > retention {
		retention = proposed.snapshot.numbers["control_metadata_retention_seconds"]
	}
	deadline := created.Add(time.Duration(current.snapshot.numbers["operation_deadline_seconds"]) * time.Second)
	until := deadline
	if actor.SessionExpiresAt.Before(until) {
		until = actor.SessionExpiresAt
	}
	return ConfigMutationOperationPreparation{database, actor, installation, operation, r.Endpoint(), key, hash, highest + 1, created, deadline, until, retention}, nil
}
func (p ConfigMutationOperationPreparation) Database() DatabaseIdentity { return p.database }
func (p ConfigMutationOperationPreparation) Actor() RegistrationActor   { return p.actor }
func (p ConfigMutationOperationPreparation) ValidUntil() time.Time      { return p.until }
func (ConfigMutationOperationPreparation) MarshalJSON() ([]byte, error) {
	return nil, ErrConfigMutation
}
func (p ConfigMutationOperationPreparation) terminal(now time.Time) (ConfigOperationResponsePolicy, []byte, time.Time, error) {
	policy := ConfigOperationResponsePolicy{InstallationID: p.installation, OperationPublicID: p.operation, Endpoint: p.endpoint, IdempotencyKey: p.key, RequestHash: p.hash, ActorID: p.actor.UserID, Version: p.version, RowVersion: 1, CreatedAt: p.created, StartedAt: p.created, FinishedAt: now, UpdatedAt: now, DeadlineAt: p.deadline}
	if !now.Before(p.until) {
		return ConfigOperationResponsePolicy{}, nil, time.Time{}, ErrRegistrationUnavailable
	}
	raw, err := CanonicalConfigOperationResponse(policy)
	if err != nil {
		return ConfigOperationResponsePolicy{}, nil, time.Time{}, ErrRegistrationUnavailable
	}
	return policy, raw, now.Add(time.Duration(p.retentionSeconds) * time.Second), nil
}
