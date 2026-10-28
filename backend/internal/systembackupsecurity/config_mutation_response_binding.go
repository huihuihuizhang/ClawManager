package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// A's public request hash is unchanged. ScopeSHA256 additionally fixes the
// idempotency slot. AttemptSHA256 fixes this operation/session and both locked
// SQL snapshots plus the exact response; neither digest is a write grant.
type ConfigMutationResponseRequestBinding struct {
	endpoint, method, key, requestID, operation, requestHash, scopeHash, attemptHash string
	expectedVersion, currentRowVersion, stateRowVersion, highest, rollbackFrom       int64
}

func (b ConfigMutationResponseRequestBinding) Endpoint() string          { return b.endpoint }
func (b ConfigMutationResponseRequestBinding) Method() string            { return b.method }
func (b ConfigMutationResponseRequestBinding) IdempotencyKey() string    { return b.key }
func (b ConfigMutationResponseRequestBinding) RequestID() string         { return b.requestID }
func (b ConfigMutationResponseRequestBinding) OperationPublicID() string { return b.operation }
func (b ConfigMutationResponseRequestBinding) RequestHash() string       { return b.requestHash }
func (b ConfigMutationResponseRequestBinding) ScopeSHA256() string       { return b.scopeHash }
func (b ConfigMutationResponseRequestBinding) AttemptSHA256() string     { return b.attemptHash }
func (b ConfigMutationResponseRequestBinding) ExpectedVersion() int64    { return b.expectedVersion }
func (b ConfigMutationResponseRequestBinding) CurrentRowVersion() int64  { return b.currentRowVersion }
func (b ConfigMutationResponseRequestBinding) InstallationRowVersion() int64 {
	return b.stateRowVersion
}
func (b ConfigMutationResponseRequestBinding) HighestVersion() int64      { return b.highest }
func (b ConfigMutationResponseRequestBinding) RollbackFromVersion() int64 { return b.rollbackFrom }
func (ConfigMutationResponseRequestBinding) MarshalJSON() ([]byte, error) {
	return nil, ErrConfigMutation
}

// BindRequest is called once, from independently authenticated writer facts
// after the first SQL snapshot. No proof/raw JWT/unredacted reason is retained
// or serialized into the producer binding. Rollback's actual source is checked
// by the writer and must also be rechecked by the publication owner.
func (p ConfigMutationResponsePreparation) BindRequest(request ConfigMutationRequest, key, requestID, operation string, currentRowVersion, stateRowVersion, highest int64) (ConfigMutationResponsePreparation, error) {
	fail := func() (ConfigMutationResponsePreparation, error) {
		return ConfigMutationResponsePreparation{}, ErrRegistrationUnavailable
	}
	if p.binding != nil || !p.database.valid() || len(p.payload) < 2 || !validIdempotencyKey(key) || !bootstrapVersion.MatchString(requestID) || !configMutationOperationID.MatchString(operation) || currentRowVersion < 1 || currentRowVersion > 9007199254740991 || stateRowVersion < 1 || stateRowVersion >= 9007199254740991 || highest < 1 || highest >= 9007199254740991 {
		return fail()
	}
	r, err := DecodeConfigMutationRequest(request.Endpoint(), request.CanonicalJSON())
	if err != nil || r.ExpectedVersion() != request.ExpectedVersion() || r.RollbackFromVersion() != request.RollbackFromVersion() || r.ExpectedVersion() > highest || r.RollbackFromVersion() > highest || p.policy.Version != highest+1 {
		return fail()
	}
	if r.Endpoint() == ConfigUpdateEndpoint && (!bytes.Equal(r.Config().CanonicalJSON(), p.policy.Config.CanonicalJSON()) || !bytes.Equal(r.Config().CanonicalJSON(), request.Config().CanonicalJSON())) {
		return fail()
	}
	hash, err := r.RequestHash(p.policy.InstallationID, "admin", strconv.FormatInt(p.actor.UserID, 10))
	if err != nil {
		return fail()
	}
	method := "PUT"
	if r.Endpoint() == ConfigRollbackEndpoint {
		method = "POST"
	}
	// A public slot is independent of the body: another body under the same
	// key must collide with this slot and be compared against RequestHash.
	scope := map[string]any{"profile": "d-config-response-idempotency-slot.v1", "installation": p.policy.InstallationID, "actor_type": "admin", "actor_id": strconv.FormatInt(p.actor.UserID, 10), "endpoint": r.Endpoint(), "method": method, "idempotency_key": key}
	raw, err := json.Marshal(scope)
	if err != nil {
		return fail()
	}
	scopeHash := registrationHash(string(raw))
	attempt := map[string]any{"profile": "d-config-response-publication-attempt.v1", "scope_sha256": scopeHash, "request_hash": hash, "operation_public_id": operation, "request_id": requestID, "database": p.database, "subject": p.actor.Subject, "session_sha256": registrationHash(p.actor.Session), "session_issued_at": p.actor.SessionIssuedAt.UTC(), "session_expires_at": p.actor.SessionExpiresAt.UTC(), "expected_version": r.ExpectedVersion(), "current_row_version": currentRowVersion, "installation_row_version": stateRowVersion, "highest_version": highest, "rollback_from_version": r.RollbackFromVersion(), "current_sha256": p.current.SHA256(), "current_size": len(p.current.CanonicalJSON()), "proposed_sha256": p.policy.Config.SHA256(), "proposed_size": len(p.policy.Config.CanonicalJSON()), "result_version": p.policy.Version, "response_sha256": registrationHash(string(p.payload)), "response_size": len(p.payload), "created_at": p.policy.CreatedAt.UTC(), "retain_until": p.retain.UTC(), "valid_until": p.until.UTC()}
	raw, err = json.Marshal(attempt)
	if err != nil {
		return fail()
	}
	p.binding = &ConfigMutationResponseRequestBinding{r.Endpoint(), method, key, requestID, operation, hash, scopeHash, registrationHash(string(raw)), r.ExpectedVersion(), currentRowVersion, stateRowVersion, highest, r.RollbackFromVersion()}
	return p, nil
}
func (p ConfigMutationResponsePreparation) RequestBinding() (ConfigMutationResponseRequestBinding, bool) {
	if p.binding == nil {
		return ConfigMutationResponseRequestBinding{}, false
	}
	return *p.binding, true
}
