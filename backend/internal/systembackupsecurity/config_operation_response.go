package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

const ConfigOperationResponseProfile = "a-config-operation-response.v1"
const MaxConfigOperationResponseBytes = 8192

// ConfigOperationResponsePolicy describes an already established successful
// config_update Operation, not a ConfigResource or a permission to write one.
// Times must be original database facts. In particular, FinishedAt/UpdatedAt
// cannot be predicted from the earlier unlocked preparation timestamp.
type ConfigOperationResponsePolicy struct {
	InstallationID, OperationPublicID, Endpoint, IdempotencyKey, RequestHash string
	ActorID, Version, RowVersion                                             int64
	CreatedAt, StartedAt, FinishedAt, UpdatedAt, DeadlineAt                  time.Time
}

func configOperationResponseTime(t time.Time) bool {
	_, offset := t.Zone()
	return !t.IsZero() && offset == 0 && t.Year() >= 1 && t.Year() <= 9999
}

// CanonicalConfigOperationResponse emits every field of the closed public
// Operation schema, with no canonical config, credentials, proof or reason.
// The writer must bind these independent facts and the exact returned bytes
// to the same committed operation/evidence/receipt. This is a pure codec.
func CanonicalConfigOperationResponse(p ConfigOperationResponsePolicy) ([]byte, error) {
	if !configMutationInstallation.MatchString(p.InstallationID) || !configMutationOperationID.MatchString(p.OperationPublicID) ||
		(p.Endpoint != ConfigUpdateEndpoint && p.Endpoint != ConfigRollbackEndpoint) || !validIdempotencyKey(p.IdempotencyKey) || !providerHashPattern.MatchString(p.RequestHash) ||
		p.ActorID < 1 || p.Version < 2 || p.Version > 9007199254740991 || p.RowVersion < 1 || p.RowVersion > 9007199254740991 {
		return nil, ErrConfigMutation
	}
	for _, t := range []time.Time{p.CreatedAt, p.StartedAt, p.FinishedAt, p.UpdatedAt, p.DeadlineAt} {
		if !configOperationResponseTime(t) {
			return nil, ErrConfigMutation
		}
	}
	if p.StartedAt.Before(p.CreatedAt) || p.FinishedAt.Before(p.StartedAt) || p.UpdatedAt.Before(p.FinishedAt) || !p.UpdatedAt.Before(p.DeadlineAt) {
		return nil, ErrConfigMutation
	}
	format := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
	fields := map[string]any{
		"schema_version": "system-backup-operation.v1", "public_id": p.OperationPublicID, "origin_installation_id": p.InstallationID,
		"operation_type": "config_update", "target_type": "system", "target_public_id": p.InstallationID, "actor_type": "admin", "actor_id": strconv.FormatInt(p.ActorID, 10),
		"endpoint": p.Endpoint, "idempotency_key": p.IdempotencyKey, "request_hash": p.RequestHash, "status": "succeeded",
		"result_resource_public_id": nil, "result_config_version": json.Number(fieldsVersion(p.Version)), "retryable": false,
		"failure_category": "none", "failure_message": nil, "http_status": json.Number("200"), "row_version": json.Number(fieldsVersion(p.RowVersion)),
		"deadline_at": format(p.DeadlineAt), "started_at": format(p.StartedAt), "finished_at": format(p.FinishedAt), "created_at": format(p.CreatedAt), "updated_at": format(p.UpdatedAt),
	}
	var out strings.Builder
	canonicalMutationJSON(&out, fields)
	raw := []byte(out.String())
	if len(raw) > MaxConfigOperationResponseBytes {
		return nil, ErrConfigMutation
	}
	return raw, nil
}

// DecodeCanonicalConfigOperationResponse validates representation only. It
// does not establish current authority or prove that the described operation
// committed. Replay must first authenticate the saved hash/SQL receipt, then
// compare every returned policy field against independently locked facts.
func DecodeCanonicalConfigOperationResponse(raw []byte) (ConfigOperationResponsePolicy, error) {
	fail := func() (ConfigOperationResponsePolicy, error) {
		return ConfigOperationResponsePolicy{}, ErrConfigMutation
	}
	if len(raw) < 2 || len(raw) > MaxConfigOperationResponseBytes {
		return fail()
	}
	var dto struct {
		Installation string `json:"origin_installation_id"`
		PublicID     string `json:"public_id"`
		ActorID      string `json:"actor_id"`
		Endpoint     string `json:"endpoint"`
		Key          string `json:"idempotency_key"`
		Hash         string `json:"request_hash"`
		Version      int64  `json:"result_config_version"`
		RowVersion   int64  `json:"row_version"`
		Created      string `json:"created_at"`
		Started      string `json:"started_at"`
		Finished     string `json:"finished_at"`
		Updated      string `json:"updated_at"`
		Deadline     string `json:"deadline_at"`
	}
	if json.Unmarshal(raw, &dto) != nil {
		return fail()
	}
	actor, err := strconv.ParseInt(dto.ActorID, 10, 64)
	if err != nil || strconv.FormatInt(actor, 10) != dto.ActorID {
		return fail()
	}
	p := ConfigOperationResponsePolicy{InstallationID: dto.Installation, OperationPublicID: dto.PublicID, Endpoint: dto.Endpoint, IdempotencyKey: dto.Key, RequestHash: dto.Hash, ActorID: actor, Version: dto.Version, RowVersion: dto.RowVersion}
	for _, field := range []struct {
		raw string
		dst *time.Time
	}{{dto.Created, &p.CreatedAt}, {dto.Started, &p.StartedAt}, {dto.Finished, &p.FinishedAt}, {dto.Updated, &p.UpdatedAt}, {dto.Deadline, &p.DeadlineAt}} {
		*field.dst, err = time.Parse(time.RFC3339Nano, field.raw)
		if err != nil {
			return fail()
		}
	}
	expected, err := CanonicalConfigOperationResponse(p)
	// Comparing all original bytes also rejects unknown/missing/duplicate keys,
	// null-for-false, surrogate replacement, noncanonical numbers and padding.
	if err != nil || !bytes.Equal(raw, expected) {
		return fail()
	}
	return p, nil
}
