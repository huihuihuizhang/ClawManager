// Package relaywire holds the existing status-relay data types only.
// It owns no authority, wire decoder, transaction, controller or route.
package relaywire

const RelayVersion = "system-backup-status-relay.v1"

type RelayMessage struct {
	SchemaVersion        string         `json:"schema_version"`
	InstallationID       string         `json:"installation_id"`
	TaskPublicID         string         `json:"task_public_id"`
	TaskType             string         `json:"task_type"`
	AttemptNo            string         `json:"attempt_no"`
	Phase                string         `json:"phase"`
	JobUnitKey           string         `json:"job_unit_key"`
	Namespace            string         `json:"namespace"`
	JobName              string         `json:"job_name"`
	JobUID               string         `json:"job_uid"`
	JobGeneration        string         `json:"job_generation"`
	RelayIdentityRef     string         `json:"relay_identity_ref"`
	RelayIdentityVersion string         `json:"relay_identity_version"`
	Sequence             string         `json:"sequence"`
	Status               string         `json:"status"`
	ResultEvidence       *RelayEvidence `json:"result_evidence"`
}
type RelayEvidence struct {
	PublicID string `json:"public_id"`
	SHA256   string `json:"sha256"`
}
