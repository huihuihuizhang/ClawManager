package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type operationResponseVector struct {
	Name      string
	Policy    ConfigOperationResponsePolicy
	Canonical string
	SHA256    string
}

func operationResponseVectors(t *testing.T) []operationResponseVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/config_operation_response_vectors.json")
	var doc struct {
		Profile string
		Vectors []operationResponseVector
	}
	if err != nil || json.Unmarshal(raw, &doc) != nil || doc.Profile != ConfigOperationResponseProfile || len(doc.Vectors) != 2 {
		t.Fatal("independent operation codec vectors missing", err)
	}
	return doc.Vectors
}

func TestConfigOperationResponseIndependentVectors(t *testing.T) {
	for _, v := range operationResponseVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			raw, err := CanonicalConfigOperationResponse(v.Policy)
			if err != nil || string(raw) != v.Canonical || registrationHash(string(raw)) != v.SHA256 {
				t.Fatal("Operation JCS differs from independently generated vector", err)
			}
			p, err := DecodeCanonicalConfigOperationResponse(raw)
			if err != nil || !reflect.DeepEqual(p, v.Policy) {
				t.Fatal("exact Operation facts did not roundtrip", err)
			}
			raw[0] = 'x'
			fresh, err := CanonicalConfigOperationResponse(v.Policy)
			if err != nil || string(fresh) != v.Canonical {
				t.Fatal("returned body aliased future encodings")
			}
		})
	}
}

func TestConfigOperationResponseMatchesCompletePublicSchema(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/task-operation.schema.json")
	var schema struct {
		Defs map[string]struct {
			Required   []string
			Properties map[string]json.RawMessage
		} `json:"$defs"`
	}
	if err != nil || json.Unmarshal(raw, &schema) != nil {
		t.Fatal("Operation machine schema missing", err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(operationResponseVectors(t)[0].Canonical), &fields) != nil {
		t.Fatal("invalid golden Operation")
	}
	definition := schema.Defs["Operation"]
	if len(fields) != len(definition.Properties) {
		t.Fatal("complete success profile no longer matches Operation fields")
	}
	for key := range fields {
		if _, ok := definition.Properties[key]; !ok {
			t.Fatal("unknown public Operation field", key)
		}
	}
	for _, key := range definition.Required {
		if _, ok := fields[key]; !ok {
			t.Fatal("required Operation field omitted", key)
		}
	}
	for _, key := range []string{"config", "active", "effective_enabled", "change_reason", "created_by", "version"} {
		if _, ok := fields[key]; ok {
			t.Fatal("ConfigResource field escaped into Operation")
		}
	}
}

func TestConfigOperationResponseRejectsInvalidPolicy(t *testing.T) {
	for _, name := range []string{"installation", "operation", "endpoint", "key", "hash", "actor", "version", "version-overflow", "row", "row-overflow", "zero-time", "non-utc", "year-overflow", "start-before-create", "finish-before-start", "update-before-finish", "deadline-equality"} {
		t.Run(name, func(t *testing.T) {
			p := operationResponseVectors(t)[0].Policy
			switch name {
			case "installation":
				p.InstallationID = "foreign"
			case "operation":
				p.OperationPublicID = "sop_invalid"
			case "endpoint":
				p.Endpoint = ProviderRegistrationEndpoint
			case "key":
				p.IdempotencyKey = "short"
			case "hash":
				p.RequestHash = strings.Repeat("A", 64)
			case "actor":
				p.ActorID = 0
			case "version":
				p.Version = 1
			case "version-overflow":
				p.Version = 9007199254740992
			case "row":
				p.RowVersion = 0
			case "row-overflow":
				p.RowVersion = 9007199254740992
			case "zero-time":
				p.CreatedAt = time.Time{}
			case "non-utc":
				p.CreatedAt = p.CreatedAt.In(time.FixedZone("synthetic", 3600))
			case "year-overflow":
				p.DeadlineAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			case "start-before-create":
				p.StartedAt = p.CreatedAt.Add(-time.Nanosecond)
			case "finish-before-start":
				p.FinishedAt = p.StartedAt.Add(-time.Nanosecond)
			case "update-before-finish":
				p.UpdatedAt = p.FinishedAt.Add(-time.Nanosecond)
			case "deadline-equality":
				p.UpdatedAt = p.DeadlineAt
			}
			if raw, err := CanonicalConfigOperationResponse(p); err != ErrConfigMutation || len(raw) != 0 {
				t.Fatal("invalid Operation policy returned a body")
			}
		})
	}
}

func TestConfigOperationResponseDecoderRejectsAlteredRepresentation(t *testing.T) {
	for _, name := range []string{"schema", "target", "status", "retryable", "retryable-null", "failure", "failure-message", "resource", "http", "row-null", "actor-leading-zero", "unknown", "missing", "duplicate", "padding", "pretty", "noncanonical-time", "exponent", "config-body", "invalid-utf8", "surrogate", "oversize"} {
		t.Run(name, func(t *testing.T) {
			raw := []byte(operationResponseVectors(t)[0].Canonical)
			var fields map[string]any
			d := json.NewDecoder(bytes.NewReader(raw))
			d.UseNumber()
			if d.Decode(&fields) != nil {
				t.Fatal("invalid vector")
			}
			switch name {
			case "schema":
				fields["schema_version"] = "system-backup-config.v1"
			case "target":
				fields["target_public_id"] = "installation_foreign"
			case "status":
				fields["status"] = "pending"
			case "retryable":
				fields["retryable"] = true
			case "retryable-null":
				fields["retryable"] = nil
			case "failure":
				fields["failure_category"] = "internal"
			case "failure-message":
				fields["failure_message"] = "PRIVATE upstream error"
			case "resource":
				fields["result_resource_public_id"] = "sev_foreign"
			case "http":
				fields["http_status"] = json.Number("202")
			case "row-null":
				fields["row_version"] = nil
			case "actor-leading-zero":
				fields["actor_id"] = "042"
			case "unknown":
				fields["proof"] = "PRIVATE proof"
			case "missing":
				delete(fields, "failure_message")
			}
			raw, _ = json.Marshal(fields)
			switch name {
			case "duplicate":
				raw = append([]byte(`{"actor_id":"42",`), raw[1:]...)
			case "padding":
				raw = append(raw, ' ')
			case "pretty":
				raw, _ = json.MarshalIndent(fields, "", "  ")
			case "noncanonical-time":
				raw = bytes.Replace(raw, []byte(".123456Z"), []byte(".1234560Z"), 1)
			case "exponent":
				raw = bytes.Replace(raw, []byte(`"row_version":1`), []byte(`"row_version":1e0`), 1)
			case "config-body":
				raw = []byte(`{"schema_version":"system-backup-config.v1","config":{}}`)
			case "invalid-utf8":
				raw = bytes.Replace(raw, []byte("config_update"), []byte{0xff}, 1)
			case "surrogate":
				raw = bytes.Replace(raw, []byte("config_update"), []byte(`\ud800`), 1)
			case "oversize":
				raw = bytes.Repeat([]byte{' '}, MaxConfigOperationResponseBytes+1)
			}
			if p, err := DecodeCanonicalConfigOperationResponse(raw); err != ErrConfigMutation || !reflect.DeepEqual(p, ConfigOperationResponsePolicy{}) {
				t.Fatal("altered/noncanonical Operation was accepted")
			}
		})
	}
}

func TestConfigOperationResponseMaximumFactsRemainInline(t *testing.T) {
	p := operationResponseVectors(t)[1].Policy
	p.InstallationID = "installation_" + strings.Repeat("i", 115)
	p.IdempotencyKey = strings.Repeat("k", 128)
	p.ActorID = 9223372036854775807
	p.Version, p.RowVersion = 9007199254740991, 9007199254740991
	p.CreatedAt = time.Date(9999, 12, 31, 23, 59, 58, 999999999, time.UTC)
	p.StartedAt, p.FinishedAt, p.UpdatedAt = p.CreatedAt, p.CreatedAt, p.CreatedAt
	p.DeadlineAt = p.CreatedAt.Add(time.Second)
	raw, err := CanonicalConfigOperationResponse(p)
	if err != nil || len(raw) > MaxConfigOperationResponseBytes {
		t.Fatal("bounded complete Operation did not fit inline", len(raw), err)
	}
	t.Logf("BOUND complete-operation bytes=%d inline_limit=%d", len(raw), MaxConfigOperationResponseBytes)
	decoded, err := DecodeCanonicalConfigOperationResponse(raw)
	if err != nil || !reflect.DeepEqual(decoded, p) {
		t.Fatal("maximum safe integer/time/reference facts did not roundtrip", err)
	}
}
