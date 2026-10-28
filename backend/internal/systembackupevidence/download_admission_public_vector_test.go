package systembackupevidence

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

// Shared by the actual producer, public SQL reader, schema and TS client. The
// vector is synthetic public metadata, never an admission/authorization source.
func TestDownloadAdmissionProducerMatchesPublicReadVector(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/download-admission-public-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Operation map[string]any `json:"operation"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&vector); err != nil {
		t.Fatal(err)
	}
	v := vector.Operation
	admitted, err := time.Parse(time.RFC3339Nano, v["created_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := time.Parse(time.RFC3339Nano, v["deadline_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := CanonicalDownloadAdmissionOperation(DownloadAdmissionOperationFacts{
		Installation: v["origin_installation_id"].(string), OperationID: v["public_id"].(string), EvidenceID: v["target_public_id"].(string),
		ActorID: 42, IdempotencyKey: v["idempotency_key"].(string), RequestHash: v["request_hash"].(string), RowVersion: 1, AdmittedAt: admitted, DeadlineAt: deadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	var actual map[string]any
	d = json.NewDecoder(bytes.NewReader(encoded))
	d.UseNumber()
	if err := d.Decode(&actual); err != nil || !reflect.DeepEqual(actual, v) {
		t.Fatal("producer differs from independent public vector", err)
	}
}
