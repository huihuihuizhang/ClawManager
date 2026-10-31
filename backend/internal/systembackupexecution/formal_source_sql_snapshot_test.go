package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	w "clawreef/internal/systembackupwire"
)

// Actual captured original SQL bytes become a C frame candidate. Only producer
// key/unwrap and Kubernetes/finished-use facts are named local fixtures; the
// source SELECT/RR, original consumer SQL and independent body parser are real.
func forgeActualSQLSnapshotCandidate(t *testing.T, i worker.Invocation, candidate worker.FormalCaptureResult, keys *candidateContentUnwrapper, actual domain.Snapshot, mode string) (*os.Root, worker.FormalCaptureResult) {
	t.Helper()
	raw, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	var snapshot domain.Snapshot
	if json.Unmarshal(raw, &snapshot) != nil {
		t.Fatal("actual original snapshot clone")
	}
	switch mode {
	case "missing-table":
		for n, table := range snapshot.Tables {
			if table.Name == "gateway_keys" {
				snapshot.Tables = append(snapshot.Tables[:n], snapshot.Tables[n+1:]...)
				break
			}
		}
	case "schema-changed":
		for n, table := range snapshot.Tables {
			if table.Name == "gateway_keys" {
				snapshot.Tables[n].Columns[0].Type = "bigint unsigned"
			}
		}
	case "control-table":
		snapshot.Tables = append(snapshot.Tables, domain.Table{Name: "system_backup_v2_configs", Engine: "InnoDB", Columns: []domain.Column{{Name: "id", Type: "bigint"}}, PrimaryKey: []string{"id"}, Rows: []domain.Row{{"id": domain.Text("1")}}})
	}
	var payload []byte
	if mode == "control-table" {
		payload, err = json.Marshal(snapshot)
	} else {
		var buffer bytes.Buffer
		err = domain.Encode(&buffer, snapshot)
		payload = bytes.Clone(buffer.Bytes())
		clear(buffer.Bytes())
	}
	if err != nil {
		t.Fatal("actual source snapshot encoding", err)
	}
	defer clear(payload)
	if mode == "suffix" {
		payload = append(payload, []byte("{}")...)
	}
	var frames bytes.Buffer
	spec := w.StreamSpec{Request: i.ProviderKey.Request, Path: i.Request.ArtifactName, MaxPlaintextBytes: i.Request.MaxCompressedBytes, MaxFrames: i.FormalCapture.MaxFrames}
	seal, err := w.EncryptStream(context.Background(), spec, keys.key, &frames, func(dst io.Writer) error {
		return staging.Compress(dst, func(z io.Writer) error { _, e := z.Write(payload); return e })
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := seal.EnvelopeJSON(w.WrappedKey{Request: spec.Request, Algorithm: "provider-native", Ciphertext: []byte("named original SQL producer key fixture")})
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	receipt := func(name string, body []byte) staging.Receipt {
		if source.WriteFile(name, body, 0600) != nil {
			t.Fatal("owned encrypted SQL candidate write")
		}
		return staging.Receipt{Name: name, Size: int64(len(body)), SHA256: hash(body)}
	}
	candidate.Ciphertext, candidate.Envelope = receipt(i.Request.ArtifactName, frames.Bytes()), receipt(i.FormalCapture.EnvelopeName, envelope)
	candidate.Files, candidate.Bytes, candidate.Rows, candidate.Tables = 0, 0, 0, len(snapshot.Tables)
	for _, table := range snapshot.Tables {
		candidate.Rows += int64(len(table.Rows))
	}
	if mode == "count" {
		candidate.Rows++
	}
	return source, candidate
}
