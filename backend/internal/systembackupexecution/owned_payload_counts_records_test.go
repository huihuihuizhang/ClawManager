package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	source "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackup/worker"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// Nonempty local record DATA, not a live source grant or task/capture proof.
func TestOwnedPayloadCountsFromNonemptyResourceHistoryData(t *testing.T) {
	spec := worker.ResourceCaptureSpec{Part: "deployment_resources", Namespace: "source", NamespaceUID: "source-ns", ServiceAccountName: "resource-reader", ServiceAccountUID: "resource-reader-uid", MaxItems: 10, Selections: []source.KubernetesSelection{{Version: "v1", Resource: "configmaps", Name: "original", UID: "original-uid"}}, OriginalWriters: []worker.ResourceWriterOriginal{}}
	object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"namespace": "source", "name": "original", "uid": "original-uid"}, "data": map[string]any{"record": "nonempty captured resource DATA"}}}
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), object)
	var payload bytes.Buffer
	header, _ := json.Marshal(struct {
		Version string                     `json:"schema_version"`
		Scope   worker.ResourceCaptureSpec `json:"scope"`
	}{"resource-capture-history.v1", spec})
	payload.Write(append(header, '\n'))
	if err := source.CaptureKubernetesResourcesGuarded(context.Background(), client, &payload, spec.Namespace, spec.NamespaceUID, spec.Part, spec.Selections, source.ObjectBudget{MaxItems: 10, MaxBytes: 1 << 20}, func(context.Context) error { return nil }); err != nil {
		t.Fatal("local native resource history producer", err)
	}
	_, _, _, invocation, candidate, _ := formalObserverFixture(t, func(_ *os.Root, i *worker.Invocation) {
		i.Request.Operation, i.WorkspacePath = "capture-deployment-resources", ""
		i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
		i.Request.Resources = &spec
		i.Request.Binding.Path, i.ProviderKey.Request.Context.Part = spec.Part, spec.Part
	})
	candidate.Files, candidate.Bytes = 0, 0
	var compressed bytes.Buffer
	if err := staging.Compress(&compressed, func(dst io.Writer) error { _, err := dst.Write(payload.Bytes()); return err }); err != nil {
		t.Fatal(err)
	}
	var counts ownedPayloadCounts
	if err := inspectOwnedBusinessPayloadCounts(context.Background(), invocation, candidate, bytes.NewReader(compressed.Bytes()), &counts); err != nil {
		t.Fatal("nonempty actual resource record parser", err)
	}
	raw, _ := json.Marshal(object.Object)
	if !counts.Complete || counts.Kind != "kubernetes_captured_json_bytes" || counts.Items != 1 || counts.ContentBytes != int64(len(raw)) || candidate.Files != 0 || candidate.Bytes != 0 {
		t.Fatal("resource statistics used zero report placeholders", counts)
	}
}

func TestOwnedPayloadCountsFromNonemptyObjectRecordsData(t *testing.T) {
	for _, mode := range []string{"current", "wrong-digest", "missing-end"} {
		t.Run(mode, func(t *testing.T) {
			body := []byte("nonempty original object payload DATA")
			meta := source.ObjectMetadata{Bucket: "team-local", Key: "prefix/object.bin", Version: "immutable-v1", Size: int64(len(body)), ContentType: "application/octet-stream"}
			var payload bytes.Buffer
			whole := sha256.New()
			emit := func(record source.ObjectRecord, final bool) {
				raw, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				raw = append(raw, '\n')
				if !final {
					whole.Write(raw)
				}
				payload.Write(raw)
			}
			emit(source.ObjectRecord{Kind: "object_bytes_v1", Buckets: []string{meta.Bucket}}, false)
			emit(source.ObjectRecord{Kind: "object", Metadata: &meta}, false)
			emit(source.ObjectRecord{Kind: "chunk", Data: body}, false)
			digest := hash(body)
			if mode == "wrong-digest" {
				digest = hash([]byte("different DATA"))
			}
			emit(source.ObjectRecord{Kind: "end_object", Count: meta.Size, SHA256: digest}, false)
			if mode != "missing-end" {
				emit(source.ObjectRecord{Kind: "end", Count: 1, SHA256: hex.EncodeToString(whole.Sum(nil))}, true)
			}
			invocation := worker.Invocation{Request: worker.Request{Operation: "capture-team-objects", MaxArchiveBytes: 1 << 20, Teams: &worker.TeamCaptureSpec{MaxItems: 10, Objects: []team.ObjectRef{{TeamID: 20, Bucket: meta.Bucket, Key: meta.Key, Version: meta.Version, SHA256: hash(body), Size: meta.Size}}}}}
			var counts ownedPayloadCounts
			err := inspectOwnedTeamObjects(context.Background(), invocation, bytes.NewReader(payload.Bytes()), &counts)
			if mode != "current" {
				if err == nil || counts.Items != 0 || counts.ContentBytes != 0 {
					t.Fatal("incomplete/incorrect object retained successful counts", mode, err, counts)
				}
				return
			}
			if err != nil || counts.Items != 1 || counts.ContentBytes != meta.Size {
				t.Fatal("object counts did not come from complete body records", err, counts)
			}
		})
	}
}

func TestOwnedSQLCountsRetainNonemptyRowsAndRawCellByteUnitsData(t *testing.T) {
	snapshot := domain.Snapshot{Tables: []domain.Table{
		{Name: "z_rows", Rows: []domain.Row{{"text": domain.Text("nonempty SQL DATA"), "nullable": {Null: true}}, {"binary": {Bytes: []byte{0, 1, 2}}, "empty": domain.Text("")}}},
		{Name: "a_empty", Rows: []domain.Row{}},
	}}
	counts := countOwnedSQLSnapshot(snapshot)
	if !counts.Complete || counts.Kind != "sql_raw_cell_bytes" || counts.Items != 2 || len(counts.SQLTables) != 2 || counts.SQLTables[0].Table != "a_empty" || counts.SQLTables[0].Rows != 0 || counts.SQLTables[1].Rows != 2 || counts.SQLTables[1].CellBytes != int64(len("nonempty SQL DATA")+3) || counts.ContentBytes != counts.SQLTables[1].CellBytes {
		t.Fatal("SQL raw cell bytes, NULL/empty values or empty tables were miscounted", counts)
	}
}
