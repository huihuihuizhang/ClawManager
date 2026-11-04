package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSharedRuntimeCallbacksUseActualClientAndExactOriginalHash(t *testing.T) {
	id := RuntimeSharedBackupIdentity{Protocol: RuntimeSharedBackupProtocol, Namespace: "n", PodUID: "p", Deployment: "d", AgentEpoch: strings.Repeat("a", 32), OperationID: strings.Repeat("b", 32), InventorySHA256: strings.Repeat("c", 64)}
	now := time.Now().UTC()
	state := RuntimeSharedNativeState{Version: "shared-runtime-native-state.v1", Identity: id, Phase: "reserved", AgentPID: 123, AgentStartTicks: "12345", PIDNamespace: "pid:[1]", MountNamespace: "mnt:[2]", BootID: "original-boot", Entries: []RuntimeSharedBackupEntry{}, Sequence: 1, PreparedAt: now, UpdatedAt: now, JournalPath: "/var/lib/clawmanager-agent/shared-backup/current.json", GuardPath: "/var/lib/clawmanager-agent/shared-backup.guard", JournalSHA256: strings.Repeat("d", 64)}
	state.OriginalSHA256 = SharedRuntimeOriginalSHA(state)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/shared-backup/prepare" || r.Header.Get("X-ClawManager-Control-Token") != "fixture-token" {
			t.Error("wrong authenticated callback")
			w.WriteHeader(400)
			return
		}
		var got RuntimeSharedBackupIdentity
		if json.NewDecoder(r.Body).Decode(&got) != nil || got != id {
			t.Error("original identity changed")
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(state)
	}))
	defer server.Close()
	callbacks, err := NewRuntimeSharedBackupCallbacks(NewRuntimeAgentClientWithHTTPClient("fixture-token", server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	got, raw, err := callbacks.Transition(context.Background(), server.URL, "prepare", id)
	if err != nil || got.OriginalSHA256 != state.OriginalSHA256 || len(raw) == 0 || calls != 1 {
		t.Fatal("actual callback failed", err)
	}
}

func TestSharedRuntimeCallbacksNeverRetryUnknownOrAcceptDuplicateJSON(t *testing.T) {
	id := RuntimeSharedBackupIdentity{Protocol: RuntimeSharedBackupProtocol, Namespace: "n", PodUID: "p", Deployment: "d", AgentEpoch: strings.Repeat("a", 32), OperationID: strings.Repeat("b", 32), InventorySHA256: strings.Repeat("c", 64)}
	for _, body := range []string{`{"Phase":"reserved","Phase":"completed"}`, `{"Phase":"reserved"} {}`} {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = w.Write([]byte(body)) }))
		callbacks, err := NewRuntimeSharedBackupCallbacks(NewRuntimeAgentClientWithHTTPClient("fixture-token", server.Client()))
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		_, _, err = callbacks.Transition(context.Background(), server.URL, "prepare", id)
		server.Close()
		if err == nil || calls != 1 {
			t.Fatal("ambiguous response accepted or retried")
		}
	}
}
