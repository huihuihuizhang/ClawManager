package services

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func stoppedWireRequest() RuntimeStoppedBackupRequest {
	return RuntimeStoppedBackupRequest{RuntimeStoppedBackupIdentity: RuntimeStoppedBackupIdentity{Protocol: RuntimeStoppedBackupProtocol, Namespace: "tenant", PodUID: "pod-original", AgentEpoch: strings.Repeat("a", 32), RuntimeType: "openclaw", InstanceID: 7, UserID: 2, Generation: 5, GatewayID: "gw-7-5", GatewayPort: 20000}, OperationID: strings.Repeat("b", 32), CheckpointSHA256: strings.Repeat("c", 64), HoldUntil: time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)}
}
func stoppedWireReceipt(t *testing.T, req RuntimeStoppedBackupRequest, state string) RuntimeStoppedBackupObservation {
	t.Helper()
	r := RuntimeStoppedBackupReceipt{Request: req, Slot: "slot-0", Scope: RuntimeStoppedBackupScope, State: state, CheckpointSHA256: req.CheckpointSHA256, ConfirmedAt: time.Now().UTC()}
	raw, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	return RuntimeStoppedBackupObservation{Receipt: r, Raw: append(raw, '\n')}
}

// Native HTTP/TLS wire component only, not an installed Agent or physical cut.
func TestOriginallyStoppedClientUsesDistinctNativeV2WithoutPIDOrRestart(t *testing.T) {
	req := stoppedWireRequest()
	paths := []string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-ClawManager-Control-Token") != "control" {
			w.WriteHeader(401)
			return
		}
		paths = append(paths, r.URL.Path)
		if strings.Contains(r.URL.Path, "/v1/") || strings.Contains(r.URL.Path, "resume") {
			t.Error("running-source protocol used for stopped source")
		}
		if r.URL.Path == "/v2/backup-stopped/inspect" {
			var i RuntimeStoppedBackupIdentity
			if json.NewDecoder(r.Body).Decode(&i) != nil || i != req.RuntimeStoppedBackupIdentity {
				t.Error("identity changed")
			}
			json.NewEncoder(w).Encode(RuntimeStoppedBackupInspection{Identity: i, Slot: "slot-0", Scope: RuntimeStoppedBackupScope, State: "stopped_unreserved", CheckpointSHA256: req.CheckpointSHA256})
			return
		}
		var got RuntimeStoppedBackupRequest
		if json.NewDecoder(r.Body).Decode(&got) != nil || !runtimeStoppedRequestEqual(req, got) {
			t.Error("original stopped request changed")
		}
		state := "reserved_stopped"
		if strings.HasSuffix(r.URL.Path, "complete-kept-stopped") {
			state = "completed_stopped"
		}
		w.Write(stoppedWireReceipt(t, req, state).Raw)
	}))
	defer server.Close()
	client := NewRuntimeAgentClientWithHTTPClient("control", server.Client()).(RuntimeAgentStoppedBackupClient)
	if _, _, e := client.InspectStoppedBackup(context.Background(), server.URL, req.RuntimeStoppedBackupIdentity); e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"reserve", "observe", "complete-kept-stopped"} {
		o, e := client.StoppedBackupControl(context.Background(), server.URL, action, req)
		if e != nil || len(o.Raw) == 0 {
			t.Fatal(action, e)
		}
	}
	raw, _ := json.Marshal(req)
	for _, forbidden := range []string{"expected_pid", "resume_generation", "restart_sha256", "task_id", "bootstrap_grant"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("fictitious running/task authority field", forbidden)
		}
	}
	if len(paths) != 4 {
		t.Fatal("missing native control calls", paths)
	}
}
func TestOriginallyStoppedWireRejectsLegacyUnknownAndChangedOriginalScope(t *testing.T) {
	req := stoppedWireRequest()
	valid := stoppedWireReceipt(t, req, "reserved_stopped")
	for _, which := range []string{"pending", "legacy", "operation", "checkpoint", "case_alias", "duplicate", "running"} {
		t.Run(which, func(t *testing.T) {
			raw := bytes.Clone(valid.Raw)
			status := 200
			switch which {
			case "pending":
				status = 202
			case "legacy":
				raw = bytes.ReplaceAll(raw, []byte(RuntimeStoppedBackupProtocol), []byte(RuntimeBackupProtocol))
			case "operation":
				raw = bytes.Replace(raw, []byte(req.OperationID), []byte(strings.Repeat("d", 32)), 1)
			case "checkpoint":
				raw = bytes.ReplaceAll(raw, []byte(req.CheckpointSHA256), []byte(strings.Repeat("d", 64)))
			case "case_alias":
				raw = bytes.Replace(raw, []byte(`"operation_id"`), []byte(`"Operation_ID"`), 1)
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"slot":"slot-0"`), []byte(`"slot":"slot-0","slot":"slot-0"`), 1)
			case "running":
				raw = bytes.ReplaceAll(raw, []byte("reserved_stopped"), []byte("resumed"))
			}
			if _, e := DecodeRuntimeStoppedBackupWireObservation(req, "observe", status, raw); e == nil {
				t.Fatal("foreign/unknown stopped proof accepted", which)
			}
		})
	}
}
