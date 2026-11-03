package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Actual TLS capability decoding plus metadata checks, not a field hold grant.
func TestRuntimeBackupOriginalRecoveryCapabilityWire(t *testing.T) {
	for _, mode := range []string{"original", "legacy-false", "cross-restart-true", "unknown-scope", "auto-thaw", "no-durability", "unsupported", "wrong-epoch", "no-keep-stopped"} {
		t.Run(mode, func(t *testing.T) {
			v1 := RuntimeBackupCapabilities{Protocol: RuntimeBackupProtocol, Namespace: "tenant", PodUID: "original-pod", AgentEpoch: strings.Repeat("a", 32), Slot: "slot-0", GatewayPort: 20000, Scope: RuntimeBackupStopScope, Supported: true, DurableReservation: true, RecoveryScope: RuntimeBackupOriginalRecoveryScope, AgentRestartPolicy: RuntimeBackupRestartQuarantinePolicy}
			v2 := RuntimeStoppedBackupCapabilities{Protocol: RuntimeStoppedBackupProtocol, Namespace: v1.Namespace, PodUID: v1.PodUID, AgentEpoch: v1.AgentEpoch, Slot: v1.Slot, GatewayPort: v1.GatewayPort, Scope: RuntimeStoppedBackupScope, Supported: true, DurableReservation: true, KeepStoppedComplete: true, RecoveryScope: v1.RecoveryScope, AgentRestartPolicy: v1.AgentRestartPolicy}
			switch mode {
			case "legacy-false":
				v1.RecoveryScope, v2.RecoveryScope, v1.AgentRestartPolicy, v2.AgentRestartPolicy = "", "", "", ""
			case "cross-restart-true":
				v1.AgentRestartReconciliation, v2.AgentRestartReconciliation = true, true
			case "unknown-scope":
				v1.RecoveryScope, v2.RecoveryScope = "any_operation", "any_operation"
			case "auto-thaw":
				v1.AgentRestartPolicy, v2.AgentRestartPolicy = "resume_on_restart", "resume_on_restart"
			case "no-durability":
				v1.DurableReservation, v2.DurableReservation = false, false
			case "unsupported":
				v1.Supported, v2.Supported = false, false
			case "wrong-epoch":
				v1.AgentEpoch, v2.AgentEpoch = "invalid", "invalid"
			case "no-keep-stopped":
				v2.KeepStoppedComplete = false
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-ClawManager-Control-Token") != "original-control" {
					w.WriteHeader(401)
					return
				}
				if r.URL.Path == "/v1/backup/capabilities" {
					_ = json.NewEncoder(w).Encode(v1)
				} else if r.URL.Path == "/v2/backup-stopped/capabilities" {
					_ = json.NewEncoder(w).Encode(v2)
				} else {
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			client := NewRuntimeAgentClientWithHTTPClient("original-control", server.Client())
			got1, err1 := client.(RuntimeAgentBackupClient).BackupCapabilities(context.Background(), server.URL, 20000)
			got2, err2 := client.(RuntimeAgentStoppedBackupClient).StoppedBackupCapabilities(context.Background(), server.URL, 20000)
			ok1 := err1 == nil && RuntimeBackupSupportsOriginalOperationRecovery(got1)
			ok2 := err2 == nil && RuntimeStoppedBackupSupportsOriginalOperationRecovery(got2)
			if ok1 != (mode == "original" || mode == "no-keep-stopped") || ok2 != (mode == "original") {
				t.Fatal("unsupported recovery admitted", ok1, ok2, err1, err2)
			}
			if mode == "original" && (got1.AgentRestartReconciliation || got2.AgentRestartReconciliation || got1.AgentEpoch != v1.AgentEpoch || got2.AgentEpoch != v2.AgentEpoch) {
				t.Fatal("restart support promoted or identity changed")
			}
		})
	}
	if RuntimeBackupSupportsOriginalOperationRecovery(nil) || RuntimeStoppedBackupSupportsOriginalOperationRecovery(nil) {
		t.Fatal("missing capability admitted")
	}
}
