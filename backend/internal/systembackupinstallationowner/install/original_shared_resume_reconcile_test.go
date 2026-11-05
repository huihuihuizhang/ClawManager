package install

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/services"
)

// Wire-state fixtures exercise the actual authenticated client/decoder and the
// bounded reconciliation decision. They do not claim native thaw/PID proof.
func sharedResumeFixtureState() services.RuntimeSharedNativeState {
	now := time.Now().UTC()
	id := services.RuntimeSharedBackupIdentity{Protocol: services.RuntimeSharedBackupProtocol, Namespace: "n", PodUID: "original-pod", Deployment: "d", AgentEpoch: strings.Repeat("a", 32), OperationID: strings.Repeat("b", 32), InventorySHA256: strings.Repeat("c", 64)}
	state := services.RuntimeSharedNativeState{Version: "shared-runtime-native-state.v1", Identity: id, Phase: "reserved", AgentPID: 123, AgentStartTicks: "456", PIDNamespace: "pid:[1]", MountNamespace: "mnt:[2]", BootID: "original-boot", Entries: []services.RuntimeSharedBackupEntry{}, Sequence: 1, PreparedAt: now, UpdatedAt: now, JournalPath: "/var/lib/agent/shared-backup/current.json", GuardPath: "/var/lib/agent/shared-backup.guard", JournalSHA256: strings.Repeat("d", 64)}
	state.OriginalSHA256 = services.SharedRuntimeOriginalSHA(state)
	return state
}

func sharedResumeFixtureClient(t *testing.T, server *httptest.Server) *services.RuntimeSharedBackupCallbacks {
	t.Helper()
	c, err := services.NewRuntimeSharedBackupCallbacks(services.NewRuntimeAgentClientWithHTTPClient("original-token", server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func checkSharedResumeFixtureRequest(t *testing.T, r *http.Request, id services.RuntimeSharedBackupIdentity) {
	t.Helper()
	var got services.RuntimeSharedBackupIdentity
	if r.Method != http.MethodPost || r.Header.Get("X-ClawManager-Control-Token") != "original-token" || json.NewDecoder(r.Body).Decode(&got) != nil || got != id {
		t.Error("original authenticated identity changed")
	}
}

func TestSharedResumeReconcilePreCancelledDoesNotDispatch(t *testing.T) {
	for _, action := range []string{"resume", "state"} {
		t.Run(action, func(t *testing.T) {
			var calls, boundaries atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			state := sharedResumeFixtureState()
			_, _, err := reconcileOriginalSharedResume(ctx, sharedResumeFixtureClient(t, server), server.URL, action, state.Identity, state.OriginalSHA256, func() error { boundaries.Add(1); return nil })
			if err == nil || calls.Load() != 0 || boundaries.Load() != 0 {
				t.Fatal("canceled invocation dispatched", calls.Load(), boundaries.Load(), err)
			}
		})
	}
}

func TestSharedResumeReconcileUnknownArrivalUsesOriginalState(t *testing.T) {
	for _, delivered := range []bool{false, true} {
		t.Run(map[bool]string{false: "dispatch-not-applied", true: "delivered-response-unknown"}[delivered], func(t *testing.T) {
			state := sharedResumeFixtureState()
			original := state
			var stateMu sync.Mutex
			var calls, sends, boundaries atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				stateMu.Lock()
				defer stateMu.Unlock()
				calls.Add(1)
				checkSharedResumeFixtureRequest(t, r, original.Identity)
				if r.URL.Path == "/v1/shared-backup/resume" {
					sends.Add(1)
					if sends.Load() == 1 {
						if delivered {
							state.Phase = "resumed"
						}
						connection, _, hijackErr := w.(http.Hijacker).Hijack()
						if hijackErr != nil {
							t.Error(hijackErr)
							return
						}
						_ = connection.Close() // real lost response, without a transport retry
						return
					}
					if boundaries.Load() != 1 {
						t.Error("resume preceded durable resend boundary")
					}
					state.Phase = "resumed"
				} else if r.URL.Path != "/v1/shared-backup/state" {
					t.Error("unexpected operation", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(state)
			}))
			defer server.Close()
			client := sharedResumeFixtureClient(t, server)
			if _, _, err := reconcileOriginalSharedResume(context.Background(), client, server.URL, "resume", original.Identity, original.OriginalSHA256, nil); err == nil {
				t.Fatal("unknown first response accepted")
			}
			got, raw, err := reconcileOriginalSharedResume(context.Background(), client, server.URL, "state", original.Identity, original.OriginalSHA256, func() error { boundaries.Add(1); return nil })
			wantSends, wantBoundaries, wantCalls := 2, 1, 3
			if delivered {
				wantSends, wantBoundaries, wantCalls = 1, 0, 2
			}
			if err != nil || got.Phase != "resumed" || got.Identity != original.Identity || got.OriginalSHA256 != original.OriginalSHA256 || len(raw) == 0 || sends.Load() != int32(wantSends) || boundaries.Load() != int32(wantBoundaries) || calls.Load() != int32(wantCalls) {
				t.Fatal("original unknown dispatch was not reconciled", sends.Load(), boundaries.Load(), calls.Load(), err)
			}
		})
	}
}

func TestSharedResumeReconcileTerminalPhasesDoNotResend(t *testing.T) {
	for _, phase := range []string{"resumed", "completed"} {
		t.Run(phase, func(t *testing.T) {
			state := sharedResumeFixtureState()
			state.Phase = phase
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				checkSharedResumeFixtureRequest(t, r, state.Identity)
				if r.URL.Path != "/v1/shared-backup/state" {
					t.Error("terminal state resent")
				}
				_ = json.NewEncoder(w).Encode(state)
			}))
			defer server.Close()
			got, _, err := reconcileOriginalSharedResume(context.Background(), sharedResumeFixtureClient(t, server), server.URL, "state", state.Identity, state.OriginalSHA256, func() error { t.Error("unexpected boundary"); return nil })
			if err != nil || got.Phase != phase || calls.Load() != 1 {
				t.Fatal("terminal query failed", err)
			}
		})
	}
}

func TestSharedResumeReconcileRejectsForeignAndFailedBoundary(t *testing.T) {
	for _, scenario := range []string{"foreign-identity", "foreign-original", "boundary-failed"} {
		t.Run(scenario, func(t *testing.T) {
			original := sharedResumeFixtureState()
			reply := original
			if scenario == "foreign-identity" {
				reply.Identity.PodUID = "replacement"
			}
			if scenario == "foreign-original" {
				reply.AgentPID++
			}
			reply.OriginalSHA256 = services.SharedRuntimeOriginalSHA(reply)
			var calls, boundaries atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				checkSharedResumeFixtureRequest(t, r, original.Identity)
				if r.URL.Path != "/v1/shared-backup/state" {
					t.Error("unverified resume dispatched")
				}
				_ = json.NewEncoder(w).Encode(reply)
			}))
			defer server.Close()
			_, _, err := reconcileOriginalSharedResume(context.Background(), sharedResumeFixtureClient(t, server), server.URL, "state", original.Identity, original.OriginalSHA256, func() error { boundaries.Add(1); return errors.New("durability/fence unavailable") })
			wantBoundaries := 0
			if scenario == "boundary-failed" {
				wantBoundaries = 1
			}
			if err == nil || calls.Load() != 1 || boundaries.Load() != int32(wantBoundaries) {
				t.Fatal("unsafe reconciliation admitted", calls.Load(), boundaries.Load(), err)
			}
		})
	}
}

func TestSharedResumeReconcileUnknownResendIsBounded(t *testing.T) {
	state := sharedResumeFixtureState()
	var calls, sends, boundaries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		checkSharedResumeFixtureRequest(t, r, state.Identity)
		if r.URL.Path == "/v1/shared-backup/state" {
			_ = json.NewEncoder(w).Encode(state)
			return
		}
		if r.URL.Path != "/v1/shared-backup/resume" {
			t.Error("unexpected route")
		}
		sends.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	_, _, err := reconcileOriginalSharedResume(context.Background(), sharedResumeFixtureClient(t, server), server.URL, "state", state.Identity, state.OriginalSHA256, func() error { boundaries.Add(1); return nil })
	if err == nil || calls.Load() != 2 || sends.Load() != 1 || boundaries.Load() != 1 {
		t.Fatal("unknown resend retried or accepted", calls.Load(), sends.Load(), boundaries.Load(), err)
	}
}

func TestSharedResumeReconcileCancelAfterBoundaryDoesNotSend(t *testing.T) {
	state := sharedResumeFixtureState()
	var calls, boundaries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		checkSharedResumeFixtureRequest(t, r, state.Identity)
		if r.URL.Path != "/v1/shared-backup/state" {
			t.Error("canceled resume was sent")
		}
		_ = json.NewEncoder(w).Encode(state)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, err := reconcileOriginalSharedResume(ctx, sharedResumeFixtureClient(t, server), server.URL, "state", state.Identity, state.OriginalSHA256, func() error {
		boundaries.Add(1)
		cancel() // durable send-unknown may precede a canceled actual dispatch
		return nil
	})
	if err == nil || calls.Load() != 1 || boundaries.Load() != 1 {
		t.Fatal("canceled send crossed boundary", calls.Load(), boundaries.Load(), err)
	}
}
