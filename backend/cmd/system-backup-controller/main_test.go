package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"clawreef/internal/systembackupcontroller"
)

type fixedPinger struct {
	err error
}

func (p fixedPinger) PingContext(context.Context) error {
	return p.err
}

func TestLeaderControlLoopFailureCancelsRuntime(t *testing.T) {
	for _, runErr := range []error{errors.New("invalid control loop"), nil} {
		runtimeCtx, cancel := context.WithCancel(context.Background())
		failures := make(chan error, 1)
		runLeaderControlLoop(context.Background(), func(context.Context) error { return runErr }, failures, cancel)
		if runtimeCtx.Err() != context.Canceled {
			t.Fatalf("run error %v left runtime active", runErr)
		}
		select {
		case err := <-failures:
			if err == nil || (runErr != nil && !errors.Is(err, runErr)) {
				t.Fatalf("run error %v reported %v", runErr, err)
			}
		default:
			t.Fatalf("run error %v was not reported", runErr)
		}
	}
}

func TestLeaderControlLoopCancellationDoesNotReportFailure(t *testing.T) {
	leaderCtx, stopLeader := context.WithCancel(context.Background())
	stopLeader()
	runtimeCtx, cancelRuntime := context.WithCancel(context.Background())
	defer cancelRuntime()
	failures := make(chan error, 1)
	runLeaderControlLoop(leaderCtx, func(ctx context.Context) error { return ctx.Err() }, failures, cancelRuntime)
	if runtimeCtx.Err() != nil || len(failures) != 0 {
		t.Fatalf("normal leader loss canceled runtime=%v failures=%d", runtimeCtx.Err(), len(failures))
	}
}

func requestHealth(t *testing.T, handler http.Handler, path string) (int, string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	body, err := io.ReadAll(response.Result().Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return response.Code, string(body)
}

func TestHealthHandlerDistinguishesDisabledStandbyLeaderAndDatabaseFailure(t *testing.T) {
	status := &controllerStatus{}
	code, body := requestHealth(t, healthHandler(nil, status), "/readyz")
	if code != http.StatusOK || body != "disabled\n" {
		t.Fatalf("disabled readiness = %d %q", code, body)
	}

	code, body = requestHealth(t, healthHandler(fixedPinger{}, status), "/readyz")
	if code != http.StatusServiceUnavailable || body != "bootstrap not ready: bootstrap_pending\n" {
		t.Fatalf("pending readiness = %d %q", code, body)
	}

	status.setReady(systembackupcontroller.BootstrapSnapshot{
		ConfigEnabled:        false,
		EffectiveEnabled:     false,
		ConfigVersion:        7,
		MigrationCatalogHash: systembackupcontroller.ContractMigrationCatalogHash,
	})
	code, body = requestHealth(t, healthHandler(fixedPinger{}, status), "/readyz")
	if code != http.StatusServiceUnavailable || body != "dependencies not ready: dependency_probe_failed\n" {
		t.Fatalf("dependency-pending readiness = %d %q", code, body)
	}
	status.setDependenciesReady()
	code, body = requestHealth(t, healthHandler(fixedPinger{}, status), "/readyz")
	if code != http.StatusOK || body != "standby config=disabled effective=disabled config_version=7 catalog=294bc95d5b07\n" {
		t.Fatalf("standby readiness = %d %q", code, body)
	}

	status.leading.Store(true)
	code, body = requestHealth(t, healthHandler(fixedPinger{}, status), "/readyz")
	if code != http.StatusOK || body != "leader config=disabled effective=disabled config_version=7 catalog=294bc95d5b07\n" {
		t.Fatalf("leader readiness = %d %q", code, body)
	}

	code, _ = requestHealth(t, healthHandler(fixedPinger{err: errors.New("down")}, status), "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("database failure readiness = %d", code)
	}
	status.setDependencyFailure("dependency_probe_failed")
	code, body = requestHealth(t, healthHandler(fixedPinger{}, status), "/readyz")
	if code != http.StatusServiceUnavailable || body != "dependencies not ready: dependency_probe_failed\n" {
		t.Fatalf("dependency failure readiness = %d %q", code, body)
	}

	code, body = requestHealth(t, healthHandler(fixedPinger{err: errors.New("down")}, status), "/healthz")
	if code != http.StatusOK || body != "ok\n" {
		t.Fatalf("liveness = %d %q", code, body)
	}
}

func TestRunDependencyProbePublishesResult(t *testing.T) {
	status := &controllerStatus{}
	ctx, cancel := context.WithCancel(context.Background())
	probe := systembackupcontroller.ReadinessProbeFunc(func(context.Context) error {
		cancel()
		return nil
	})
	runDependencyProbe(ctx, status, probe)
	if readiness := status.readiness(); !readiness.dependenciesReady || readiness.dependencyReason != "" {
		t.Fatalf("readiness=%#v", readiness)
	}
}

func TestControllerEnvironmentParsingIsStrict(t *testing.T) {
	t.Setenv("TEST_DURATION", "10s")
	if value, err := envDuration("TEST_DURATION", time.Second); err != nil || value != 10*time.Second {
		t.Fatalf("duration = %s, %v", value, err)
	}
	t.Setenv("TEST_DURATION", "10")
	if _, err := envDuration("TEST_DURATION", time.Second); err == nil {
		t.Fatal("unitless duration accepted")
	}

	t.Setenv("TEST_INT", "100")
	if value, err := envInt("TEST_INT", 1); err != nil || value != 100 {
		t.Fatalf("int = %d, %v", value, err)
	}
	t.Setenv("TEST_INT", "1.5")
	if _, err := envInt("TEST_INT", 1); err == nil {
		t.Fatal("fractional integer accepted")
	}

	t.Setenv("TEST_BOOL", "true")
	if value, err := envBool("TEST_BOOL", false); err != nil || !value {
		t.Fatalf("bool = %t, %v", value, err)
	}
	t.Setenv("TEST_BOOL", "enabled")
	if _, err := envBool("TEST_BOOL", false); err == nil {
		t.Fatal("non-boolean feature gate accepted")
	}
}
