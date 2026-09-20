package systembackupcontroller

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestControllerTelemetryRendersContractMetrics(t *testing.T) {
	telemetry := &ControllerTelemetry{}
	initial := string(telemetry.Render())
	if !strings.Contains(initial, "clawmanager_system_backup_controller_reconcile_total{metric_result=\"success\"} 0\n") ||
		!strings.Contains(initial, "clawmanager_system_backup_controller_last_success_timestamp_seconds 0\n") ||
		strings.Contains(initial, "_reconcile_seconds_bucket{") {
		t.Fatalf("initial controller metrics violate no-data contract: %s", initial)
	}
	telemetry.LeaderStarted()
	telemetry.ObserveReconcile(ControlLoopResult{Duration: 50 * time.Millisecond}, time.Unix(2_000_000_000, 0))
	telemetry.ObserveReconcile(ControlLoopResult{Duration: 400 * time.Second, Err: errors.New("database unavailable")}, time.Unix(2_000_000_001, 0))
	output := string(telemetry.Render())
	for _, want := range []string{
		"clawmanager_system_backup_controller_leader_changes_total 1\n",
		"clawmanager_system_backup_controller_reconcile_total{metric_result=\"success\"} 1\n",
		"clawmanager_system_backup_controller_reconcile_total{metric_result=\"failure\"} 1\n",
		"clawmanager_system_backup_controller_reconcile_seconds_bucket{metric_result=\"success\",le=\"0.01\"} 0\n",
		"clawmanager_system_backup_controller_reconcile_seconds_bucket{metric_result=\"success\",le=\"0.05\"} 1\n",
		"clawmanager_system_backup_controller_reconcile_seconds_bucket{metric_result=\"failure\",le=\"300\"} 0\n",
		"clawmanager_system_backup_controller_reconcile_seconds_bucket{metric_result=\"failure\",le=\"+Inf\"} 1\n",
		"clawmanager_system_backup_controller_reconcile_seconds_sum{metric_result=\"success\"} 0.05\n",
		"clawmanager_system_backup_controller_last_success_timestamp_seconds 2e+09\n",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("controller metrics missing %q:\n%s", want, output)
		}
	}
}

func TestControllerTelemetryPublishedOnlyWithCompleteLeaderScrape(t *testing.T) {
	telemetry := &ControllerTelemetry{}
	telemetry.LeaderStarted()
	telemetry.ObserveReconcile(ControlLoopResult{}, time.Unix(2_000_000_000, 0))
	leading := false
	handler := QueueBudgetMetricsHandler{
		Collector: fakeQueueBudgetCollector{collect: func(_ context.Context, _ string) ([]QueueBudgetMetricSample, error) {
			return completeQueueBudgetSamples(), nil
		}},
		InstallationID: "installation_test", Leader: func() bool { return leading }, Ready: func() bool { return true }, Controller: telemetry,
	}
	if code, body := requestQueueMetrics(t, handler); code != http.StatusOK || body != "" {
		t.Fatalf("standby exposed controller metrics: %d %q", code, body)
	}
	leading = true
	if code, body := requestQueueMetrics(t, handler); code != http.StatusOK || !strings.Contains(body, "clawmanager_system_backup_controller_leader_changes_total 1\n") {
		t.Fatalf("leader omitted controller metrics: %d %q", code, body)
	}
	handler.Collector = fakeQueueBudgetCollector{collect: func(_ context.Context, _ string) ([]QueueBudgetMetricSample, error) {
		return nil, errors.New("database unavailable")
	}}
	if code, body := requestQueueMetrics(t, handler); code != http.StatusServiceUnavailable || strings.Contains(body, "_controller_leader_changes_total") {
		t.Fatalf("failed scrape exposed partial controller metrics: %d %q", code, body)
	}
}
